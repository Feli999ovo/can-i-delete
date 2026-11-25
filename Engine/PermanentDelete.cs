using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// 永久删除后端：只用于「内容已校验」的缓存（npm 包缓存、缩略图缓存、崩溃转储等）。
///
/// 为什么不走回收站：IFileOperation 在回收站放不下时可能静默永久删除，且派发前无法完全保证。
/// 本后端不承诺可恢复，因此该问题不再成立；界面必须如实告知「删除后不可恢复」。
///
/// 防替换：先以 DELETE 权限、不跟随重解析点打开文件，在**同一个句柄**上核对最终真实路径、
/// 卷号 + 文件号、硬链接数、大小、修改时间与内容，再通过该句柄设置删除标记。
/// 核对与删除作用于同一个文件对象，打开之后路径或上级目录被调包也删不到别的文件。
/// FileShare.None 等价：不允许其他进程同时打开，正在使用的文件会直接打开失败。
/// </summary>
public sealed class PermanentDeleteBin : IRecycleBin
{
    public bool IsAvailable(string path, long bytes, bool sizeComplete, out string reason, out DeleteRefusalKind kind)
    {
        reason = ""; kind = DeleteRefusalKind.None;
        if (!sizeComplete) { reason = "目标体积不完整"; kind = DeleteRefusalKind.DirSizeIncomplete; return false; }
        return true;
    }

    public RecycleEvidence SendFile(string path) { throw new NotSupportedException("请使用 DeleteVerified"); }

    /// <summary>在同一句柄上核对强身份后删除。返回 null 表示成功，否则返回未删除的原因。</summary>
    public static string DeleteVerified(string path, FileIdentity expected)
    { return DeleteVerified(path, expected, -1, DateTime.MinValue, null); }

    /// <summary>
    /// 在独占句柄上完成全部最终核对后再设置删除标记：最终真实路径、强身份、硬链接数、大小、修改时间，
    /// 以及（可选）由调用方提供的内容校验。句柄不共享写入，核对之后内容不可能再被改写。
    /// </summary>
    public static string DeleteVerified(string path, FileIdentity expected, long expectedBytes, DateTime expectedWriteUtc,
                                        Func<Stream, string> verifyContent)
    {
        string canon = PathGuard.Canonical(path);
        if (canon.Length == 0 || !PathGuard.IsLocalDrivePath(canon))
            return "目标路径无效，未删除";

        // 独占打开（share=0）：其他进程不能读、写、删、改名；正在使用的文件会直接打开失败。
        IntPtr h = CreateFileW(canon, DELETE | FILE_READ_ATTRIBUTES | GENERIC_READ, 0, IntPtr.Zero, OPEN_EXISTING,
                               FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == INVALID || h == IntPtr.Zero)
            return "无法独占打开（" + new Win32Exception(Marshal.GetLastWin32Error()).Message + "），未删除";
        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) return "无法读取句柄身份，未删除";
            if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
                return "句柄指向目录或重解析点，未删除";

            string actualFinal;
            string expectedLong;
            if (!PathGuard.TryGetFinalDosPath(h, out actualFinal)
                || !PathGuard.TryGetLongCanonicalPath(canon, out expectedLong)
                || !string.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
                return "句柄真实路径与目标路径不一致（存在上级重解析点或重定向），未删除";

            ulong index = ((ulong)info.nFileIndexHigh << 32) | info.nFileIndexLow;
            if (!expected.Ok || info.dwVolumeSerialNumber != expected.VolumeSerial || index != expected.Index)
                return "打开的文件与扫描时不是同一个（已被替换），未删除";
            if (info.nNumberOfLinks != 1) return "文件存在多个硬链接，删除一处无法收回空间，未删除";
            long size = ((long)info.nFileSizeHigh << 32) | info.nFileSizeLow;
            if (expectedBytes >= 0 && size != expectedBytes) return "文件大小已变化，未删除";
            if (expectedWriteUtc != DateTime.MinValue)
            {
                long rawWrite = ((long)info.ftWriteHigh << 32) | info.ftWriteLow;
                DateTime w;
                try { w = DateTime.FromFileTimeUtc(rawWrite); }
                catch { return "文件修改时间无效，未删除"; }
                if (Math.Abs((w - expectedWriteUtc).TotalSeconds) > 2) return "文件修改时间已变化，未删除";
            }
            if (verifyContent != null)
            {
                string bad;
                // 句柄所有权仍归本方法：ownsHandle=false，由 finally 统一关闭。
                using (var fs = new FileStream(new SafeFileHandle(h, false), FileAccess.Read)) bad = verifyContent(fs);
                if (bad != null) return "最终内容复核未通过（" + bad + "），未删除";
            }
            var disposition = new FILE_DISPOSITION_INFO { DeleteFile = true };
            if (!SetFileInformationByHandle(h, FileDispositionInfo, ref disposition, Marshal.SizeOf(disposition)))
                return "设置删除标记失败（" + new Win32Exception(Marshal.GetLastWin32Error()).Message + "），未删除";
            return null;
        }
        finally { CloseHandle(h); }   // 句柄关闭时文件真正移除
    }

    /// <summary>
    /// 基于目录句柄安全删除空目录（消除 path-based Directory.Delete TOCTOU 与上级重解析点绕过）：
    /// 独占打开目录句柄（不跟随重解析点），核验确为普通目录且最终真实路径与期望路径一致后，
    /// 通过同一句柄设置 FileDispositionInfo；若目录非空，OS 原子拒绝。
    /// </summary>
    public static bool TryDeleteEmptyDirVerified(string dir)
    {
        string canon = PathGuard.Canonical(dir);
        if (canon.Length <= 3 || !PathGuard.IsLocalDrivePath(canon)) return false;

        IntPtr h = CreateFileW(canon, DELETE | FILE_READ_ATTRIBUTES, 0, IntPtr.Zero, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == INVALID || h == IntPtr.Zero) return false;
        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) return false;
            if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) return false;
            if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return false;

            string actualFinal;
            string expectedLong;
            if (!PathGuard.TryGetFinalDosPath(h, out actualFinal)
                || !PathGuard.TryGetLongCanonicalPath(canon, out expectedLong)
                || !string.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
                return false;

            FILE_DISPOSITION_INFO disposition = new FILE_DISPOSITION_INFO { DeleteFile = true };
            return SetFileInformationByHandle(h, FileDispositionInfo, ref disposition, Marshal.SizeOf(disposition));
        }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// 在不跟随重解析点的句柄上核验单个普通文件：非目录、非重解析点、单硬链接、
    /// 句柄最终真实路径与期望长路径一致，并输出强身份与规范长路径（供单文件回收前与 PreDeleteItem 复用）。
    /// </summary>
    internal static bool VerifySingleFileHandle(string path, out FileIdentity id, out string expectedLong, out string reason)
    {
        id = new FileIdentity();
        expectedLong = "";
        reason = "";

        string canon = PathGuard.Canonical(path);
        if (canon.Length == 0 || !PathGuard.IsLocalDrivePath(canon))
        {
            reason = "目标路径无效";
            return false;
        }

        IntPtr h = CreateFileW(canon, FILE_READ_ATTRIBUTES, SHARE_ALL, IntPtr.Zero, OPEN_EXISTING,
                               FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == INVALID || h == IntPtr.Zero)
        {
            reason = "无法读取目标文件句柄（" + new Win32Exception(Marshal.GetLastWin32Error()).Message + "）";
            return false;
        }
        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info))
            {
                reason = "无法读取句柄文件信息";
                return false;
            }
            if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                reason = "句柄指向目录，不是普通文件";
                return false;
            }
            if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            {
                reason = "句柄指向重解析点";
                return false;
            }
            if (info.nNumberOfLinks != 1)
            {
                reason = "文件存在多个硬链接，拒绝移入回收站";
                return false;
            }

            string actualFinal;
            if (!PathGuard.TryGetFinalDosPath(h, out actualFinal)
                || !PathGuard.TryGetLongCanonicalPath(canon, out expectedLong)
                || !string.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
            {
                reason = "句柄真实路径与目标路径不一致（存在上级重解析点或重定向）";
                return false;
            }

            id.Ok = true;
            id.VolumeSerial = info.dwVolumeSerialNumber;
            id.IndexHigh = info.nFileIndexHigh;
            id.IndexLow = info.nFileIndexLow;
            return true;
        }
        finally { CloseHandle(h); }
    }

    private static readonly IntPtr INVALID = new IntPtr(-1);
    private const uint DELETE = 0x00010000;
    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint GENERIC_READ = 0x80000000;
    private const uint SHARE_ALL = 0x01 | 0x02 | 0x04;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    private const int FileDispositionInfo = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct FILE_DISPOSITION_INFO { [MarshalAs(UnmanagedType.U1)] public bool DeleteFile; }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint dwFileAttributes, ftCreationLow, ftCreationHigh, ftAccessLow, ftAccessHigh, ftWriteLow, ftWriteHigh;
        public uint dwVolumeSerialNumber, nFileSizeHigh, nFileSizeLow, nNumberOfLinks, nFileIndexHigh, nFileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr h, out BY_HANDLE_FILE_INFORMATION info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(IntPtr h, int cls, ref FILE_DISPOSITION_INFO info, int size);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);
}
