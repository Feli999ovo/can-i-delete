using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// 永久删除后端：只用于「内容已校验」的缓存（npm 包缓存、缩略图缓存、崩溃转储）。
///
/// 为什么不走回收站：IFileOperation 在回收站放不下时可能静默永久删除，且派发前无法拦住。
/// 本后端不承诺可恢复，因此该问题不再成立；界面必须如实告知「删除后不可恢复」。
///
/// 防替换：先以 DELETE 权限、不跟随重解析点打开文件，在**同一个句柄**上核对卷号 + 文件号，
/// 再通过该句柄设置删除标记。核对与删除作用于同一个文件对象，打开之后路径被调包也删不到别的文件。
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
    /// 在独占句柄上完成全部最终核对后再设置删除标记：强身份、大小、修改时间，
    /// 以及（可选）由调用方提供的内容校验。句柄不共享写入，核对之后内容不可能再被改写。
    /// </summary>
    public static string DeleteVerified(string path, FileIdentity expected, long expectedBytes, DateTime expectedWriteUtc,
                                        Func<Stream, string> verifyContent)
    {
        // 只共享读：其他进程不能写、不能删、不能改名；正在写入的文件会直接打开失败。
        IntPtr h = CreateFileW(path, DELETE | FILE_READ_ATTRIBUTES | GENERIC_READ, 0, IntPtr.Zero, OPEN_EXISTING,
                               FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == INVALID) return "无法独占打开（" + new Win32Exception(Marshal.GetLastWin32Error()).Message + "），未删除";
        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) return "无法读取句柄身份，未删除";
            if ((info.dwFileAttributes & (0x10 | 0x400)) != 0) return "句柄指向目录或重解析点，未删除";
            ulong index = ((ulong)info.nFileIndexHigh << 32) | info.nFileIndexLow;
            if (!expected.Ok || info.dwVolumeSerialNumber != expected.VolumeSerial || index != expected.Index)
                return "打开的文件与扫描时不是同一个（已被替换），未删除";
            if (info.nNumberOfLinks != 1) return "文件存在多个硬链接，删除一处不能释放空间，未删除";
            long size = ((long)info.nFileSizeHigh << 32) | info.nFileSizeLow;
            if (expectedBytes >= 0 && size != expectedBytes) return "文件大小已变化，未删除";
            if (expectedWriteUtc != DateTime.MinValue)
            {
                DateTime w = DateTime.FromFileTimeUtc(((long)info.ftWriteHigh << 32) | info.ftWriteLow);
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

    private static readonly IntPtr INVALID = new IntPtr(-1);
    private const uint DELETE = 0x00010000, FILE_READ_ATTRIBUTES = 0x80, GENERIC_READ = 0x80000000, OPEN_EXISTING = 3, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
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
