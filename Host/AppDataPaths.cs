using System;
using System.IO;
using System.Runtime.InteropServices;

// Portable data follows the executable, never the working directory or AppData.
public static class AppDataPaths
{
    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint SHARE_ALL = 0x01 | 0x02 | 0x04;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_ATTR_DIRECTORY = 0x00000010;
    private const uint FILE_ATTR_REPARSE_POINT = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME { public uint Low; public uint High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr handle, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static string Root { get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data"); } }
    public static string WebView { get { return Path.Combine(Root, "WebView2Data"); } }
    public static string DeleteLog { get { return Path.Combine(Root, "delete-log.txt"); } }
    public static string Diagnostics { get { return Path.Combine(Root, "bridge-diagnostics.log"); } }

    public static void Prepare()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        if (string.IsNullOrEmpty(baseDir)
            || !PathGuard.IsLocalDrivePath(baseDir)
            || PathGuard.HasAnyReparseComponent(baseDir))
        {
            throw new IOException("程序所在目录不受信任或包含符号链接：" + (baseDir ?? ""));
        }

        foreach (string dir in new[] { Root, WebView })
        {
            string parent = Path.GetDirectoryName(dir.TrimEnd('\\', '/'));
            if (string.IsNullOrEmpty(parent) || PathGuard.HasAnyReparseComponent(parent))
                throw new IOException("数据目录父级包含符号链接或重解析点：" + dir);

            try
            {
                FileAttributes preAttr = File.GetAttributes(dir);
                if ((preAttr & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("数据目录不能是指向其他位置的链接：" + dir);
                if ((preAttr & FileAttributes.Directory) == 0)
                    throw new IOException("数据目录路径已被同名文件占用：" + dir);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }

            Directory.CreateDirectory(dir);
            if (PathGuard.HasAnyReparseComponent(dir))
                throw new IOException("数据目录不能是指向其他位置的链接：" + dir);

            VerifyDirectoryHandle(dir);

            using (var probe = new FileStream(Path.Combine(dir, ".write-" + Guid.NewGuid().ToString("N")),
                FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose))
                probe.WriteByte(0);
        }
        // WebView2's environment override otherwise takes precedence over CreateAsync's argument.
        Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", WebView);
    }

    private static void VerifyDirectoryHandle(string dir)
    {
        string expectedLong;
        if (!PathGuard.TryGetLongCanonicalPath(dir, out expectedLong) || string.IsNullOrEmpty(expectedLong))
            throw new IOException("无法解析数据目录的规范路径：" + dir);

        IntPtr h = IntPtr.Zero;
        try
        {
            h = CreateFileW(dir, FILE_READ_ATTRIBUTES, SHARE_ALL, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1))
            {
                h = IntPtr.Zero;
                throw new IOException("无法打开数据目录句柄进行安全校验：" + dir);
            }

            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info))
                throw new IOException("无法读取数据目录句柄属性：" + dir);
            if ((info.FileAttributes & FILE_ATTR_REPARSE_POINT) != 0)
                throw new IOException("数据目录不能是指向其他位置的链接：" + dir);
            if ((info.FileAttributes & FILE_ATTR_DIRECTORY) == 0)
                throw new IOException("数据目录不是有效文件夹：" + dir);

            string actualFinal;
            if (!PathGuard.TryGetFinalDosPath(h, out actualFinal)
                || !string.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException("数据目录真实路径与预期不一致（可能被链接重定向）：" + dir);
            }
        }
        finally
        {
            if (h != IntPtr.Zero && h != new IntPtr(-1))
            {
                try { CloseHandle(h); } catch { }
            }
        }
    }
}
