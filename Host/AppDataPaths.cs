using System;
using System.IO;

// Portable data follows the executable, never the working directory or AppData.
public static class AppDataPaths
{
    public static string Root { get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data"); } }
    public static string WebView { get { return Path.Combine(Root, "WebView2Data"); } }
    public static string DeleteLog { get { return Path.Combine(Root, "delete-log.txt"); } }
    public static string Diagnostics { get { return Path.Combine(Root, "bridge-diagnostics.log"); } }

    public static void Prepare()
    {
        foreach (string dir in new[] { Root, WebView })
        {
            Directory.CreateDirectory(dir);
            if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("数据目录不能是指向其他位置的链接：" + dir);
            using (var probe = new FileStream(Path.Combine(dir, ".write-" + Guid.NewGuid().ToString("N")),
                FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose))
                probe.WriteByte(0);
        }
        // WebView2's environment override otherwise takes precedence over CreateAsync's argument.
        Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", WebView);
    }
}
