using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

public static class Program
{
    private const int ERROR_CANCELLED = 1223;
    private const int ASFW_ANY = -1;
    private const uint MSGFLT_ADD = 1;
    private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xFFFF);

    private static string startupAutoAction = "";
    private static bool waitForPreviousInstance;
    private static Mutex instanceMutex;
    private static bool instanceMutexOwned;
    private static uint activateWindowMessageId;

    /// <summary>
    /// 启动命令行请求的自动续扫动作：""（无）、"quick"（--quick-scan）、"chat"（--chat-scan）。
    /// </summary>
    public static string StartupAutoAction
    {
        get { return startupAutoAction ?? ""; }
        set { startupAutoAction = value ?? ""; }
    }

    public static uint ActivateWindowMessageId
    {
        get
        {
            if (activateWindowMessageId == 0)
            {
                try
                {
                    activateWindowMessageId = RegisterWindowMessage(BuildActivateMessageName(AppDataPaths.Root));
                }
                catch
                {
                    activateWindowMessageId = 0;
                }
            }
            return activateWindowMessageId;
        }
    }

    private static string ComputeDataRootHex16(string dataRootPath)
    {
        string canon = PathGuard.Canonical(dataRootPath);
        if (string.IsNullOrEmpty(canon))
        {
            canon = (dataRootPath ?? "").Trim().Replace('/', '\\').TrimEnd('\\');
        }
        string normalized = canon.ToLowerInvariant();
        byte[] inputBytes = Encoding.UTF8.GetBytes(normalized);
        byte[] hash;
        using (SHA256 sha = SHA256.Create())
        {
            hash = sha.ComputeHash(inputBytes);
        }
        StringBuilder sb = new StringBuilder(16);
        for (int i = 0; i < 8 && i < hash.Length; i++)
        {
            sb.Append(hash[i].ToString("x2"));
        }
        return sb.ToString();
    }

    public static string BuildInstanceMutexName(string dataRootPath)
    {
        return "Local\\AnPing_Instance_" + ComputeDataRootHex16(dataRootPath);
    }

    public static string BuildActivateMessageName(string dataRootPath)
    {
        return "AnPing_Activate_" + ComputeDataRootHex16(dataRootPath);
    }

    public static void ReleaseInstanceMutexForRelaunch()
    {
        Mutex m = instanceMutex;
        instanceMutex = null;
        if (m != null)
        {
            if (instanceMutexOwned)
            {
                instanceMutexOwned = false;
                try { m.ReleaseMutex(); } catch { }
            }
            try { m.Dispose(); } catch { }
        }
    }

    public static string ConsumeStartupAutoAction()
    {
        string act = startupAutoAction ?? "";
        startupAutoAction = "";
        return act;
    }

    public static void ParseStartupArgs(string[] args)
    {
        startupAutoAction = "";
        waitForPreviousInstance = false;
        if (args == null) return;
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i] == null ? "" : args[i].Trim();
            if (string.Equals(a, "--quick-scan", StringComparison.OrdinalIgnoreCase))
            {
                startupAutoAction = "quick";
            }
            else if (string.Equals(a, "--chat-scan", StringComparison.OrdinalIgnoreCase))
            {
                startupAutoAction = "chat";
            }
            else if (string.Equals(a, "--wait-prev", StringComparison.OrdinalIgnoreCase))
            {
                waitForPreviousInstance = true;
            }
        }
    }

    public static bool IsCurrentProcessAdmin()
    {
        try
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                if (identity == null) return false;
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        catch
        {
            return false;
        }
    }

    public static bool TryRelaunchAsAdmin(string autoActionArg, out bool cancelledByUser, out string error)
    {
        cancelledByUser = false;
        error = "";

        string safeArg = (autoActionArg ?? "").Trim();
        if (safeArg.IndexOf('"') >= 0 || safeArg.IndexOfAny(new char[] { '\r', '\n', '\t' }) >= 0)
        {
            error = "启动参数包含非法字符，已拒绝重启。";
            return false;
        }

        string rawExe = "";
        try { rawExe = Application.ExecutablePath; } catch { rawExe = ""; }
        string exePath = PathGuard.Canonical(rawExe);
        if (string.IsNullOrEmpty(exePath) || !Path.IsPathRooted(exePath) || !File.Exists(exePath))
        {
            error = "未找到当前可执行文件，无法以管理员身份重新启动。";
            return false;
        }

        string workDir = AppDomain.CurrentDomain.BaseDirectory;
        if (string.IsNullOrEmpty(workDir) || !Directory.Exists(workDir))
        {
            workDir = Path.GetDirectoryName(exePath) ?? "";
        }

        try
        {
            string launchArgs = safeArg;
            if (launchArgs.IndexOf("--wait-prev", StringComparison.OrdinalIgnoreCase) < 0)
            {
                launchArgs = string.IsNullOrEmpty(launchArgs) ? "--wait-prev" : (launchArgs + " --wait-prev");
            }

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = exePath;
            psi.Arguments = launchArgs;
            psi.UseShellExecute = true;
            psi.Verb = "runas";
            if (!string.IsNullOrEmpty(workDir))
            {
                psi.WorkingDirectory = workDir;
            }

            Process started = Process.Start(psi);
            if (started == null)
            {
                error = "未能启动管理员进程，继续以普通模式运行。";
                return false;
            }
            ReleaseInstanceMutexForRelaunch();
            try { started.Dispose(); } catch { }
            return true;
        }
        catch (Win32Exception wex)
        {
            if (wex.NativeErrorCode == ERROR_CANCELLED)
            {
                cancelledByUser = true;
                error = "已取消管理员授权，继续以普通模式运行。";
                return false;
            }
            error = "无法以管理员身份重新启动（" + wex.Message + "）。";
            return false;
        }
        catch (Exception ex)
        {
            error = "无法以管理员身份重新启动（" + ex.GetType().Name + "：" + ex.Message + "）。";
            return false;
        }
    }

    [DllImport("user32.dll")]
    private static extern int SetProcessDpiAwarenessContext(IntPtr value);

    [DllImport("user32.dll")]
    private static extern bool SetProcessDPIAware();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterWindowMessage(string lpString);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool AllowSetForegroundWindow(int dwProcessId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ChangeWindowMessageFilter(uint message, uint dwFlag);

    [STAThread]
    public static void Main(string[] args)
    {
        ParseStartupArgs(args);

        try { SetProcessDpiAwarenessContext(new IntPtr(-4)); }
        catch { try { SetProcessDPIAware(); } catch { } }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;

        uint activateMsgId = ActivateWindowMessageId;
        if (activateMsgId != 0)
        {
            try { ChangeWindowMessageFilter(activateMsgId, MSGFLT_ADD); } catch { }
        }

        string mutexName = BuildInstanceMutexName(AppDataPaths.Root);
        bool waitPrev = !string.IsNullOrEmpty(StartupAutoAction) || waitForPreviousInstance;
        int waitMs = waitPrev ? 4000 : 0;
        bool acquired = false;
        instanceMutex = new Mutex(false, mutexName);
        try
        {
            acquired = instanceMutex.WaitOne(waitMs, false);
        }
        catch (AbandonedMutexException)
        {
            acquired = true;
        }
        catch
        {
            acquired = false;
        }

        if (!acquired)
        {
            try { instanceMutex.Dispose(); } catch { }
            instanceMutex = null;
            instanceMutexOwned = false;
            if (activateMsgId != 0)
            {
                try { AllowSetForegroundWindow(ASFW_ANY); } catch { }
                try { PostMessage(HWND_BROADCAST, activateMsgId, IntPtr.Zero, IntPtr.Zero); } catch { }
            }
            return;
        }

        instanceMutexOwned = true;
        try
        {
            RunHost();
        }
        catch (FileNotFoundException)
        {
            ShowWebView2MissingDialog(null);
        }
        catch (BadImageFormatException ex)
        {
            ShowWebView2MissingDialog(ex.Message);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "「按平」启动遇到异常，已安全退出（未创建任何文件操作会话）。\n\n" +
                ex.GetType().Name + "：" + ex.Message,
                "按平 · 启动异常",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        finally
        {
            ReleaseInstanceMutexForRelaunch();
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void RunHost()
    {
        Application.Run(new AnPingForm());
    }

    private static Assembly OnAssemblyResolve(object sender, ResolveEventArgs resolveArgs)
    {
        try
        {
            string assemblyName = new AssemblyName(resolveArgs.Name).Name;
            string libPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "lib", assemblyName + ".dll");
            if (File.Exists(libPath))
            {
                return Assembly.LoadFrom(libPath);
            }
        }
        catch { }
        return null;
    }

    internal static void ShowWebView2MissingDialog(string detail)
    {
        string msg = "「按平」白瓷界面需要 Microsoft Edge WebView2 Runtime 运行时支持。\n\n" +
                     "当前系统未检测到可用的 WebView2 运行时组件，程序将安全退出（未修改任何文件）。\n\n" +
                     "请前往微软官方下载页面安装「Microsoft Edge WebView2 Runtime（常青版引导程序）」后重新打开本程序。";
        if (!string.IsNullOrEmpty(detail))
        {
            msg += "\n\n技术信息：" + detail;
        }
        MessageBox.Show(msg, "按平 · 缺少 WebView2 运行时", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    public static bool TryBuildRevealCommand(string path, out string fileName, out string arguments, out string why)
    {
        fileName = "";
        arguments = "";
        why = "";
        if (string.IsNullOrEmpty(path)) { why = "路径为空。"; return false; }

        if (path.IndexOf('"') >= 0 || path.IndexOfAny(new char[] { '\r', '\n', '\t' }) >= 0)
        { why = "路径包含引号或控制字符，已拒绝拼接。"; return false; }
        if (!Path.IsPathRooted(path)) { why = "路径不是绝对路径，已拒绝。"; return false; }

        string p;
        try { p = PathGuard.Canonical(path); } catch { why = "路径无法规范化。"; return false; }
        if (p.Length == 0) { why = "路径无法规范化。"; return false; }
        if (p.IndexOf('"') >= 0 || p.IndexOfAny(new char[] { '\r', '\n', '\t' }) >= 0)
        { why = "路径包含引号或控制字符，已拒绝拼接。"; return false; }
        if (p.Length == 2 && p[1] == ':') { why = "驱动器根目录无法用 /select 定位。"; return false; }

        bool exists = false;
        try { exists = File.Exists(p) || Directory.Exists(p); } catch { exists = false; }
        if (!exists) { why = "该项目已不存在，或已不可访问（可能已被删除、移动或重命名）。"; return false; }

        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(win)) win = "C:\\Windows";
        fileName = Path.Combine(win, "explorer.exe");
        arguments = "/select,\"" + p + "\"";
        return true;
    }

    public static ProcessStartInfo BuildRevealStartInfo(string fileName, string arguments)
    {
        ProcessStartInfo psi = new ProcessStartInfo(fileName, arguments);
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        return psi;
    }
}
