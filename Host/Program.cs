using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;

public static class Program
{
    private const int ERROR_CANCELLED = 1223;
    private const int ERROR_ACCESS_DENIED = 5;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_ATTR_DIRECTORY = 0x00000010;
    private const uint FILE_ATTR_REPARSE_POINT = 0x00000400;
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new Guid("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
    private static readonly byte[] WebView2PublicKeyToken =
        new byte[] { 0x2a, 0x8a, 0xb4, 0x80, 0x44, 0xd2, 0x60, 0x1e };

    private static string startupAutoAction = "";
    private static bool waitForPreviousInstance;
    private static Mutex instanceMutex;
    private static bool instanceMutexOwned;
    private static uint activateWindowMessageId;

    internal static void ClearSensitiveWebView2EnvironmentOverrides()
    {
        try
        {
            IDictionary envVars = Environment.GetEnvironmentVariables();
            if (envVars != null)
            {
                List<string> toClear = new List<string>();
                foreach (DictionaryEntry entry in envVars)
                {
                    string key = entry.Key as string;
                    if (string.IsNullOrEmpty(key)) continue;
                    if (string.Equals(key, "WEBVIEW2_USER_DATA_FOLDER", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (key.StartsWith("WEBVIEW2_", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(key, "COREWEBVIEW2_FORCED_HOSTING_MODE", StringComparison.OrdinalIgnoreCase))
                    {
                        toClear.Add(key);
                    }
                }
                for (int i = 0; i < toClear.Count; i++)
                {
                    try { Environment.SetEnvironmentVariable(toClear[i], null); } catch { }
                }
            }
        }
        catch { }

        try { Environment.SetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", null); } catch { }
        try { Environment.SetEnvironmentVariable("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", null); } catch { }
        try { Environment.SetEnvironmentVariable("WEBVIEW2_RELEASE_CHANNEL_PREFERENCE", null); } catch { }
        try { Environment.SetEnvironmentVariable("WEBVIEW2_DEFAULT_BACKGROUND_COLOR", null); } catch { }
        try { Environment.SetEnvironmentVariable("WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER", null); } catch { }
        try { Environment.SetEnvironmentVariable("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER", null); } catch { }
        try { Environment.SetEnvironmentVariable("COREWEBVIEW2_FORCED_HOSTING_MODE", null); } catch { }
    }

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

        string rawArg = (autoActionArg ?? "").Trim();
        string safeArg;
        if (rawArg.Length == 0)
        {
            safeArg = "";
        }
        else if (string.Equals(rawArg, "--quick-scan", StringComparison.OrdinalIgnoreCase))
        {
            safeArg = "--quick-scan";
        }
        else if (string.Equals(rawArg, "--chat-scan", StringComparison.OrdinalIgnoreCase))
        {
            safeArg = "--chat-scan";
        }
        else
        {
            error = "启动参数不在允许范围内，已拒绝重启。";
            return false;
        }

        string rawExe = "";
        try { rawExe = Application.ExecutablePath; } catch { rawExe = ""; }
        string exePath = PathGuard.Canonical(rawExe);
        if (string.IsNullOrEmpty(exePath)
            || !PathGuard.IsLocalDrivePath(exePath)
            || PathGuard.HasAnyReparseComponent(exePath)
            || !File.Exists(exePath))
        {
            error = "当前可执行文件路径无效或不受信任，无法以管理员身份重新启动。";
            return false;
        }

        try
        {
            string launchArgs = string.IsNullOrEmpty(safeArg) ? "--wait-prev" : (safeArg + " --wait-prev");

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = exePath;
            psi.Arguments = launchArgs;
            psi.UseShellExecute = true;
            psi.Verb = "runas";
            psi.WorkingDirectory = Environment.SystemDirectory;

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

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

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

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr handle, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

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
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetClassNameW(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    private static void SignalExistingInstance(uint activateMsgId)
    {
        if (activateMsgId == 0) return;

        int selfPid = 0;
        try { selfPid = Process.GetCurrentProcess().Id; } catch { selfPid = 0; }

        string selfExe = "";
        try { selfExe = PathGuard.Canonical(Application.ExecutablePath); } catch { selfExe = ""; }

        StringBuilder titleBuf = new StringBuilder(64);
        StringBuilder classBuf = new StringBuilder(128);
        StringBuilder pathBuf = new StringBuilder(1024);

        try
        {
            EnumWindows(delegate(IntPtr hWnd, IntPtr lParam)
            {
                if (hWnd == IntPtr.Zero) return true;

                uint winPid;
                GetWindowThreadProcessId(hWnd, out winPid);
                if (winPid == 0 || (int)winPid == selfPid) return true;

                titleBuf.Length = 0;
                int titleLen = GetWindowTextW(hWnd, titleBuf, titleBuf.Capacity);
                if (titleLen <= 0 || !string.Equals(titleBuf.ToString(), "按平", StringComparison.Ordinal))
                {
                    return true;
                }

                bool matched = false;
                IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, winPid);
                if (hProc != IntPtr.Zero)
                {
                    try
                    {
                        uint cap = (uint)pathBuf.Capacity;
                        pathBuf.Length = 0;
                        if (QueryFullProcessImageNameW(hProc, 0, pathBuf, ref cap) && cap > 0)
                        {
                            string targetExe = PathGuard.Canonical(pathBuf.ToString());
                            if (!string.IsNullOrEmpty(selfExe)
                                && string.Equals(targetExe, selfExe, StringComparison.OrdinalIgnoreCase))
                            {
                                matched = true;
                            }
                        }
                    }
                    finally
                    {
                        try { CloseHandle(hProc); } catch { }
                    }
                }
                else if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    // Existing instance may be running elevated; verify WinForms window class before targeted post.
                    classBuf.Length = 0;
                    int clsLen = GetClassNameW(hWnd, classBuf, classBuf.Capacity);
                    if (clsLen > 0 && classBuf.ToString().StartsWith("WindowsForms10.Window.", StringComparison.Ordinal))
                    {
                        matched = true;
                    }
                }

                if (matched)
                {
                    try { AllowSetForegroundWindow((int)winPid); } catch { }
                    try { PostMessage(hWnd, activateMsgId, IntPtr.Zero, IntPtr.Zero); } catch { }
                    return false;
                }
                return true;
            }, IntPtr.Zero);
        }
        catch { }
    }

    private static bool VerifyWebView2LoaderBeforeHost(out string failureMessage)
    {
        failureMessage = "";
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        if (string.IsNullOrEmpty(baseDir)) return true;

        string loaderPath = Path.Combine(baseDir, "WebView2Loader.dll");
        FileAttributes attrs;
        try
        {
            attrs = File.GetAttributes(loaderPath);
        }
        catch (FileNotFoundException)
        {
            return true;
        }
        catch (DirectoryNotFoundException)
        {
            return true;
        }
        catch
        {
            failureMessage = "无法读取 WebView2Loader.dll 的文件属性，已拒绝启动。";
            return false;
        }

        if (!PathGuard.IsLocalDrivePath(loaderPath)
            || (attrs & FileAttributes.Directory) != 0
            || (attrs & FileAttributes.ReparsePoint) != 0
            || PathGuard.HasAnyReparseComponent(loaderPath))
        {
            failureMessage = "检测到 WebView2Loader.dll 路径不受信任或为符号链接，已拒绝加载。";
            return false;
        }

        if (!IsCurrentProcessAdmin())
        {
            return true;
        }

        return VerifyMicrosoftAuthenticode(loaderPath, "WebView2Loader.dll", out failureMessage);
    }

    private static bool VerifyMicrosoftAuthenticode(string filePath, string displayName, out string failureMessage)
    {
        failureMessage = "";
        string expectedLong;
        if (!PathGuard.TryGetLongCanonicalPath(filePath, out expectedLong) || string.IsNullOrEmpty(expectedLong))
        {
            failureMessage = "无法解析 " + displayName + " 的规范路径，已拒绝在管理员模式下加载。";
            return false;
        }

        IntPtr hFile = IntPtr.Zero;
        IntPtr pathPtr = IntPtr.Zero;
        IntPtr fileInfoPtr = IntPtr.Zero;
        bool wvtOpened = false;
        WINTRUST_DATA data = new WINTRUST_DATA();
        Guid actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        try
        {
            hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (hFile == IntPtr.Zero || hFile == new IntPtr(-1))
            {
                hFile = IntPtr.Zero;
                failureMessage = "无法打开 " + displayName + " 进行数字签名校验，已拒绝启动。";
                return false;
            }

            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(hFile, out info)
                || (info.FileAttributes & FILE_ATTR_REPARSE_POINT) != 0
                || (info.FileAttributes & FILE_ATTR_DIRECTORY) != 0)
            {
                failureMessage = displayName + " 属性校验失败（可能为重解析点），已拒绝启动。";
                return false;
            }

            string actualFinal;
            if (!PathGuard.TryGetFinalDosPath(hFile, out actualFinal)
                || !string.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
            {
                failureMessage = displayName + " 真实路径与预期不符，已拒绝启动。";
                return false;
            }

            pathPtr = Marshal.StringToCoTaskMemUni(actualFinal);
            WINTRUST_FILE_INFO fileInfo = new WINTRUST_FILE_INFO();
            fileInfo.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fileInfo.pcwszFilePath = pathPtr;
            fileInfo.hFile = hFile;
            fileInfo.pgKnownSubject = IntPtr.Zero;

            fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_NONE;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.pFile = fileInfoPtr;
            data.dwStateAction = WTD_STATEACTION_VERIFY;
            data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;

            int trustResult = WinVerifyTrust(new IntPtr(-1), ref actionGuid, ref data);
            wvtOpened = true;
            if (trustResult != 0)
            {
                failureMessage = displayName + " 数字签名校验未通过（错误码 0x" + trustResult.ToString("X8") + "），已拒绝在管理员模式下运行。";
                return false;
            }

            using (X509Certificate cert = X509Certificate.CreateFromSignedFile(actualFinal))
            {
                string subject = cert != null ? (cert.Subject ?? "") : "";
                if (subject.IndexOf("CN=Microsoft Corporation", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    failureMessage = displayName + " 签名发布者不是 Microsoft Corporation，已拒绝在管理员模式下运行。";
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            failureMessage = "校验 " + displayName + " 完整性失败（" + ex.GetType().Name + "），已拒绝启动。";
            return false;
        }
        finally
        {
            if (wvtOpened)
            {
                try
                {
                    data.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(new IntPtr(-1), ref actionGuid, ref data);
                }
                catch { }
            }
            if (fileInfoPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(fileInfoPtr);
            if (pathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPtr);
            if (hFile != IntPtr.Zero && hFile != new IntPtr(-1))
            {
                try { CloseHandle(hFile); } catch { }
            }
        }
    }

    [STAThread]
    public static void Main(string[] args)
    {
        try { SetDllDirectory(""); } catch { }
        ClearSensitiveWebView2EnvironmentOverrides();

        ParseStartupArgs(args);

        try { SetProcessDpiAwarenessContext(new IntPtr(-4)); }
        catch { try { SetProcessDPIAware(); } catch { } }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        AppDomain.CurrentDomain.AssemblyResolve += OnAssemblyResolve;

        uint activateMsgId = ActivateWindowMessageId;

        string mutexName = BuildInstanceMutexName(AppDataPaths.Root);
        bool waitPrev = !string.IsNullOrEmpty(StartupAutoAction) || waitForPreviousInstance;
        int waitMs = waitPrev ? 4000 : 0;
        bool acquired = false;
        bool createdNew = false;
        try
        {
            MutexSecurity mutexSec = null;
            try
            {
                using (WindowsIdentity ident = WindowsIdentity.GetCurrent())
                {
                    SecurityIdentifier userSid = ident != null ? ident.User : null;
                    if (userSid != null)
                    {
                        mutexSec = new MutexSecurity();
                        mutexSec.AddAccessRule(new MutexAccessRule(
                            userSid,
                            MutexRights.Synchronize | MutexRights.Modify,
                            AccessControlType.Allow));
                    }
                }
            }
            catch { mutexSec = null; }

            instanceMutex = mutexSec != null
                ? new Mutex(false, mutexName, out createdNew, mutexSec)
                : new Mutex(false, mutexName, out createdNew);
            acquired = instanceMutex.WaitOne(waitMs, false);
        }
        catch (AbandonedMutexException)
        {
            acquired = true;
        }
        catch (UnauthorizedAccessException)
        {
            acquired = false;
        }
        catch
        {
            acquired = false;
        }

        if (!acquired)
        {
            if (instanceMutex != null)
            {
                try { instanceMutex.Dispose(); } catch { }
                instanceMutex = null;
            }
            instanceMutexOwned = false;
            if (!createdNew && activateMsgId != 0)
            {
                SignalExistingInstance(activateMsgId);
            }
            return;
        }

        instanceMutexOwned = true;
        try
        {
            string loaderErr;
            if (!VerifyWebView2LoaderBeforeHost(out loaderErr))
            {
                MessageBox.Show(
                    "「按平」安全校验未通过，已拒绝启动（未修改任何文件）。\n\n" + loaderErr,
                    "按平 · 组件完整性校验失败",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }
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

    internal static Assembly OnAssemblyResolve(object sender, ResolveEventArgs resolveArgs)
    {
        try
        {
            if (resolveArgs == null || string.IsNullOrEmpty(resolveArgs.Name)) return null;
            string assemblyName = new AssemblyName(resolveArgs.Name).Name;
            if (!string.Equals(assemblyName, "Microsoft.Web.WebView2.Core", StringComparison.Ordinal)
                && !string.Equals(assemblyName, "Microsoft.Web.WebView2.WinForms", StringComparison.Ordinal))
            {
                return null;
            }

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            if (string.IsNullOrEmpty(baseDir)
                || !PathGuard.IsLocalDrivePath(baseDir)
                || PathGuard.HasAnyReparseComponent(baseDir))
            {
                return null;
            }

            string libDir = Path.Combine(baseDir, "lib");
            string libPath = Path.Combine(libDir, assemblyName + ".dll");
            if (!Directory.Exists(libDir) || PathGuard.HasAnyReparseComponent(libDir)) return null;
            if (!File.Exists(libPath) || PathGuard.HasAnyReparseComponent(libPath)) return null;

            byte[] token = AssemblyName.GetAssemblyName(libPath).GetPublicKeyToken();
            if (token == null || token.Length != WebView2PublicKeyToken.Length) return null;
            for (int i = 0; i < token.Length; i++)
            {
                if (token[i] != WebView2PublicKeyToken[i]) return null;
            }
            if (IsCurrentProcessAdmin())
            {
                string sigErr;
                if (!VerifyMicrosoftAuthenticode(libPath, assemblyName + ".dll", out sigErr))
                    return null;
            }
            return Assembly.LoadFrom(libPath);
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

    internal static bool HasShellClsidSegment(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string[] segments = path.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < segments.Length; i++)
        {
            string seg = segments[i];
            int idx = seg.IndexOf(".{", StringComparison.Ordinal);
            while (idx >= 0)
            {
                int closeIdx = seg.IndexOf('}', idx + 2);
                if (closeIdx > idx + 2)
                {
                    string inside = seg.Substring(idx + 2, closeIdx - (idx + 2));
                    Guid parsed;
                    if (Guid.TryParse(inside, out parsed)) return true;
                }
                idx = seg.IndexOf(".{", idx + 2, StringComparison.Ordinal);
            }
        }
        return false;
    }

    private static bool ContainsControlChar(string s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] < 0x20) return true;
        }
        return false;
    }

    internal static bool TryValidateLocalRevealPath(string path, out string canonicalPath, out string why)
    {
        canonicalPath = "";
        why = "";
        if (string.IsNullOrEmpty(path)) { why = "路径为空。"; return false; }
        if (ContainsControlChar(path)) { why = "路径包含控制字符，已拒绝。"; return false; }
        if (!PathGuard.IsLocalDrivePath(path)) { why = "仅支持本地磁盘绝对路径，已拒绝。"; return false; }

        string p;
        try { p = PathGuard.Canonical(path); } catch { why = "路径无法规范化。"; return false; }
        if (string.IsNullOrEmpty(p) || ContainsControlChar(p) || !PathGuard.IsLocalDrivePath(p))
        {
            why = "路径无法规范化或不是本地磁盘路径。";
            return false;
        }
        if (p.Length <= 3) { why = "驱动器根目录无法用 /select 定位。"; return false; }
        if (HasShellClsidSegment(p)) { why = "路径包含 Shell CLSID 扩展段，已拒绝定位。"; return false; }
        if (PathGuard.HasAnyReparseComponent(p)) { why = "路径包含符号链接或重解析点，已拒绝定位。"; return false; }

        bool exists = false;
        try { exists = File.Exists(p) || Directory.Exists(p); } catch { exists = false; }
        if (!exists) { why = "该项目已不存在，或已不可访问（可能已被删除、移动或重命名）。"; return false; }

        canonicalPath = p;
        return true;
    }

    public static bool TryBuildRevealCommand(string path, out string fileName, out string arguments, out string why)
    {
        fileName = "";
        arguments = "";
        why = "";
        if (string.IsNullOrEmpty(path)) { why = "路径为空。"; return false; }

        if (ContainsControlChar(path) || path.IndexOf('"') >= 0 || path.IndexOf(',') >= 0)
        {
            why = "路径包含引号、逗号或控制字符，已拒绝拼接。";
            return false;
        }

        string p;
        if (!TryValidateLocalRevealPath(path, out p, out why))
        {
            return false;
        }

        if (p.IndexOf('"') >= 0 || p.IndexOf(',') >= 0)
        {
            why = "路径包含引号或逗号，已拒绝拼接。";
            return false;
        }

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
