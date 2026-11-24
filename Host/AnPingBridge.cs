using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Web.WebView2.Core;

public sealed class AnPingBridge : IDisposable
{
    private readonly Form hostForm;
    private readonly WebView2 webView;
    private readonly JavaScriptSerializer inboundSerializer = new JavaScriptSerializer();
    private readonly JavaScriptSerializer outboundSerializer = new JavaScriptSerializer();
    private readonly object outboundSerLock = new object();
    private readonly object diagnosticLock = new object();
    private readonly ManualResetEventSlim activeFileOpDone = new ManualResetEventSlim(true);
    private int inFlightFileTech;
    private readonly ScanSessionHost session = new ScanSessionHost();
    private readonly ScanBudget scanBudget;
    private readonly List<ListRow> allRows = new List<ListRow>();
    private readonly Dictionary<int, ListRow> idMap = new Dictionary<int, ListRow>();
    private DirectorySummary directorySummary;
    private readonly List<string> selectedTargets = new List<string>();
    private readonly List<string> currentScanRoots = new List<string>();
    private System.Windows.Forms.Timer progressTimer;
    private int nextFileId = 1;
    private string currentScanRoot = "";
    private bool scanOpen;
    private bool stopRequested;
    private bool budgetReached;
    private int deliveredFiles;
    private int lastDirectorySummaryUpdateCount;
    private List<string> pendingStart;
    private bool pendingQuickScan;
    private bool pendingChatScan;
    private List<ListRow> detailSnapshot;
    private int snapshotVersion;
    private long scanSessionId;
    private int diagnosticCount;
    private readonly string diagnosticFile = AppDataPaths.Diagnostics;
    private readonly Dictionary<ListRow, int> rowIds = new Dictionary<ListRow, int>();
    private Dictionary<string, CategoryAccumulator> liveCatMap;
    private List<CategoryAccumulator> liveCatOrder;
    private int lastAggregatedRowCount;
    private long lockedCacheBytes;
    private string currentDriveLabel = "";
    private long currentDriveFreeBytes;
    private long currentDriveTotalBytes;
    private bool cachedIsAdmin;
    private bool cachedHasAdminTargets;
    private static readonly object[] emptyFilesArray = new object[0];

    public delegate bool RelaunchAdminDelegate(string autoActionArg, out bool cancelledByUser, out string error);

    private IRecycleBin customTestRecycleBin;
    private string customDeleteLogPathForTest;
    private Action<string> messageCaptureForTest;
    private RelaunchAdminDelegate relaunchHandlerForTest;

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_ALWAYS = 4;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
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

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr ILCreateFromPathW(string pszPath);

    [DllImport("shell32.dll", ExactSpelling = true)]
    private static extern void ILFree(IntPtr pidl);

    [DllImport("shell32.dll", ExactSpelling = true)]
    private static extern int SHOpenFolderAndSelectItems(IntPtr pidlFolder, uint cidl, IntPtr apidl, uint dwFlags);

    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);

    private const int WM_NCLBUTTONDOWN = 0xA1;
    private const int HTCAPTION = 0x2;

    public AnPingBridge(Form form, WebView2 wv)
    {
        hostForm = form;
        webView = wv;
        inboundSerializer.MaxJsonLength = 256 * 1024;
        inboundSerializer.RecursionLimit = 16;
        outboundSerializer.MaxJsonLength = 64 * 1024 * 1024;

        ScanBudget budget = null;
        try
        {
            string envLimits = Program.IsCurrentProcessAdmin()
                ? null
                : Environment.GetEnvironmentVariable("CANIDELETE_SCAN_LIMITS");
            budget = ScanSessionHost.BudgetFromEnvironment(envLimits);
        }
        catch
        {
            budget = ScanSessionHost.BudgetFromEnvironment(null);
        }
        scanBudget = budget ?? ScanSessionHost.BudgetFromEnvironment(null);
        scanBudget.Recursive = true;
        ResetLiveAccumulators();

        progressTimer = new System.Windows.Forms.Timer();
        progressTimer.Interval = 60;
        progressTimer.Tick += OnProgressTick;

        string sysDrive = Path.GetPathRoot(Environment.SystemDirectory);
        if (!string.IsNullOrEmpty(sysDrive))
        {
            selectedTargets.Add(sysDrive);
        }
    }

    public void SetRecycleBinForTest(IRecycleBin bin)
    {
        customTestRecycleBin = bin;
    }

    public void SetDeleteLogPathForTest(string logPath)
    {
        customDeleteLogPathForTest = logPath;
    }

    public void SetMessageCaptureForTest(Action<string> handler)
    {
        messageCaptureForTest = handler;
    }

    public void SetRelaunchHandlerForTest(RelaunchAdminDelegate handler)
    {
        relaunchHandlerForTest = handler;
    }

    private string GetDeleteLogPath()
    {
        return !string.IsNullOrEmpty(customDeleteLogPathForTest)
            ? customDeleteLogPathForTest
            : DeleteEngine.DefaultLogPath();
    }

    internal void PumpForTest()
    {
        OnProgressTick(this, EventArgs.Empty);
    }

    private static bool TryGetInt32(Dictionary<string, object> msg, string key, out int value)
    {
        value = 0;
        object raw;
        if (msg == null || !msg.TryGetValue(key, out raw) || raw == null) return false;
        if (raw is int) { value = (int)raw; return true; }
        if (raw is long)
        {
            long l = (long)raw;
            if (l >= int.MinValue && l <= int.MaxValue) { value = (int)l; return true; }
        }
        return false;
    }

    private static bool TryGetInt64(Dictionary<string, object> msg, string key, out long value)
    {
        value = 0L;
        object raw;
        if (msg == null || !msg.TryGetValue(key, out raw) || raw == null) return false;
        if (raw is int) { value = (int)raw; return true; }
        if (raw is long) { value = (long)raw; return true; }
        return false;
    }

    private static void HandleJsLog(Dictionary<string, object> msg)
    {
        object lvlObj;
        string rawLevel = msg.TryGetValue("level", out lvlObj) && lvlObj != null
            ? (Convert.ToString(lvlObj) ?? "").Trim().ToLowerInvariant()
            : "info";
        string level = (rawLevel == "info" || rawLevel == "warn" || rawLevel == "error" || rawLevel == "fatal")
            ? rawLevel : "info";

        object msgObj;
        string rawMsg = msg.TryGetValue("msg", out msgObj) && msgObj != null
            ? (Convert.ToString(msgObj) ?? "")
            : "";
        StringBuilder clean = new StringBuilder(Math.Min(rawMsg.Length, 512));
        for (int i = 0; i < rawMsg.Length && clean.Length < 512; i++)
        {
            char ch = rawMsg[i];
            if (ch >= 0x20 && ch != 0x7F)
            {
                clean.Append(ch);
            }
            else if (ch == '\t' || ch == '\r' || ch == '\n')
            {
                clean.Append(' ');
            }
        }
        Console.WriteLine("[JS " + level + "] " + clean.ToString());
    }

    public void HandleWebMessage(string json)
    {
        if (closingOrDisposed || isClosingGracefully) return;
        try
        {
            Dictionary<string, object> msg = inboundSerializer.Deserialize<Dictionary<string, object>>(json);
            if (msg == null || !msg.ContainsKey("action")) return;

            string action = Convert.ToString(msg["action"]);
            switch (action)
            {
                case "init":
                    SendInitState();
                    AnPingForm native = hostForm as AnPingForm;
                    if (native != null) native.PublishSystemPreferences();
                    SendPendingCleanRecords();
                    string startupAction = Program.ConsumeStartupAutoAction();
                    if (string.Equals(startupAction, "quick", StringComparison.OrdinalIgnoreCase))
                    {
                        StartQuickScan();
                    }
                    else if (string.Equals(startupAction, "chat", StringComparison.OrdinalIgnoreCase))
                    {
                        StartChatScan();
                    }
                    break;

                case "log":
                    HandleJsLog(msg);
                    break;

                case "getDrives":
                    SendAvailableDrives();
                    break;

                case "browseFolder":
                    BrowseCustomFolder();
                    break;

                case "startScan":
                    List<string> targets = new List<string>();
                    if (msg.ContainsKey("targets") && msg["targets"] is System.Collections.ArrayList)
                    {
                        foreach (object item in (System.Collections.ArrayList)msg["targets"])
                        {
                            string p = Convert.ToString(item);
                            if (!string.IsNullOrEmpty(p)) targets.Add(p);
                        }
                    }
                    StartScan(targets);
                    break;

                case "startQuickScan":
                    StartQuickScan();
                    break;

                case "startChatScan":
                    StartChatScan();
                    break;

                case "relaunchAdmin":
                    HandleRelaunchAdmin(msg);
                    break;

                case "snapshotStart":
                    detailSnapshot = allRows.ToList();
                    snapshotVersion++;
                    PostMessage(new
                    {
                        action = "snapshotReady",
                        scanSessionId = scanSessionId,
                        request = msg.ContainsKey("request") ? msg["request"] : null,
                        snapshot = snapshotVersion,
                        count = detailSnapshot.Count(delegate(ListRow r) { return !r.IsDirectory; }),
                        categories = AggregateCategories(false)
                    });
                    break;

                case "reviewGroups":
                    SendReviewGroups(msg);
                    break;

                case "filesPage":
                    SendFilesPage(msg);
                    break;

                case "directoriesPage":
                    SendDirectoriesPage(msg);
                    break;

                case "largeFiles":
                    SendLargeFiles(msg);
                    break;

                case "fileTech":
                    SendFileTech(msg);
                    break;

                case "continueScan":
                    ContinueScan();
                    break;

                case "stopScan":
                    StopScan();
                    break;

                case "revealFile":
                    int revealId;
                    if (TryGetInt32(msg, "id", out revealId) && revealId >= 0)
                    {
                        RevealFileById(revealId);
                    }
                    else
                    {
                        PostMessage(new { action = "fileActionResult", op = "reveal", id = -1, success = false, error = "无效的文件标识。" });
                    }
                    break;

                case "copyPath":
                    int copyId;
                    if (TryGetInt32(msg, "id", out copyId) && copyId >= 0)
                    {
                        CopyPathById(copyId);
                    }
                    else
                    {
                        PostMessage(new { action = "fileActionResult", op = "copy", id = -1, success = false, error = "无效的文件标识。" });
                    }
                    break;

                case "cleanSummary":
                    SendCleanSummary(msg);
                    break;

                case "cleanEligible":
                    CleanEligible(msg);
                    break;

                case "stopClean":
                    if (cleaning) cleanStopRequested = true;
                    break;

                case "recycleSingleFile":
                    RecycleSingleFile(msg);
                    break;

                case "window":
                    if (msg.ContainsKey("op"))
                    {
                        string op = Convert.ToString(msg["op"]);
                        HandleWindowOp(op);
                    }
                    break;

                case "drag":
                    if (hostForm != null)
                    {
                        ReleaseCapture();
                        SendMessage(hostForm.Handle, WM_NCLBUTTONDOWN, (IntPtr)HTCAPTION, IntPtr.Zero);
                    }
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[Bridge Error] " + ex.GetType().Name);
            WriteDiagnostic("incoming", "dispatch", ex);
        }
    }

    private void HandleWindowOp(string op)
    {
        if (hostForm == null) return;
        if (op == "min") hostForm.WindowState = FormWindowState.Minimized;
        else if (op == "max")
        {
            hostForm.WindowState = (hostForm.WindowState == FormWindowState.Maximized)
                ? FormWindowState.Normal : FormWindowState.Maximized;
        }
        else if (op == "close")
        {
            if (isClosingGracefully || hostForm.IsDisposed || hostForm.Disposing) return;
            if (hostForm.IsHandleCreated)
            {
                try
                {
                    hostForm.BeginInvoke(new Action(delegate()
                    {
                        try { if (!hostForm.IsDisposed && !hostForm.Disposing) hostForm.Close(); } catch { }
                    }));
                }
                catch
                {
                    try { hostForm.Close(); } catch { }
                }
            }
            else
            {
                try { hostForm.Close(); } catch { }
            }
        }
    }

    private void RefreshAdminStateCache()
    {
        cachedIsAdmin = Program.IsCurrentProcessAdmin();
        cachedHasAdminTargets = CacheRuleRegistry.HasSystemAdminCacheTargets();
    }

    private void UpdateCurrentDriveContext(IList<string> roots)
    {
        currentDriveLabel = "";
        currentDriveFreeBytes = 0L;
        currentDriveTotalBytes = 0L;

        string sysDrive = "";
        try { sysDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? ""; } catch { sysDrive = ""; }

        List<string> driveRoots = new List<string>();
        HashSet<string> seenDrives = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (roots != null)
        {
            for (int i = 0; i < roots.Count; i++)
            {
                string r = roots[i];
                if (string.IsNullOrEmpty(r)) continue;
                try
                {
                    string dr = Path.GetPathRoot(r);
                    if (!string.IsNullOrEmpty(dr) && seenDrives.Add(dr))
                    {
                        driveRoots.Add(dr);
                    }
                }
                catch { }
            }
        }

        string chosenRoot = "";
        if (driveRoots.Count == 1)
        {
            chosenRoot = driveRoots[0];
        }
        else if (driveRoots.Count > 1)
        {
            if (!string.IsNullOrEmpty(sysDrive) && seenDrives.Contains(sysDrive))
            {
                chosenRoot = sysDrive;
            }
            else
            {
                for (int i = 0; i < driveRoots.Count; i++)
                {
                    try
                    {
                        DriveInfo candidate = new DriveInfo(driveRoots[i]);
                        if (candidate.DriveType == DriveType.Fixed && candidate.IsReady)
                        {
                            chosenRoot = driveRoots[i];
                            break;
                        }
                    }
                    catch { }
                }
                if (string.IsNullOrEmpty(chosenRoot)) chosenRoot = driveRoots[0];
            }
        }
        else
        {
            chosenRoot = sysDrive;
        }

        if (string.IsNullOrEmpty(chosenRoot)) return;
        try
        {
            DriveInfo di = new DriveInfo(chosenRoot);
            if (di.IsReady && di.TotalSize > 0)
            {
                currentDriveLabel = di.Name.TrimEnd('\\', '/');
                currentDriveFreeBytes = di.AvailableFreeSpace;
                currentDriveTotalBytes = di.TotalSize;
            }
        }
        catch
        {
            currentDriveLabel = "";
            currentDriveFreeBytes = 0L;
            currentDriveTotalBytes = 0L;
        }
    }

    private void RefreshCurrentDriveSpace()
    {
        if (string.IsNullOrEmpty(currentDriveLabel)) return;
        try
        {
            DriveInfo di = new DriveInfo(currentDriveLabel + "\\");
            if (di.IsReady && di.TotalSize > 0)
            {
                currentDriveFreeBytes = di.AvailableFreeSpace;
                currentDriveTotalBytes = di.TotalSize;
            }
        }
        catch { }
    }

    private void HandleRelaunchAdmin(Dictionary<string, object> msg)
    {
        if (cleaning || recyclingSingle)
        {
            PostMessage(new
            {
                action = "relaunchAdminResult",
                ok = false,
                cancelled = false,
                error = "正在执行文件操作，请完成后再切换管理员模式。"
            });
            return;
        }

        string mode = msg != null && msg.ContainsKey("mode") ? Convert.ToString(msg["mode"]) : "quick";
        string arg = string.Equals(mode, "chat", StringComparison.OrdinalIgnoreCase) ? "--chat-scan" : "--quick-scan";

        bool cancelled;
        string err;
        RelaunchAdminDelegate handler = relaunchHandlerForTest;
        bool ok = handler != null
            ? handler(arg, out cancelled, out err)
            : Program.TryRelaunchAsAdmin(arg, out cancelled, out err);

        if (ok)
        {
            Program.ReleaseInstanceMutexForRelaunch();
            PostMessage(new { action = "relaunchAdminResult", ok = true });
            if (hostForm != null && !hostForm.IsDisposed)
            {
                if (hostForm.IsHandleCreated)
                {
                    try
                    {
                        hostForm.BeginInvoke(new Action(delegate()
                        {
                            try { if (!hostForm.IsDisposed) hostForm.Close(); } catch { }
                        }));
                    }
                    catch
                    {
                        try { hostForm.Close(); } catch { }
                    }
                }
                else
                {
                    try { hostForm.Close(); } catch { }
                }
            }
        }
        else
        {
            PostMessage(new
            {
                action = "relaunchAdminResult",
                ok = false,
                cancelled = cancelled,
                error = err ?? ""
            });
        }
    }

    private void SendInitState()
    {
        RefreshAdminStateCache();
        UpdateCurrentDriveContext(selectedTargets);
        ChatStorageLocator.ChatDataFolder[] discoveredChats = ChatStorageLocator.DiscoverChatDataFolders();
        int chatCount = 0;
        if (discoveredChats != null)
        {
            for (int i = 0; i < discoveredChats.Length; i++)
            {
                ChatStorageLocator.ChatDataFolder cf = discoveredChats[i];
                if (cf != null && !string.IsNullOrEmpty(cf.Path)) chatCount++;
            }
        }
        var data = new
        {
            action = "initState",
            appName = "按平",
            isReadOnly = true,
            defaultDrive = Path.GetPathRoot(Environment.SystemDirectory),
            driveLabel = currentDriveLabel,
            driveFreeBytes = currentDriveFreeBytes,
            driveTotalBytes = currentDriveTotalBytes,
            chatFolderCount = chatCount,
            isAdmin = cachedIsAdmin,
            hasAdminTargets = cachedHasAdminTargets
        };
        PostMessage(data);
    }

    private void SendAvailableDrives()
    {
        List<object> driveList = new List<object>();
        foreach (DriveInfo di in DriveInfo.GetDrives())
        {
            if (di.DriveType == DriveType.Fixed && di.IsReady)
            {
                string label = string.IsNullOrEmpty(di.VolumeLabel) ? "" : " (" + di.VolumeLabel + ")";
                bool isSystem = string.Equals(di.Name, Path.GetPathRoot(Environment.SystemDirectory), StringComparison.OrdinalIgnoreCase);
                string title = di.Name.TrimEnd('\\') + (isSystem ? " 系统盘" : " 数据盘" + label);
                string desc = "可用 " + FormatGb(di.AvailableFreeSpace) + " / 共 " + FormatGb(di.TotalSize);
                driveList.Add(new
                {
                    path = di.Name,
                    title = title,
                    desc = desc,
                    selected = isSystem
                });
            }
        }

        ChatStorageLocator.ChatDataFolder[] discoveredChats = ChatStorageLocator.DiscoverChatDataFolders();
        List<object> chatList = new List<object>(discoveredChats != null ? discoveredChats.Length : 0);
        if (discoveredChats != null)
        {
            for (int i = 0; i < discoveredChats.Length; i++)
            {
                ChatStorageLocator.ChatDataFolder cf = discoveredChats[i];
                if (cf == null || string.IsNullOrEmpty(cf.Path)) continue;
                chatList.Add(new
                {
                    appName = cf.AppName ?? "",
                    kind = cf.Kind ?? "",
                    path = cf.Path
                });
            }
        }

        PostMessage(new
        {
            action = "drivesList",
            drives = driveList,
            chatFolders = chatList
        });
    }

    private void BrowseCustomFolder()
    {
        using (FolderBrowserDialog fbd = new FolderBrowserDialog())
        {
            fbd.Description = "选择要用「按平」进行分析的文件夹";
            fbd.ShowNewFolderButton = false;
            if (fbd.ShowDialog(hostForm) == DialogResult.OK && !string.IsNullOrEmpty(fbd.SelectedPath))
            {
                string path = fbd.SelectedPath;
                string title = Path.GetFileName(path);
                if (string.IsNullOrEmpty(title)) title = path;
                PostMessage(new
                {
                    action = "folderAdded",
                    folder = new
                    {
                        path = path,
                        title = title,
                        desc = path,
                        selected = true
                    }
                });
            }
        }
    }

    private void StartScan(List<string> targets)
    {
        if (budgetReached && scanOpen && session.IsPaused)
        {
            pendingQuickScan = false;
            pendingChatScan = false;
            pendingStart = targets;
            StopScan();
            return;
        }
        if (cleaning || recyclingSingle)
        {
            PostMessage(new { action = "scanRejected", error = "正在处理文件，请稍候再扫描。" });
            return;
        }
        if (scanOpen || (session.IsBusy && !session.IsPaused))
        {
            PostMessage(new { action = "scanRejected", error = "上一轮扫描正在收尾，请稍后再试。" });
            return;
        }
        if (targets == null || targets.Count != 1)
        {
            PostMessage(new { action = "scanRejected", error = "每次请选择一个扫描位置。" });
            return;
        }
        string rawTarget = targets[0] == null ? "" : targets[0].Trim();
        if (!PathGuard.IsLocalDrivePath(rawTarget))
        {
            PostMessage(new { action = "scanRejected", error = "仅支持扫描本地磁盘路径，不支持网络共享或设备路径。" });
            return;
        }

        CacheRuleRegistry.RefreshRootsCache();
        string why;
        if (!session.Start(rawTarget, scanBudget, out why))
        {
            PostMessage(new { action = "scanRejected", error = why });
            return;
        }

        selectedTargets.Clear();
        selectedTargets.AddRange(targets);
        currentScanRoot = targets[0];
        currentScanRoots.Clear();
        currentScanRoots.AddRange(session.Roots);
        RefreshAdminStateCache();
        UpdateCurrentDriveContext(currentScanRoots);
        allRows.Clear();
        ResetLiveAccumulators();
        detailSnapshot = null;
        snapshotVersion++;
        deliveredFiles = 0;
        lastDirectorySummaryUpdateCount = 0;
        idMap.Clear();
        rowIds.Clear();
        directorySummary = new DirectorySummary(currentScanRoot);
        directorySummary.StartScan(scanSessionId + 1);
        cleanLockedReason = "";
        stopRequested = false;
        budgetReached = false;
        scanSessionId++;
        scanOpen = true;
        progressTimer.Start();
        PostMessage(new
        {
            action = "scanStarted",
            scanSessionId = scanSessionId,
            target = currentScanRoot,
            quick = false,
            chat = false,
            driveLabel = currentDriveLabel,
            driveFreeBytes = currentDriveFreeBytes,
            driveTotalBytes = currentDriveTotalBytes,
            isAdmin = cachedIsAdmin,
            hasAdminTargets = cachedHasAdminTargets
        });
    }

    private void StartQuickScan()
    {
        if (budgetReached && scanOpen && session.IsPaused)
        {
            pendingStart = null;
            pendingChatScan = false;
            pendingQuickScan = true;
            StopScan();
            return;
        }
        if (cleaning || recyclingSingle)
        {
            PostMessage(new { action = "scanRejected", error = "正在处理文件，请稍候再扫描。" });
            return;
        }
        if (scanOpen || (session.IsBusy && !session.IsPaused))
        {
            PostMessage(new { action = "scanRejected", error = "上一轮扫描正在收尾，请稍后再试。" });
            return;
        }

        CacheRuleRegistry.RefreshRootsCache();
        string[] roots = FilterOutSelfRoots(CacheRuleRegistry.GetQuickScanRoots());
        StartMultiRootPresetScan(roots, "常见缓存位置", true, false);
    }

    private void StartChatScan()
    {
        if (budgetReached && scanOpen && session.IsPaused)
        {
            pendingStart = null;
            pendingQuickScan = false;
            pendingChatScan = true;
            StopScan();
            return;
        }
        if (cleaning || recyclingSingle)
        {
            PostMessage(new { action = "scanRejected", error = "正在处理文件，请稍候再扫描。" });
            return;
        }
        if (scanOpen || (session.IsBusy && !session.IsPaused))
        {
            PostMessage(new { action = "scanRejected", error = "上一轮扫描正在收尾，请稍后再试。" });
            return;
        }

        CacheRuleRegistry.RefreshRootsCache();
        string[] roots = DiscoverChatScanRoots();
        StartMultiRootPresetScan(roots, "微信 / QQ 存储空间", false, true);
    }

    private static string[] DiscoverChatScanRoots()
    {
        List<string> raw = new List<string>();
        ChatStorageLocator.ChatDataFolder[] dataFolders = ChatStorageLocator.DiscoverChatDataFolders();
        if (dataFolders != null)
        {
            for (int i = 0; i < dataFolders.Length; i++)
            {
                if (dataFolders[i] != null && !string.IsNullOrEmpty(dataFolders[i].Path))
                {
                    raw.Add(dataFolders[i].Path);
                }
            }
        }

        CacheRoots.Root[] pureRoots = ChatStorageLocator.DiscoverPureChatCacheRoots();
        if (pureRoots != null)
        {
            for (int i = 0; i < pureRoots.Length; i++)
            {
                if (pureRoots[i] != null && !string.IsNullOrEmpty(pureRoots[i].Directory))
                {
                    raw.Add(pureRoots[i].Directory);
                }
            }
        }

        return FilterOutSelfRoots(CacheRuleRegistry.NormalizeQuickScanRoots(raw));
    }

    private void StartMultiRootPresetScan(string[] roots, string titlePrefix, bool isQuick, bool isChat)
    {
        RefreshAdminStateCache();
        if (roots == null || roots.Length == 0)
        {
            selectedTargets.Clear();
            currentScanRoots.Clear();
            currentScanRoot = titlePrefix + "（0 处）";
            UpdateCurrentDriveContext(currentScanRoots);
            allRows.Clear();
            ResetLiveAccumulators();
            detailSnapshot = null;
            snapshotVersion++;
            deliveredFiles = 0;
            lastDirectorySummaryUpdateCount = 0;
            idMap.Clear();
            rowIds.Clear();
            scanSessionId++;
            directorySummary = new DirectorySummary(new string[0], currentScanRoot);
            directorySummary.StartScan(scanSessionId);
            cleanLockedReason = "";
            stopRequested = false;
            budgetReached = false;
            scanOpen = false;

            PostMessage(new
            {
                action = "scanStarted",
                scanSessionId = scanSessionId,
                target = currentScanRoot,
                quick = isQuick,
                chat = isChat,
                driveLabel = currentDriveLabel,
                driveFreeBytes = currentDriveFreeBytes,
                driveTotalBytes = currentDriveTotalBytes,
                isAdmin = cachedIsAdmin,
                hasAdminTargets = cachedHasAdminTargets
            });
            PostMessage(new
            {
                action = "scanComplete",
                scanSessionId = scanSessionId,
                endKind = "ended",
                stopped = false,
                limited = false,
                completed = true,
                failedOverall = false,
                analysisWarning = false,
                canContinue = false,
                budgetReason = "",
                resumeBlocked = "",
                rounds = 1,
                analyzed = 0,
                delivered = 0,
                fileCount = 0,
                discoveredFiles = 0,
                notAnalyzed = 0,
                directoryCount = 0,
                lockedCacheBytes = 0L,
                driveLabel = currentDriveLabel,
                driveFreeBytes = currentDriveFreeBytes,
                driveTotalBytes = currentDriveTotalBytes,
                isAdmin = cachedIsAdmin,
                hasAdminTargets = cachedHasAdminTargets,
                currentPath = "",
                coverage = new ScanCoverage { Root = currentScanRoot },
                categories = new object[0],
                inaccessibles = new string[0],
                incomplete = false,
                error = "",
                failed = 0,
                evidenceIncomplete = 0
            });
            return;
        }

        string why;
        if (!session.StartTargets(roots, scanBudget, out why))
        {
            PostMessage(new { action = "scanRejected", error = why });
            return;
        }

        selectedTargets.Clear();
        selectedTargets.AddRange(session.Roots);
        currentScanRoots.Clear();
        currentScanRoots.AddRange(session.Roots);
        currentScanRoot = titlePrefix + "（" + currentScanRoots.Count + " 处）";
        UpdateCurrentDriveContext(currentScanRoots);
        allRows.Clear();
        ResetLiveAccumulators();
        detailSnapshot = null;
        snapshotVersion++;
        deliveredFiles = 0;
        lastDirectorySummaryUpdateCount = 0;
        idMap.Clear();
        rowIds.Clear();
        directorySummary = new DirectorySummary(currentScanRoots, currentScanRoot);
        directorySummary.StartScan(scanSessionId + 1);
        cleanLockedReason = "";
        stopRequested = false;
        budgetReached = false;
        scanSessionId++;
        scanOpen = true;
        progressTimer.Start();
        PostMessage(new
        {
            action = "scanStarted",
            scanSessionId = scanSessionId,
            target = currentScanRoot,
            quick = isQuick,
            chat = isChat,
            driveLabel = currentDriveLabel,
            driveFreeBytes = currentDriveFreeBytes,
            driveTotalBytes = currentDriveTotalBytes,
            isAdmin = cachedIsAdmin,
            hasAdminTargets = cachedHasAdminTargets
        });
    }

    private static string[] FilterOutSelfRoots(string[] roots)
    {
        if (roots == null || roots.Length == 0) return roots;
        string selfRoot = "";
        string selfWebView = "";
        string legacyLocalAppData = "";
        try { selfRoot = PathGuard.Canonical(AppDataPaths.Root); } catch { }
        try { selfWebView = PathGuard.Canonical(AppDataPaths.WebView); } catch { }
        try
        {
            string lad = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (!string.IsNullOrEmpty(lad))
                legacyLocalAppData = PathGuard.Canonical(Path.Combine(lad, "CanIDelete"));
        }
        catch { }

        List<string> safe = new List<string>(roots.Length);
        for (int i = 0; i < roots.Length; i++)
        {
            string r = roots[i];
            if (string.IsNullOrEmpty(r)) continue;
            if (!string.IsNullOrEmpty(selfRoot) && PathGuard.IsInside(selfRoot, r)) continue;
            if (!string.IsNullOrEmpty(selfWebView) && PathGuard.IsInside(selfWebView, r)) continue;
            if (!string.IsNullOrEmpty(legacyLocalAppData) && PathGuard.IsInside(legacyLocalAppData, r)) continue;
            safe.Add(r);
        }
        return safe.ToArray();
    }

    private void StopScan()
    {
        if (!scanOpen || stopRequested) return;
        stopRequested = true;
        session.RequestCancel();
        PostMessage(new { action = "scanStopping", scanSessionId = scanSessionId });
    }

    private void ContinueScan()
    {
        string why;
        if (!scanOpen || !budgetReached || !session.CanContinue || !session.TryContinue(out why))
        {
            PostMessage(new { action = "scanRejected", continueBlocked = true, error = "暂停游标已失效或无法继续，请重新选择扫描位置。" });
            return;
        }
        budgetReached = false;
        stopRequested = false;
        PostMessage(new { action = "scanContinued", scanSessionId = scanSessionId, target = currentScanRoot });
    }

    private void OnProgressTick(object sender, EventArgs e)
    {
        if (hostForm != null && (hostForm.IsDisposed || hostForm.Disposing))
        {
            progressTimer.Stop();
            return;
        }

        if (!scanOpen) return;
        int before = allRows.Count;
        session.Pump(allRows, 64, 16384);
        for (int i = before; i < allRows.Count; i++) if (!allRows[i].IsDirectory) deliveredFiles++;
        EnsureLiveAccumulatorsUpdated();
        if (directorySummary != null && allRows.Count > lastDirectorySummaryUpdateCount)
        {
            directorySummary.UpdateFromRows(allRows, lastDirectorySummaryUpdateCount);
            lastDirectorySummaryUpdateCount = allRows.Count;
        }

        if (budgetReached)
        {
            if (!session.IsDrained) return;
            progressTimer.Stop();
            FinishScanReport(true);
            if (pendingQuickScan)
            {
                pendingQuickScan = false;
                StartQuickScan();
            }
            else if (pendingChatScan)
            {
                pendingChatScan = false;
                StartChatScan();
            }
            else if (pendingStart != null)
            {
                var next = pendingStart;
                pendingStart = null;
                StartScan(next);
            }
            return;
        }
        ScanProgress final;
        if (session.TryFinalize(out final))
        {
            if (session.IsPaused)
            {
                budgetReached = true;
                PostScanReport(true, false);
                return;
            }
            progressTimer.Stop();
            FinishScanReport(stopRequested);
            return;
        }

        if (session.State != ScanSessionState.Scanning && session.State != ScanSessionState.Cancelling)
        {
            progressTimer.Stop();
            FinishScanReport(stopRequested);
            return;
        }

        var cats = AggregateCategories(false);
        var progress = new
        {
            action = "scanProgress",
            scanSessionId = scanSessionId,
            discovered = session.Progress != null ? session.Progress.Discovered : allRows.Count,
            analyzed = session.Progress != null ? session.Progress.Analyzed : allRows.Count,
            delivered = session.Delivered,
            currentPath = session.Progress.CurrentPath,
            fileCount = deliveredFiles,
            discoveredFiles = session.Progress.FilesDiscovered,
            directoryCount = session.Progress.DirectoryEntries,
            lockedCacheBytes = lockedCacheBytes,
            driveLabel = currentDriveLabel,
            driveFreeBytes = currentDriveFreeBytes,
            driveTotalBytes = currentDriveTotalBytes,
            isAdmin = cachedIsAdmin,
            hasAdminTargets = cachedHasAdminTargets,
            coverage = session.Progress.Coverage,
            categories = cats
        };
        PostMessage(progress);
    }

    private void FinishScanReport(bool stopped)
    {
        scanOpen = false;
        PostScanReport(false, stopped);
    }

    internal static string EndKind(ScanProgress progress, bool paused, bool stopped, string error)
    {
        if (paused) return "paused";
        if (!string.IsNullOrEmpty(error)) return "failed";
        if (stopped) return "stopped";
        if (!progress.IsScanExhaustive) return "failed";
        var c = progress.Coverage;
        return progress.Failed > 0 || progress.RowsDropped > 0 || (c != null && (c.UnreadableDirectories > 0 || c.ReparseSkipped > 0 || c.MetadataFailures > 0)) ? "endedWithWarnings" : "ended";
    }

    private void PostScanReport(bool paused, bool stopped)
    {
        RefreshAdminStateCache();
        RefreshCurrentDriveSpace();
        ScanProgress p = session.Progress;
        ScanCoverage c = p.Coverage;
        bool coverageWarning = !p.IsScanExhaustive || (c != null && (c.UnreadableDirectories > 0 || c.ReparseSkipped > 0 || c.MetadataFailures > 0));
        bool localWarning = p.Failed > 0 || p.RowsDropped > 0;
        if (directorySummary != null) directorySummary.SetPartial(paused || stopped || coverageWarning || localWarning);
        EnsureLiveAccumulatorsUpdated();
        var cats = AggregateCategories(true);
        string endKind = EndKind(p, paused, stopped, session.LastError);
        bool naturalEnd = endKind == "ended" || endKind == "endedWithWarnings";
        var report = new
        {
            action = paused ? "scanPaused" : "scanComplete",
            scanSessionId = scanSessionId,
            endKind = endKind,
            stopped = stopped,
            limited = paused,
            completed = naturalEnd,
            failedOverall = endKind == "failed",
            analysisWarning = localWarning,
            canContinue = paused && session.CanContinue,
            budgetReason = p.SliceStop == ScanStopReason.TimeBudget ? "本轮时间预算" : (p.SliceStop == ScanStopReason.TopLevelBudget ? "本轮枚举条目预算" : "本轮分析条目预算"),
            resumeBlocked = p.ResumeBlocked,
            rounds = p.Rounds,
            analyzed = p.Analyzed,
            delivered = allRows.Count,
            fileCount = deliveredFiles,
            discoveredFiles = p.FilesDiscovered,
            notAnalyzed = p.NotAnalyzed,
            directoryCount = p.DirectoryEntries,
            lockedCacheBytes = lockedCacheBytes,
            driveLabel = currentDriveLabel,
            driveFreeBytes = currentDriveFreeBytes,
            driveTotalBytes = currentDriveTotalBytes,
            isAdmin = cachedIsAdmin,
            hasAdminTargets = cachedHasAdminTargets,
            currentPath = p.CurrentPath,
            coverage = c,
            categories = cats,
            inaccessibles = c == null ? new string[0] : c.SkippedPaths,
            incomplete = coverageWarning,
            error = session.LastError,
            failed = p.Failed,
            evidenceIncomplete = p.ContentUnverified
        };
        PostMessage(report);
    }

    private const int MaxFilesPerCategory = 500;

    private static List<KeyValuePair<string, string>> GetCategoryDefinitions()
    {
        var list = new List<KeyValuePair<string, string>>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        Action<string, string> add = delegate(string id, string name)
        {
            if (string.IsNullOrEmpty(id)) return;
            if (seen.Add(id))
            {
                list.Add(new KeyValuePair<string, string>(id, name));
            }
        };

        add("wx", "微信 / 办公聊天缓存");
        CacheRuleSpec[] specs = CacheRuleRegistry.All;
        for (int i = 0; i < specs.Length; i++)
        {
            CacheRuleSpec s = specs[i];
            if (s.CategoryId != "tmp")
            {
                add(s.CategoryId, string.IsNullOrEmpty(s.CategoryName) ? s.RuleLabel : s.CategoryName);
            }
        }
        add("log", "安装与系统更新日志");
        add("draft", "办公草稿与自动保存");
        add("dl", "未完成下载残留");
        add("upd", "应用程序更新残留");
        add("user", "受保护系统/用户数据");
        add("tmp", "其他未识别文件");
        return list;
    }

    private void ResetLiveAccumulators()
    {
        var defs = GetCategoryDefinitions();
        liveCatMap = new Dictionary<string, CategoryAccumulator>(StringComparer.Ordinal);
        liveCatOrder = new List<CategoryAccumulator>(defs.Count);
        for (int i = 0; i < defs.Count; i++)
        {
            CategoryAccumulator acc = new CategoryAccumulator { Id = defs[i].Key, Name = defs[i].Value, OrderIndex = i };
            liveCatMap[acc.Id] = acc;
            liveCatOrder.Add(acc);
        }
        lastAggregatedRowCount = 0;
        lockedCacheBytes = 0L;
    }

    private void EnsureLiveAccumulatorsUpdated()
    {
        if (liveCatMap == null || liveCatOrder == null || lastAggregatedRowCount > allRows.Count)
        {
            ResetLiveAccumulators();
        }

        for (int i = lastAggregatedRowCount; i < allRows.Count; i++)
        {
            ListRow r = allRows[i];
            long bytes = Math.Max(0L, r.Bytes);
            if (!r.IsDirectory && r.LockedCleanableCache)
            {
                lockedCacheBytes += bytes;
            }
            if (scanBudget.Recursive && r.IsDirectory) continue;

            string catId = MapRuleToCategory(r.RuleId);
            CategoryAccumulator acc;
            if (!liveCatMap.TryGetValue(catId, out acc))
            {
                acc = liveCatMap["tmp"];
            }

            acc.Count++;
            if (r.PolicyEligible && r.Risk == "安全")
            {
                acc.OkBytes += bytes;
            }
            else if (r.Risk == "需复核")
            {
                acc.ReviewBytes += bytes;
            }
            else
            {
                acc.KeepBytes += bytes;
            }
        }

        lastAggregatedRowCount = allRows.Count;
    }

    private void RebuildLiveAccumulators()
    {
        ResetLiveAccumulators();
        EnsureLiveAccumulatorsUpdated();
    }

    private List<object> AggregateCategories(bool includeFiles)
    {
        EnsureLiveAccumulatorsUpdated();

        List<int>[] indexesByCat = null;
        if (includeFiles)
        {
            indexesByCat = new List<int>[liveCatOrder.Count];
            for (int m = 0; m < liveCatOrder.Count; m++)
            {
                indexesByCat[m] = new List<int>();
            }
            for (int i = 0; i < allRows.Count; i++)
            {
                ListRow r = allRows[i];
                if (scanBudget.Recursive && r.IsDirectory) continue;
                string catId = MapRuleToCategory(r.RuleId);
                CategoryAccumulator acc;
                if (!liveCatMap.TryGetValue(catId, out acc))
                {
                    acc = liveCatMap["tmp"];
                }
                indexesByCat[acc.OrderIndex].Add(i);
            }
        }

        const double gbDiv = 1024.0 * 1024.0 * 1024.0;
        List<object> result = new List<object>(liveCatOrder.Count);
        for (int m = 0; m < liveCatOrder.Count; m++)
        {
            CategoryAccumulator acc = liveCatOrder[m];
            long totalBytes = acc.OkBytes + acc.ReviewBytes + acc.KeepBytes;
            if (totalBytes > 0 || acc.Count > 0)
            {
                double okGb = acc.OkBytes / gbDiv;
                double reviewGb = acc.ReviewBytes / gbDiv;
                double keepGb = acc.KeepBytes / gbDiv;
                double totGb = okGb + reviewGb + keepGb;

                object filesPayload = emptyFilesArray;
                if (includeFiles)
                {
                    List<int> idxs = indexesByCat[m];
                    idxs.Sort(delegate(int x, int y) { return allRows[y].Bytes.CompareTo(allRows[x].Bytes); });
                    int take = Math.Min(idxs.Count, MaxFilesPerCategory);
                    object[] projected = new object[take];
                    for (int k = 0; k < take; k++)
                    {
                        projected[k] = ProjectFile(allRows[idxs[k]]);
                    }
                    filesPayload = projected;
                }

                result.Add(new
                {
                    id = acc.Id,
                    name = acc.Name,
                    ok = okGb,
                    review = reviewGb,
                    keep = keepGb,
                    total = totGb,
                    count = acc.Count,
                    files = filesPayload
                });
            }
        }

        return result;
    }

    private static string GetRowDirectory(ListRow r)
    {
        if (r == null) return "";
        if (!string.IsNullOrEmpty(r.DirectoryPath)) return r.DirectoryPath;
        return Path.GetDirectoryName(r.Path) ?? "";
    }

    private object ProjectFile(ListRow r)
    {
        int id;
        if (!rowIds.TryGetValue(r, out id)) { id = nextFileId++; rowIds[r] = id; }
        idMap[id] = r;
        string dir = GetRowDirectory(r);
        if (dir.Length > 0 && dir[dir.Length - 1] != '\\') dir += "\\";
        string why = !string.IsNullOrWhiteSpace(r.Reason) ? r.Reason
            : (!string.IsNullOrWhiteSpace(r.DenyReason) ? r.DenyReason : "未提供判断依据");
        CacheRuleSpec spec = CacheRuleRegistry.Find(r.RuleId);
        bool showHeader = r.ContentVerified && spec != null && spec.ReportHeaderInDetail;

        return new
        {
            id = id,
            catId = MapRuleToCategory(r.RuleId),
            n = r.Name,
            s = r.Bytes / (1024.0 * 1024.0 * 1024.0),
            p = dir,
            j = Judgement(r),
            r = ScanText.RuleLabel(r.RuleId),
            why = why,
            mt = r.LastWriteUtc == DateTime.MinValue ? "未知" : r.LastWriteUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
            x = new
            {
                why2 = !r.PolicyEligible && r.DenyReason != why ? r.DenyReason : "",
                detail = AnPingExplanation.For(r),
                bytes = r.Bytes,
                ruleId = r.RuleId,
                ruleVersion = "未读取",
                created = "未读取",
                accessed = "未读取",
                attributes = r.WasReadOnly ? "只读（其他属性未读取）" : "完整属性未读取",
                header = showHeader ? r.EvidenceDetail : "未读取",
                process = "未读取",
                purpose = ExplainPurpose(r),
                evidence = r.EvidenceDetail,
                conclusion = ScanText.EvidenceConclusion(r.ContentVerified).Replace("结论强度：", ""),
                sizeComplete = r.SizeComplete,
                scope = r.Scope,
                excludes = r.Excludes,
                consequence = r.Consequence,
                sizeReason = r.SizeComplete ? "" : (string.IsNullOrEmpty(r.SizeReason) ? "大小统计不完整" : r.SizeReason)
            }
        };
    }

    private static Dictionary<string, string> ExplainPurpose(ListRow r)
    {
        if (r.IsDirectory) return null;
        try
        {
            string cache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Installer");
            string file = Path.GetFullPath(r.Path);
            string ext = Path.GetExtension(file);
            if (!string.Equals(Path.GetDirectoryName(file), cache, StringComparison.OrdinalIgnoreCase)
                || !(ext.Equals(".msi", StringComparison.OrdinalIgnoreCase) || ext.Equals(".msp", StringComparison.OrdinalIgnoreCase))) return null;
            return new Dictionary<string, string>
            {
                { "title", "Windows Installer 安装维护缓存" },
                { "basis", "位置与扩展名符合 Windows Installer 默认缓存位置；这是目录用途说明，不是该文件内容或归属的验证。" },
                { "use", "微软说明：此缓存保存已安装应用的重要文件，用于软件修复、更新和卸载。缺失后可能直到进行这些操作时才暴露问题。" },
                { "owner", "尚未核实具体所属软件；不能从随机文件名或体积推断，也不能据此判断为孤立残留。" },
                { "advice", "不建议手动删除。若不再需要对应软件，请使用其正式卸载入口；缓存异常应联系软件厂商，不要逐个试删。" },
                { "source", "微软官方 · KB 2667628" },
                { "url", "https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/missing-windows-installer-cache" }
            };
        }
        catch (ArgumentException) { return null; }
        catch (NotSupportedException) { return null; }
        catch (PathTooLongException) { return null; }
    }

    private static string Judgement(ListRow r)
    {
        return r.PolicyEligible && r.Risk == "安全" ? "ok" : (r.Risk == "需复核" ? "review" : "keep");
    }

    private bool ValidSnapshot(Dictionary<string, object> msg)
    {
        object value;
        if (!msg.TryGetValue("snapshot", out value)) return true;
        int snap;
        if (!TryGetInt32(msg, "snapshot", out snap)) return false;
        return snap == 0 || (detailSnapshot != null && snap == snapshotVersion);
    }

    private void SendFilesPage(Dictionary<string, object> msg)
    {
        int request;
        if (!TryGetInt32(msg, "request", out request)) request = -1;
        int offset;
        if (!TryGetInt32(msg, "offset", out offset)) offset = -1;
        if (!ValidSnapshot(msg))
        {
            PostMessage(new { action = "filesPage", request = msg.ContainsKey("request") ? msg["request"] : null, error = "快照已失效，请重新打开。" });
            return;
        }

        int version = 0;
        if (msg.ContainsKey("snapshot"))
        {
            if (!TryGetInt32(msg, "snapshot", out version))
            {
                PostMessage(new { action = "filesPage", request = request, error = "无效的明细参数" });
                return;
            }
        }
        if (version != 0 && (version != snapshotVersion || detailSnapshot == null))
        {
            PostMessage(new { action = "filesPage", request = request, error = "明细快照已过期，请重新打开。" });
            return;
        }

        var source = version == 0 ? allRows : detailSnapshot;
        string filter = msg.ContainsKey("filter") ? (Convert.ToString(msg["filter"]) ?? "") : "";
        string sort = msg.ContainsKey("sort") ? (Convert.ToString(msg["sort"]) ?? "") : "";
        string query = msg.ContainsKey("query") ? (Convert.ToString(msg["query"]) ?? "") : "";
        string group = msg.ContainsKey("group") ? (Convert.ToString(msg["group"]) ?? "") : "";
        string[] allowed = GetCategoryDefinitions().Select(delegate(KeyValuePair<string, string> kv) { return kv.Key; }).ToArray();
        var raw = msg.ContainsKey("categories") ? msg["categories"] as System.Collections.ArrayList : null;

        if (request < 0 || offset < 0 || source == null || offset > source.Count
            || raw == null || raw.Count == 0 || raw.Count > allowed.Length
            || query.Length > 200 || group.Length > 32768
            || !new[] { "all", "ok", "review", "keep" }.Contains(filter) || (sort != "size" && sort != "name"))
        {
            PostMessage(new { action = "filesPage", request = request, error = "无效的明细参数" });
            return;
        }

        string[] cats = raw.Cast<object>().Select(delegate(object v) { return Convert.ToString(v) ?? ""; }).ToArray();
        if (cats.Distinct().Count() != cats.Length || cats.Any(delegate(string c) { return !allowed.Contains(c); }))
        {
            PostMessage(new { action = "filesPage", request = request, error = "无效的明细参数" });
            return;
        }

        var catSet = new HashSet<string>(cats, StringComparer.Ordinal);
        var rows = new List<ListRow>();
        for (int i = 0; i < source.Count; i++)
        {
            ListRow r = source[i];
            if (r.IsDirectory) continue;
            if (!catSet.Contains(MapRuleToCategory(r.RuleId))) continue;
            if (group.Length > 0 && ReviewGroupKey(r) != group) continue;
            if (query.Length > 0 && r.Name.IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0
                && GetRowDirectory(r).IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0
                && r.Path.IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0) continue;
            rows.Add(r);
        }

        int okCnt = 0, rvCnt = 0, kpCnt = 0;
        var matched = new List<ListRow>(rows.Count);
        for (int i = 0; i < rows.Count; i++)
        {
            ListRow r = rows[i];
            string j = Judgement(r);
            if (j == "ok") okCnt++;
            else if (j == "review") rvCnt++;
            else kpCnt++;
            if (filter == "all" || j == filter) matched.Add(r);
        }

        var counts = new { all = rows.Count, ok = okCnt, review = rvCnt, keep = kpCnt };
        const int limit = 100;
        offset = matched.Count == 0 ? 0 : Math.Min(offset, ((matched.Count - 1) / limit) * limit);
        var names = StringComparer.Create(CultureInfo.GetCultureInfo("zh-CN"), false);
        matched.Sort(delegate(ListRow a, ListRow b)
        {
            int c = Array.IndexOf(cats, MapRuleToCategory(a.RuleId)).CompareTo(Array.IndexOf(cats, MapRuleToCategory(b.RuleId)));
            if (c == 0) c = sort == "size" ? b.Bytes.CompareTo(a.Bytes) : names.Compare(a.Name, b.Name);
            if (c != 0) return c;
            c = StringComparer.OrdinalIgnoreCase.Compare(GetRowDirectory(a), GetRowDirectory(b));
            return c != 0 ? c : StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name);
        });

        PostMessage(new
        {
            action = "filesPage",
            request = request,
            snapshot = version,
            offset = offset,
            limit = limit,
            total = matched.Count,
            logicalBytes = matched.Sum(delegate(ListRow r) { return r.Bytes; }),
            counts = counts,
            files = matched.Skip(offset).Take(limit).Select(ProjectFile).ToArray()
        });
    }

    private static string ReviewGroupKey(ListRow r)
    {
        return GetRowDirectory(r) + "\n" + (r.Reason ?? "未知依据");
    }

    private void SendReviewGroups(Dictionary<string, object> msg)
    {
        int version = 0;
        bool snapOk = !msg.ContainsKey("snapshot") || TryGetInt32(msg, "snapshot", out version);
        var source = version == 0 ? allRows : detailSnapshot;
        int offset = 0;
        bool offsetOk = !msg.ContainsKey("offset") || TryGetInt32(msg, "offset", out offset);
        if (!snapOk || !offsetOk || !ValidSnapshot(msg) || source == null || offset < 0 || offset > source.Count)
        {
            PostMessage(new { action = "reviewGroups", request = msg.ContainsKey("request") ? msg["request"] : null, error = "分组快照已失效，请重新打开。" });
            return;
        }
        var rows = source.Where(delegate(ListRow r) { return !r.IsDirectory && Judgement(r) == "review"; }).ToList();
        var groups = rows.GroupBy(ReviewGroupKey)
            .OrderByDescending(delegate(IGrouping<string, ListRow> g) { return g.Sum(delegate(ListRow r) { return r.Bytes; }); })
            .Select(delegate(IGrouping<string, ListRow> g)
            {
                ListRow first = g.First();
                return new
                {
                    key = g.Key,
                    folder = GetRowDirectory(first),
                    reason = first.Reason,
                    count = g.Count(),
                    bytes = g.Sum(delegate(ListRow r) { return r.Bytes; }),
                    incomplete = g.Count(delegate(ListRow r) { return !r.SizeComplete; }),
                    oldest = g.Where(delegate(ListRow r) { return r.LastWriteUtc != DateTime.MinValue; }).Select(delegate(ListRow r) { return r.LastWriteUtc; }).DefaultIfEmpty(DateTime.MinValue).Min(),
                    newest = g.Where(delegate(ListRow r) { return r.LastWriteUtc != DateTime.MinValue; }).Select(delegate(ListRow r) { return r.LastWriteUtc; }).DefaultIfEmpty(DateTime.MinValue).Max(),
                    sample = g.OrderByDescending(delegate(ListRow r) { return r.Bytes; }).Take(3).Select(delegate(ListRow r)
                    {
                        return new { name = r.Name, bytes = r.Bytes, evidence = r.EvidenceDetail, scope = r.Scope, consequence = r.Consequence };
                    }).ToArray()
                };
            }).ToArray();

        const int limit = 30;
        offset = groups.Length == 0 ? 0 : Math.Min(offset, ((groups.Length - 1) / limit) * limit);
        PostMessage(new
        {
            action = "reviewGroups",
            snapshot = version,
            request = msg.ContainsKey("request") ? msg["request"] : null,
            count = rows.Count,
            bytes = rows.Sum(delegate(ListRow r) { return r.Bytes; }),
            totalGroups = groups.Length,
            offset = offset,
            limit = limit,
            groups = groups.Skip(offset).Take(limit).ToArray()
        });
    }

    private void SendDirectoriesPage(Dictionary<string, object> msg)
    {
        int request;
        if (!TryGetInt32(msg, "request", out request)) request = -1;
        int directoryId;
        if (!TryGetInt32(msg, "directoryId", out directoryId)) directoryId = -1;
        int offset;
        if (!TryGetInt32(msg, "offset", out offset)) offset = -1;
        long sessionId;
        if (!TryGetInt64(msg, "scanSessionId", out sessionId)) sessionId = -1L;

        if (request < 0 || directoryId < 0 || offset < 0 || sessionId < 0 || sessionId != scanSessionId || directorySummary == null)
        {
            PostMessage(new { action = "directoriesPage", request = request, error = "无效的目录查询参数或会话不匹配" });
            return;
        }

        var page = directorySummary.Query(sessionId, directoryId, offset);
        if (page == null)
        {
            PostMessage(new { action = "directoriesPage", request = request, error = "目录 ID 不存在或已过期" });
            return;
        }

        var breadcrumbData = page.Breadcrumb.Select(delegate(DirectorySummary.DirectoryBreadcrumb b)
        {
            return new { id = b.DirectoryId, name = b.Name, path = b.Path };
        }).ToArray();
        var parentData = page.ParentDirectory == null ? null : new { id = page.ParentDirectory.DirectoryId, name = page.ParentDirectory.Name, path = page.ParentDirectory.Path };
        var rowsData = page.Rows.Select(delegate(DirectorySummary.DirectoryRow r)
        {
            return new
            {
                id = r.DirectoryId,
                isDirectory = r.IsDirectory,
                file = r.File == null ? null : ProjectFile(r.File),
                name = r.Name,
                path = r.Path,
                bytes = r.Bytes,
                fileCount = r.FileCount,
                eligible = r.EligibleCount,
                review = r.ReviewCount,
                keep = r.KeepCount,
                eligibleBytes = r.EligibleBytes,
                reviewBytes = r.ReviewBytes,
                keepBytes = r.KeepBytes,
                partial = r.IsPartial,
                sizeComplete = r.SizeComplete
            };
        }).ToArray();

        PostMessage(new
        {
            action = "directoriesPage",
            request = request,
            scanSessionId = scanSessionId,
            directoryId = page.DirectoryId,
            currentPath = page.CurrentPath,
            currentName = page.CurrentName,
            parent = parentData,
            breadcrumb = breadcrumbData,
            totalBytes = page.TotalBytes,
            totalFileCount = page.TotalFileCount,
            totalRows = page.TotalRows,
            pageLimit = page.PageLimit,
            pageOffset = page.PageOffset,
            partial = page.IsPartial || scanOpen,
            eligible = page.EligibleCount,
            review = page.ReviewCount,
            keep = page.KeepCount,
            eligibleBytes = page.EligibleBytes,
            reviewBytes = page.ReviewBytes,
            keepBytes = page.KeepBytes,
            source = "只汇总本次已分析的文件；未进入的目录和空目录不在此列。",
            rows = rowsData
        });
    }

    private void SendLargeFiles(Dictionary<string, object> msg)
    {
        int request;
        if (!TryGetInt32(msg, "request", out request)) request = -1;
        long sessionId;
        if (!TryGetInt64(msg, "scanSessionId", out sessionId)) sessionId = -1L;
        if (request < 0 || sessionId < 0 || sessionId != scanSessionId)
        {
            PostMessage(new { action = "largeFilesPage", request = request, scanSessionId = scanSessionId, error = "无效的大文件查询参数或会话不匹配" });
            return;
        }

        int limit = 100;
        int parsedLimit;
        if (TryGetInt32(msg, "limit", out parsedLimit))
        {
            limit = parsedLimit;
        }
        if (limit < 1) limit = 1;
        if (limit > 200) limit = 200;

        bool excludeCacheShards = true;
        object exclObj;
        if (msg.TryGetValue("excludeCacheShards", out exclObj) && exclObj != null)
        {
            if (exclObj is bool) excludeCacheShards = (bool)exclObj;
            else
            {
                bool parsed;
                if (bool.TryParse(Convert.ToString(exclObj), out parsed)) excludeCacheShards = parsed;
            }
        }

        string filterMode = "";
        object fmObj;
        if (msg.TryGetValue("filterMode", out fmObj) && fmObj != null)
        {
            string rawMode = (Convert.ToString(fmObj) ?? "").Trim().ToLowerInvariant();
            if (rawMode == "chat")
            {
                filterMode = "chat";
                excludeCacheShards = true;
            }
            else if (rawMode == "all")
            {
                filterMode = "all";
                excludeCacheShards = false;
            }
            else if (rawMode == "independent")
            {
                filterMode = "independent";
                excludeCacheShards = true;
            }
        }
        if (string.IsNullOrEmpty(filterMode))
        {
            filterMode = excludeCacheShards ? "independent" : "all";
        }

        int allFileCount = 0;
        int independentCount = 0;
        int chatFileCount = 0;
        long allFileBytes = 0L;
        long independentBytes = 0L;
        long chatFileBytes = 0L;
        List<ListRow> candidates = new List<ListRow>();

        for (int i = 0; i < allRows.Count; i++)
        {
            ListRow r = allRows[i];
            if (r.IsDirectory) continue;
            long b = Math.Max(0L, r.Bytes);
            allFileCount++;
            allFileBytes += b;
            bool isCacheShard = CacheRuleRegistry.IsCleanableRule(r.RuleId);
            if (!isCacheShard)
            {
                independentCount++;
                independentBytes += b;
            }
            bool isChatFile = !isCacheShard && ChatStorageLocator.IsChatReceivedUserFile(r.Path);
            if (isChatFile)
            {
                chatFileCount++;
                chatFileBytes += b;
            }

            if (filterMode == "chat")
            {
                if (isChatFile) candidates.Add(r);
            }
            else if (filterMode == "all")
            {
                candidates.Add(r);
            }
            else
            {
                if (!isCacheShard) candidates.Add(r);
            }
        }

        candidates.Sort(delegate(ListRow a, ListRow b)
        {
            int c = b.Bytes.CompareTo(a.Bytes);
            if (c != 0) return c;
            c = StringComparer.OrdinalIgnoreCase.Compare(GetRowDirectory(a), GetRowDirectory(b));
            return c != 0 ? c : StringComparer.OrdinalIgnoreCase.Compare(a.Name, b.Name);
        });

        int take = Math.Min(limit, candidates.Count);
        object[] files = new object[take];
        for (int i = 0; i < take; i++)
        {
            files[i] = ProjectFile(candidates[i]);
        }

        long modeTotalBytes = filterMode == "chat"
            ? chatFileBytes
            : (filterMode == "independent" ? independentBytes : allFileBytes);

        PostMessage(new
        {
            action = "largeFilesPage",
            request = request,
            scanSessionId = scanSessionId,
            filterMode = filterMode,
            excludeCacheShards = excludeCacheShards,
            independentCount = independentCount,
            chatFileCount = chatFileCount,
            chatFileBytes = chatFileBytes,
            allFileCount = allFileCount,
            totalFiles = candidates.Count,
            totalBytes = modeTotalBytes,
            partial = scanOpen || budgetReached,
            files = files
        });
    }

    private void SendFileTech(Dictionary<string, object> msg)
    {
        int request;
        if (!TryGetInt32(msg, "request", out request)) request = -1;
        int id;
        if (!TryGetInt32(msg, "id", out id)) id = -1;

        object sidObj;
        if (msg.TryGetValue("scanSessionId", out sidObj))
        {
            long reqSid;
            if (!TryGetInt64(msg, "scanSessionId", out reqSid) || reqSid != scanSessionId)
            {
                PostMessage(new
                {
                    action = "fileTechResult",
                    request = request,
                    id = id,
                    created = "无法读取",
                    accessed = "无法读取",
                    attributes = "无法读取",
                    process = "无法读取"
                });
                return;
            }
        }

        ListRow r;
        if (id < 0 || !idMap.TryGetValue(id, out r) || r == null || string.IsNullOrEmpty(r.Path))
        {
            PostMessage(new
            {
                action = "fileTechResult",
                request = request,
                id = id,
                created = "无法读取",
                accessed = "无法读取",
                attributes = "无法读取",
                process = "无法读取"
            });
            return;
        }

        if (Interlocked.Increment(ref inFlightFileTech) > 4)
        {
            Interlocked.Decrement(ref inFlightFileTech);
            PostMessage(new
            {
                action = "fileTechResult",
                request = request,
                id = id,
                created = "繁忙，请稍候",
                accessed = "繁忙，请稍候",
                attributes = "繁忙，请稍候",
                process = "繁忙，请稍候"
            });
            return;
        }

        string targetPath = r.Path;
        bool queued = false;
        try
        {
            queued = ThreadPool.QueueUserWorkItem(delegate(object state)
            {
                try
                {
                    if (closingOrDisposed) return;
                    FileTechInfo info = FileDetailProbe.Inspect(targetPath);
                    if (closingOrDisposed) return;
                    PostMessage(new
                    {
                        action = "fileTechResult",
                        request = request,
                        id = id,
                        created = info.Created,
                        accessed = info.Accessed,
                        attributes = info.Attributes,
                        process = info.Process
                    });
                }
                finally
                {
                    Interlocked.Decrement(ref inFlightFileTech);
                }
            });
        }
        catch
        {
            queued = false;
        }
        if (!queued)
        {
            Interlocked.Decrement(ref inFlightFileTech);
            PostMessage(new
            {
                action = "fileTechResult",
                request = request,
                id = id,
                created = "繁忙，请稍候",
                accessed = "繁忙，请稍候",
                attributes = "繁忙，请稍候",
                process = "繁忙，请稍候"
            });
        }
    }

    private string MapRuleToCategory(string ruleId)
    {
        return CacheRuleRegistry.MapRuleToCategory(ruleId);
    }

    private void RevealFileById(int id)
    {
        ListRow r;
        bool success = false;
        string error = "扫描结果已失效，请重新扫描。";
        if (idMap.TryGetValue(id, out r) && r != null)
        {
            string canonPath, why;
            if (Program.TryValidateLocalRevealPath(r.Path, out canonPath, out why))
            {
                IntPtr pidl = IntPtr.Zero;
                try
                {
                    pidl = ILCreateFromPathW(canonPath);
                    if (pidl != IntPtr.Zero)
                    {
                        int hr = SHOpenFolderAndSelectItems(pidl, 0, IntPtr.Zero, 0);
                        if (hr == 0)
                        {
                            success = true;
                        }
                    }
                }
                catch { }
                finally
                {
                    if (pidl != IntPtr.Zero)
                    {
                        try { ILFree(pidl); } catch { }
                    }
                }

                if (!success)
                {
                    string fileName, arguments, cmdWhy;
                    if (Program.TryBuildRevealCommand(canonPath, out fileName, out arguments, out cmdWhy))
                    {
                        try
                        {
                            using (Process proc = Process.Start(Program.BuildRevealStartInfo(fileName, arguments)))
                            {
                                success = proc != null;
                                if (!success) error = "无法打开资源管理器。";
                            }
                        }
                        catch (Exception ex) { error = "无法打开资源管理器：" + ex.Message; }
                    }
                    else
                    {
                        error = cmdWhy;
                    }
                }
            }
            else
            {
                error = why;
            }
        }
        PostMessage(new { action = "fileActionResult", op = "reveal", id = id, success = success, error = success ? "" : error });
    }

    private void CopyPathById(int id)
    {
        ListRow r;
        bool success = false;
        string error = "扫描结果已失效，请重新扫描。";
        if (idMap.TryGetValue(id, out r))
        {
            try { Clipboard.SetText(r.Path); success = true; }
            catch (Exception ex) { error = "无法复制路径：" + ex.Message; }
        }
        PostMessage(new { action = "fileActionResult", op = "copy", id = id, success = success, error = success ? "" : error });
    }

    private void WriteDiagnostic(string action, string stage, Exception error)
    {
        if (Interlocked.Increment(ref diagnosticCount) > 32) return;
        lock (diagnosticLock)
        {
            IntPtr h = IntPtr.Zero;
            try
            {
                string dir = Path.GetDirectoryName(diagnosticFile);
                if (string.IsNullOrEmpty(dir)
                    || !PathGuard.IsLocalDrivePath(dir)
                    || !PathGuard.IsLocalDrivePath(diagnosticFile))
                {
                    return;
                }

                string parentDir = Path.GetDirectoryName(dir.TrimEnd('\\', '/'));
                if (string.IsNullOrEmpty(parentDir) || PathGuard.HasAnyReparseComponent(parentDir)) return;

                if (!Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                if (PathGuard.HasAnyReparseComponent(dir)) return;

                try
                {
                    FileAttributes preAttr = File.GetAttributes(diagnosticFile);
                    if ((preAttr & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0) return;
                }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }

                h = CreateFileW(diagnosticFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, IntPtr.Zero,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
                if (h == IntPtr.Zero || h == new IntPtr(-1))
                {
                    h = IntPtr.Zero;
                    return;
                }

                BY_HANDLE_FILE_INFORMATION info;
                if (!GetFileInformationByHandle(h, out info)) return;
                if ((info.FileAttributes & FILE_ATTR_REPARSE_POINT) != 0) return;
                if ((info.FileAttributes & FILE_ATTR_DIRECTORY) != 0) return;
                if (info.NumberOfLinks > 1) return;

                string expectedLong, actualFinal;
                if (!PathGuard.TryGetLongCanonicalPath(diagnosticFile, out expectedLong)
                    || !PathGuard.TryGetFinalDosPath(h, out actualFinal)
                    || !string.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                IntPtr ownedHandle = h;
                h = IntPtr.Zero;
                using (SafeFileHandle sfh = new SafeFileHandle(ownedHandle, true))
                using (FileStream fs = new FileStream(sfh, FileAccess.ReadWrite))
                {
                    if (fs.Length > 16384)
                    {
                        fs.SetLength(0);
                        fs.Seek(0, SeekOrigin.Begin);
                        byte[] header = Encoding.UTF8.GetBytes("bounded log restarted\n");
                        fs.Write(header, 0, header.Length);
                    }
                    else
                    {
                        fs.Seek(0, SeekOrigin.End);
                    }
                    string line = DateTime.UtcNow.ToString("o") + " action=" + action + " stage=" + stage
                        + " session=" + scanSessionId + " error="
                        + (error == null ? "Unavailable" : error.GetType().Name + "/" + error.HResult.ToString("X"))
                        + Environment.NewLine;
                    byte[] lineBytes = Encoding.UTF8.GetBytes(line);
                    fs.Write(lineBytes, 0, lineBytes.Length);
                    fs.Flush();
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            finally
            {
                if (h != IntPtr.Zero && h != new IntPtr(-1))
                {
                    try { CloseHandle(h); } catch { }
                }
            }
        }
    }

    private volatile bool cleaning;
    private volatile bool recyclingSingle;
    private volatile bool closingOrDisposed;
    private volatile bool isClosingGracefully;
    private string cleanLockedReason = "";
    private volatile bool cleanStopRequested;

    public bool IsBusyWithFileOp
    {
        get { return cleaning || recyclingSingle; }
    }

    public void StopFileOpGracefully(int maxWaitMs)
    {
        closingOrDisposed = true;
        isClosingGracefully = true;
        cleanStopRequested = true;
        if (!IsBusyWithFileOp || maxWaitMs <= 0) return;

        try
        {
            activeFileOpDone.Wait(maxWaitMs);
        }
        catch (ObjectDisposedException) { }
    }

    private void SendCleanSummary(Dictionary<string, object> msg)
    {
        object request = msg.ContainsKey("request") ? msg["request"] : null;
        long sid;
        if (!TryGetInt64(msg, "scanSessionId", out sid) || sid != scanSessionId || scanOpen || cleaning || recyclingSingle)
        {
            PostMessage(new { action = "cleanSummary", request = request, scanSessionId = scanSessionId, error = "扫描或清理状态已变化，请稍后重新打开清单。" });
            return;
        }

        var buckets = new Dictionary<string, List<ListRow>>(StringComparer.Ordinal);
        for (int i = 0; i < allRows.Count; i++)
        {
            ListRow r = allRows[i];
            if (!r.PolicyEligible || r.IsDirectory || !r.SizeComplete || string.IsNullOrEmpty(r.RuleId)) continue;
            List<ListRow> list;
            if (!buckets.TryGetValue(r.RuleId, out list))
            {
                list = new List<ListRow>();
                buckets[r.RuleId] = list;
            }
            list.Add(r);
        }

        var groups = new List<object>();
        CacheRuleSpec[] specs = CacheRuleRegistry.All;
        for (int i = 0; i < specs.Length; i++)
        {
            CacheRuleSpec spec = specs[i];
            List<ListRow> list;
            if (!buckets.TryGetValue(spec.Id, out list) || list.Count == 0) continue;

            long totalBytes = 0;
            var locSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var locations = new List<string>(3);
            for (int k = 0; k < list.Count; k++)
            {
                ListRow row = list[k];
                totalBytes += row.Bytes;
                if (locations.Count < 3)
                {
                    string dir = GetRowDirectory(row);
                    if (!string.IsNullOrEmpty(dir) && locSet.Add(dir))
                    {
                        locations.Add(dir);
                    }
                }
            }

            groups.Add(new
            {
                rule = spec.Id,
                title = spec.GroupTitle,
                cost = spec.GroupCost,
                requiresConfirm = spec.RequiresSeparateConfirm,
                confirmLabel = spec.ConfirmLabel,
                count = list.Count,
                bytes = totalBytes,
                locations = locations.ToArray()
            });
        }

        RefreshAdminStateCache();
        EnsureLiveAccumulatorsUpdated();
        PostMessage(new
        {
            action = "cleanSummary",
            request = request,
            scanSessionId = scanSessionId,
            lockedCacheBytes = lockedCacheBytes,
            isAdmin = cachedIsAdmin,
            hasAdminTargets = cachedHasAdminTargets,
            groups = groups.ToArray()
        });
    }

    private void CleanEligible(Dictionary<string, object> msg)
    {
        object request = msg.ContainsKey("request") ? msg["request"] : null;
        string[] rules;
        string selectionError = CleanSelection.Validate(msg, scanSessionId, out rules);
        if (selectionError != null) { PostMessage(new { action = "cleanResult", request = request, error = selectionError }); return; }
        if (cleaning || recyclingSingle) { PostMessage(new { action = "cleanResult", request = request, error = "正在清理，请稍候。" }); return; }
        if (cleanLockedReason.Length > 0) { PostMessage(new { action = "cleanResult", request = request, error = cleanLockedReason }); return; }
        if (scanOpen || session.IsBusy)
        {
            PostMessage(new { action = "cleanResult", request = request, error = "扫描尚未结束，请等扫描完成后再清理。" });
            return;
        }
        var ruleSet = new HashSet<string>(rules, StringComparer.Ordinal);
        var picked = allRows.Where(delegate(ListRow r) { return r.PolicyEligible && !r.IsDirectory && r.SizeComplete && ruleSet.Contains(r.RuleId); }).ToList();
        if (picked.Count == 0)
        {
            PostMessage(new { action = "cleanResult", request = request, error = "没有符合清理规则的文件。" });
            return;
        }

        var reqs = new List<DeleteRequest>(picked.Count);
        var reqCats = new Dictionary<DeleteRequest, string>();
        for (int i = 0; i < picked.Count; i++)
        {
            ListRow r = picked[i];
            DeleteRequest dr = new DeleteRequest
            {
                Path = r.Path,
                WasDirectory = false,
                BytesAtScan = r.Bytes,
                LastWriteUtcAtScan = r.LastWriteUtc,
                WasReadOnly = r.WasReadOnly,
                PolicyEligible = r.PolicyEligible,
                Risk = r.Risk,
                IdAtScan = r.Id
            };
            reqs.Add(dr);
            reqCats[dr] = MapRuleToCategory(r.RuleId);
        }

        string[] rootsSnapshot = currentScanRoots.Count > 0
            ? currentScanRoots.ToArray()
            : (string.IsNullOrEmpty(currentScanRoot) ? new string[0] : new string[] { currentScanRoot });
        long session0 = scanSessionId;
        string logPath = GetDeleteLogPath();
        cleaning = true;
        cleanStopRequested = false;
        activeFileOpDone.Reset();
        PostMessage(new { action = "cleanProgress", request = request, done = 0, total = reqs.Count, deleted = 0, deletedBytes = 0L, currentPath = "" });

        var worker = new Thread(delegate()
        {
            List<DeleteOutcome> res = null;
            Exception fail = null;
            int deletedCount = 0;
            long deletedBytes = 0;
            int prunedDirs = 0;
            var deletedByCat = new Dictionary<string, long>();
            long minProgressIntervalTicks = Math.Max(1L, Stopwatch.Frequency / 20L); // 50ms throttle
            long lastProgressTicks = 0L;
            try
            {
                res = DeleteEngine.Execute(reqs, rootsSnapshot, new PermanentDeleteBin(), logPath,
                    null,
                    delegate(int done, int total, DeleteRequest req, DeleteOutcome outcome)
                    {
                        if (outcome != null && outcome.Status == DeleteStatus.DeletedVerified)
                        {
                            long b = Math.Max(0, req.BytesAtScan);
                            deletedCount++;
                            deletedBytes += b;
                            string cid;
                            if (reqCats.TryGetValue(req, out cid))
                            {
                                long prev;
                                deletedByCat.TryGetValue(cid, out prev);
                                deletedByCat[cid] = prev + b;
                            }
                        }

                        long nowTicks = Stopwatch.GetTimestamp();
                        if (done == 1 || done == total || (nowTicks - lastProgressTicks) >= minProgressIntervalTicks)
                        {
                            lastProgressTicks = nowTicks;
                            PostMessage(new
                            {
                                action = "cleanProgress",
                                request = request,
                                done = done,
                                total = total,
                                deleted = deletedCount,
                                deletedBytes = deletedBytes,
                                currentPath = req != null ? req.Path : "",
                                deletedByCat = new Dictionary<string, long>(deletedByCat)
                            });
                        }
                    },
                    delegate() { return cleanStopRequested; });

                if (res != null && rootsSnapshot != null && rootsSnapshot.Length > 0)
                {
                    List<string> verifiedDeletedPaths = new List<string>(deletedCount);
                    for (int i = 0; i < res.Count; i++)
                    {
                        DeleteOutcome o = res[i];
                        if (o != null && o.Status == DeleteStatus.DeletedVerified && !string.IsNullOrEmpty(o.Path))
                        {
                            verifiedDeletedPaths.Add(o.Path);
                        }
                    }
                    if (verifiedDeletedPaths.Count > 0 && !isClosingGracefully)
                    {
                        try
                        {
                            prunedDirs = DeleteEngine.PruneEmptyParentDirs(verifiedDeletedPaths, rootsSnapshot);
                        }
                        catch { prunedDirs = 0; }
                    }
                }
            }
            catch (Exception ex) { fail = ex; }
            finally
            {
                try { activeFileOpDone.Set(); } catch (ObjectDisposedException) { }
            }

            DispatchToUiThread(delegate() { FinishClean(request, session0, picked, res, prunedDirs, fail); }, "cleanEligible");
        });
        worker.IsBackground = false;
        try
        {
            worker.Start();
        }
        catch (Exception ex)
        {
            cleaning = false;
            try { activeFileOpDone.Set(); } catch (ObjectDisposedException) { }
            WriteDiagnostic("cleanEligible", "start", ex);
            PostMessage(new { action = "cleanResult", request = request, error = "无法启动清理任务，请重试。" });
        }
    }

    private void RecycleSingleFile(Dictionary<string, object> msg)
    {
        object request = msg.ContainsKey("request") ? msg["request"] : null;
        int id;
        if (!TryGetInt32(msg, "id", out id)) id = -1;

        long sid;
        if (!TryGetInt64(msg, "scanSessionId", out sid) || sid != scanSessionId)
        {
            PostMessage(new { action = "recycleSingleResult", request = request, id = id, success = false, error = "扫描会话已变化，请重新打开文件详情。" });
            return;
        }
        if (cleanLockedReason.Length > 0)
        {
            PostMessage(new { action = "recycleSingleResult", request = request, id = id, success = false, locked = true, error = cleanLockedReason });
            return;
        }
        if (scanOpen || session.IsBusy)
        {
            PostMessage(new { action = "recycleSingleResult", request = request, id = id, success = false, error = "扫描尚未结束，请等扫描完成后再移入回收站。" });
            return;
        }
        if (cleaning || recyclingSingle)
        {
            PostMessage(new { action = "recycleSingleResult", request = request, id = id, success = false, error = "正在执行其他文件操作，请稍候。" });
            return;
        }

        ListRow r;
        if (id < 0 || !idMap.TryGetValue(id, out r) || r == null)
        {
            PostMessage(new { action = "recycleSingleResult", request = request, id = id, success = false, error = "未找到该文件记录，可能已被处理或扫描已更新。" });
            return;
        }
        if (r.IsDirectory)
        {
            PostMessage(new { action = "recycleSingleResult", request = request, id = id, success = false, error = "目录不允许移入回收站，仅支持单个普通文件。" });
            return;
        }
        if (Judgement(r) == "keep" || r.Risk == EvidenceRules.RiskKeep)
        {
            PostMessage(new { action = "recycleSingleResult", request = request, id = id, success = false, error = "受保护的系统或关键文件（建议保留）不允许移入回收站。" });
            return;
        }

        DeleteRequest req = new DeleteRequest
        {
            Path = r.Path,
            WasDirectory = r.IsDirectory,
            BytesAtScan = r.Bytes,
            LastWriteUtcAtScan = r.LastWriteUtc,
            WasReadOnly = r.WasReadOnly,
            PolicyEligible = r.PolicyEligible,
            Risk = r.Risk,
            IdAtScan = r.Id
        };

        string[] rootsSnapshot = currentScanRoots.Count > 0
            ? currentScanRoots.ToArray()
            : (string.IsNullOrEmpty(currentScanRoot) ? new string[0] : new string[] { currentScanRoot });
        long session0 = scanSessionId;
        IRecycleBin customBin = customTestRecycleBin;
        string logPath = GetDeleteLogPath();
        recyclingSingle = true;
        activeFileOpDone.Reset();

        var worker = new Thread(delegate()
        {
            DeleteOutcome outcome = null;
            Exception fail = null;
            try
            {
                outcome = DeleteEngine.ExecuteSingleRecycle(req, rootsSnapshot, customBin, logPath);
            }
            catch (Exception ex)
            {
                fail = ex;
            }
            finally
            {
                try { activeFileOpDone.Set(); } catch (ObjectDisposedException) { }
            }
            DispatchToUiThread(delegate() { FinishSingleRecycle(request, session0, id, r, outcome, fail); }, "recycleSingleFile");
        });
        worker.IsBackground = false;
        worker.SetApartmentState(ApartmentState.STA);
        try
        {
            worker.Start();
        }
        catch (Exception ex)
        {
            recyclingSingle = false;
            try { activeFileOpDone.Set(); } catch (ObjectDisposedException) { }
            WriteDiagnostic("recycleSingleFile", "start", ex);
            PostMessage(new { action = "recycleSingleResult", request = request, id = id, success = false, error = "无法启动移入回收站任务，请重试。" });
        }
    }

    private void DispatchToUiThread(Action action, string opName)
    {
        bool uiGone = (webView == null || webView.IsDisposed) && (hostForm == null || hostForm.IsDisposed);
        if (closingOrDisposed || (uiGone && messageCaptureForTest == null))
        {
            if (opName == "cleanEligible") cleaning = false;
            if (opName == "recycleSingleFile") recyclingSingle = false;
            return;
        }
        try
        {
            if (webView != null && !webView.IsDisposed && webView.IsHandleCreated)
            {
                webView.BeginInvoke(action);
                return;
            }
            if (hostForm != null && !hostForm.IsDisposed && hostForm.IsHandleCreated)
            {
                hostForm.BeginInvoke(action);
                return;
            }
            if (messageCaptureForTest != null)
            {
                action();
                return;
            }
            if (opName == "cleanEligible") cleaning = false;
            if (opName == "recycleSingleFile") recyclingSingle = false;
        }
        catch (Exception ex)
        {
            if (opName == "cleanEligible") cleaning = false;
            if (opName == "recycleSingleFile") recyclingSingle = false;
            WriteDiagnostic(opName, "finish-queue", ex);
        }
    }

    private void FinishSingleRecycle(object request, long session0, int id, ListRow row, DeleteOutcome outcome, Exception fail)
    {
        recyclingSingle = false;
        if (fail != null || outcome == null)
        {
            cleanLockedReason = "上次单文件移入回收站发生异常，文件状态无法确认。请重新扫描核对。";
            WriteDiagnostic("recycleSingleFile", "execute", fail);
            PostMessage(new
            {
                action = "recycleSingleResult",
                request = request,
                id = id,
                success = false,
                locked = true,
                error = "移入回收站时发生异常，无法确认文件状态。请检查回收站并重新扫描。"
            });
            return;
        }

        if (outcome.Status == DeleteStatus.RecycledVerified)
        {
            if (session0 == scanSessionId)
            {
                var removedRows = new List<ListRow>(1) { row };
                if (directorySummary != null)
                {
                    directorySummary.RemoveRows(removedRows);
                }
                allRows.RemoveAll(delegate(ListRow item)
                {
                    return object.ReferenceEquals(item, row) || string.Equals(item.Path, row.Path, StringComparison.OrdinalIgnoreCase);
                });
                idMap.Remove(id);
                rowIds.Remove(row);
                lastDirectorySummaryUpdateCount = allRows.Count;
                RebuildLiveAccumulators();
                detailSnapshot = null;
                snapshotVersion++;
            }
            var catsAfterRecycle = AggregateCategories(false);
            PostMessage(new
            {
                action = "recycleSingleResult",
                request = request,
                id = id,
                success = true,
                name = row.Name,
                bytes = row.Bytes,
                lockedCacheBytes = lockedCacheBytes,
                categories = catsAfterRecycle
            });
            return;
        }

        bool locked = false;
        if (outcome.NeedsUrgentReview)
        {
            cleanLockedReason = "上次单文件移入回收站结果无法确认，请人工核实回收站并重新扫描后再操作。";
            locked = true;
        }
        PostMessage(new
        {
            action = "recycleSingleResult",
            request = request,
            id = id,
            success = false,
            locked = locked,
            error = string.IsNullOrEmpty(outcome.Detail) ? "未能移入系统回收站。" : outcome.Detail
        });
    }

    private void FinishClean(object request, long session0, List<ListRow> picked, List<DeleteOutcome> res, int prunedDirs, Exception fail)
    {
        cleaning = false;
        if (fail != null || res == null)
        {
            cleanLockedReason = "上次清理执行异常，部分文件状态未知。请重新扫描核对后再清理。";
            WriteDiagnostic("cleanEligible", "execute", fail);
            PostMessage(new { action = "cleanResult", request = request, error = "清理执行异常，已停止。请重新扫描后核对。", locked = true });
            return;
        }
        var deleted = new HashSet<string>(res.Where(delegate(DeleteOutcome o) { return o.Status == DeleteStatus.DeletedVerified; }).Select(delegate(DeleteOutcome o) { return o.Path; }), StringComparer.OrdinalIgnoreCase);
        long freed = picked.Where(delegate(ListRow r) { return deleted.Contains(r.Path); }).Sum(delegate(ListRow r) { return r.Bytes; });
        int unknown = res.Count(delegate(DeleteOutcome o) { return o.NeedsUrgentReview; });

        if (session0 == scanSessionId)
        {
            var removedRows = allRows.Where(delegate(ListRow r) { return deleted.Contains(r.Path); }).ToList();
            if (directorySummary != null && removedRows.Count > 0)
            {
                directorySummary.RemoveRows(removedRows);
            }
            allRows.RemoveAll(delegate(ListRow r) { return deleted.Contains(r.Path); });
            for (int i = 0; i < removedRows.Count; i++)
            {
                int rid;
                if (rowIds.TryGetValue(removedRows[i], out rid))
                {
                    rowIds.Remove(removedRows[i]);
                    idMap.Remove(rid);
                }
            }
            lastDirectorySummaryUpdateCount = allRows.Count;
            RebuildLiveAccumulators();
            detailSnapshot = null;
            snapshotVersion++;
        }
        RefreshCurrentDriveSpace();
        if (unknown > 0) cleanLockedReason = "上次清理有 " + unknown + " 个文件结果无法确认。请重新扫描核对后再清理。";
        var problems = res.Where(delegate(DeleteOutcome o) { return !o.IsSuccess; }).Take(50)
            .Select(delegate(DeleteOutcome o) { return new { name = Path.GetFileName(o.Path), status = o.Status.ToString(), kind = o.Kind.ToString(), detail = o.Detail }; }).ToArray();
        var items = res.Take(100)
            .Select(delegate(DeleteOutcome o) { return new { name = Path.GetFileName(o.Path), status = o.Status.ToString(), kind = o.Kind.ToString(), detail = o.Detail }; }).ToArray();
        var catsAfterClean = AggregateCategories(false);
        PostMessage(new
        {
            action = "cleanResult",
            request = request,
            scanSessionId = session0,
            deleted = deleted.Count,
            freedBytes = freed,
            prunedDirs = prunedDirs,
            attempted = res.Count,
            untouched = res.Count(delegate(DeleteOutcome o) { return o.Status == DeleteStatus.RefusedNotDispatched && !ChangedKind(o.Kind); }),
            changed = res.Count(delegate(DeleteOutcome o) { return o.Status == DeleteStatus.RefusedNotDispatched && ChangedKind(o.Kind); }),
            stillPresent = res.Count(delegate(DeleteOutcome o) { return o.Status == DeleteStatus.FailedStillPresent; }),
            unknown = unknown,
            notExecuted = res.Count(delegate(DeleteOutcome o) { return o.Status == DeleteStatus.NotExecutedDueToStop; }),
            stopped = cleanStopRequested,
            locked = cleanLockedReason.Length > 0,
            lockedCacheBytes = lockedCacheBytes,
            driveLabel = currentDriveLabel,
            driveFreeBytes = currentDriveFreeBytes,
            driveTotalBytes = currentDriveTotalBytes,
            problems = problems,
            items = items,
            categories = catsAfterClean
        });
    }

    private static bool ChangedKind(DeleteRefusalKind k)
    {
        return k == DeleteRefusalKind.Vanished || k == DeleteRefusalKind.TypeChanged || k == DeleteRefusalKind.IdentityChanged
            || k == DeleteRefusalKind.WeakIdentityChanged || k == DeleteRefusalKind.RiskChanged;
    }

    private void SendPendingCleanRecords()
    {
        string logPath = GetDeleteLogPath();
        List<DeleteOutcome> pending;
        try { pending = DeleteEngine.Reconcile(logPath); }
        catch (Exception ex) { WriteDiagnostic("reconcile", "read", ex); return; }
        if (pending.Count == 0)
        {
            DeleteLog.RotateIfOversizedAndClean(logPath, DeleteLog.DefaultRotateBytes);
            return;
        }
        var items = pending.Take(20).Select(delegate(DeleteOutcome o)
        {
            return new { name = Path.GetFileName(o.Path), path = o.Path, exists = File.Exists(o.Path) };
        }).ToArray();
        PostMessage(new { action = "pendingClean", count = pending.Count, items = items, log = logPath });
    }

    private volatile object lastPostedPayload;

    private void PostMessage(object payload)
    {
        lastPostedPayload = payload;
        string action = Convert.ToString(payload.GetType().GetProperty("action").GetValue(payload, null));
        bool important = action == "scanComplete" || action == "scanPaused" || action == "snapshotReady"
            || action == "scanStarted" || action == "cleanResult" || action == "recycleSingleResult"
            || action == "pendingClean" || action == "relaunchAdminResult";
        try
        {
            string json;
            lock (outboundSerLock)
            {
                json = outboundSerializer.Serialize(payload);
            }
            Action<string> capture = messageCaptureForTest;
            if (capture != null)
            {
                try { capture(json); } catch { }
            }
            if (webView == null || webView.IsDisposed || !webView.IsHandleCreated)
            {
                if (important && capture == null) WriteDiagnostic(action, "core-unavailable", null);
                return;
            }
            webView.BeginInvoke(new Action(delegate()
            {
                try
                {
                    if (webView.IsDisposed || webView.CoreWebView2 == null) { if (important) WriteDiagnostic(action, "core-unavailable", null); return; }
                    webView.CoreWebView2.PostWebMessageAsJson(json);
                }
                catch (Exception error) { if (important) WriteDiagnostic(action, "post", error); }
            }));
        }
        catch (Exception error) { if (important) WriteDiagnostic(action, "serialize-or-queue", error); }
    }

    public void Dispose()
    {
        closingOrDisposed = true;
        isClosingGracefully = true;
        cleanStopRequested = true;
        progressTimer.Stop();
        progressTimer.Dispose();
        scanOpen = false;
        session.Shutdown(TimeSpan.FromMilliseconds(250));
        if (activeFileOpDone.IsSet)
        {
            try { activeFileOpDone.Dispose(); } catch { }
        }
    }

    internal static string FormatGb(long bytes)
    {
        double gb = Math.Max(0.0, bytes / (1024.0 * 1024.0 * 1024.0));
        return gb.ToString("0.0", CultureInfo.InvariantCulture) + " GB";
    }

    private class CategoryAccumulator
    {
        public string Id;
        public string Name;
        public int OrderIndex;
        public long OkBytes;
        public long ReviewBytes;
        public long KeepBytes;
        public int Count;
    }
}
