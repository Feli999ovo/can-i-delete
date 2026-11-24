using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>
/// 微信 / 企业微信 / QQ 存储目录跨盘自动寻址与「纯缓存 vs 聊天记录/接收原件」双轨隔离器。
/// 纯 C# 5 实现，零 WinForms 依赖；单元测试可通过 SetMockChatRootsForTest 完全沙盒隔离。
/// </summary>
public static class ChatStorageLocator
{
    public sealed class ChatDataFolder
    {
        public string AppName = "";
        public string Kind = "";
        public string Path = "";
    }

    private const int MaxConfigIniBytes = 8 * 1024;
    private const int MaxConfigIniFiles = 16;
    private const int MaxAccountDirsPerRoot = 32;

    private static readonly object mockGate = new object();
    private static ChatDataFolder[] mockChatRoots;
    private static readonly object discoveredGate = new object();
    private static string[] cachedDiscoveredChatRoots = new string[0];

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);
    private static readonly Regex MsgClassicDbNameRegex =
        new Regex(@"^msg[23]\.0\.db(?:-wal|-shm|-journal)?$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);

    /// <summary>仅供沙盒自动化测试注入模拟聊天数据根目录（传空数组可测无聊天目录分支）。</summary>
    public static void SetMockChatRootsForTest(ChatDataFolder[] roots)
    {
        lock (mockGate)
        {
            if (roots == null)
            {
                mockChatRoots = null;
            }
            else
            {
                ChatDataFolder[] copy = new ChatDataFolder[roots.Length];
                for (int i = 0; i < roots.Length; i++)
                {
                    ChatDataFolder src = roots[i];
                    if (src != null)
                    {
                        copy[i] = new ChatDataFolder
                        {
                            AppName = src.AppName ?? "",
                            Kind = src.Kind ?? "",
                            Path = src.Path ?? ""
                        };
                    }
                }
                mockChatRoots = copy;
            }
        }
        CacheRuleRegistry.RefreshRootsCache();
    }

    /// <summary>清除测试注入的模拟聊天根目录并刷新缓存根注册表。</summary>
    public static void ClearMockChatRootsForTest()
    {
        lock (mockGate)
        {
            mockChatRoots = null;
        }
        CacheRuleRegistry.RefreshRootsCache();
    }

    internal static bool HasMockChatRootsForTest
    {
        get { lock (mockGate) { return mockChatRoots != null; } }
    }

    /// <summary>
    /// 纯函数：解析微信 3ebffe94.ini（或 xwechat 配置）中的存储路径文本。
    /// 若内容为 "MyDocument:" 则返回 Path.Combine(myDocumentsPath, "WeChat Files")；
    /// 若为合法本地绝对路径且无重解析点风险，优先取存在的 WeChat Files / xwechat_files 子目录或规范化路径。
    /// </summary>
    public static string ParseWeChatConfigIniContent(string content, string myDocumentsPath)
    {
        if (string.IsNullOrEmpty(content)) return "";

        string cleaned = content.Replace("\uFEFF", "").Replace("\0", "").Trim();
        if (cleaned.Length == 0) return "";

        string[] lines = cleaned.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i].Trim();
            if (line.Length == 0 || line[0] == '#' || line[0] == ';' || line[0] == '[')
                continue;

            int eq = line.IndexOf('=');
            if (eq > 0)
            {
                string rhs = line.Substring(eq + 1).Trim();
                if (rhs.Length > 0) line = rhs;
            }

            line = line.Trim().Trim('"', '\'').Trim();
            if (line.Length == 0) continue;

            if (string.Equals(line, "MyDocument:", StringComparison.OrdinalIgnoreCase)
                || string.Equals(line, "MyDocument:\\", StringComparison.OrdinalIgnoreCase)
                || string.Equals(line, "MyDocument:/", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrEmpty(myDocumentsPath)) return "";
                string docBase = NormalizeLocalAbsolutePath(myDocumentsPath);
                if (docBase.Length == 0 || !PathGuard.IsLocalDrivePath(docBase) || !PathGuard.IsFixedLocalDrive(docBase)) return "";
                if (IsDisallowedSystemOrSelfDir(docBase)) return "";
                if (PathGuard.HasAnyReparseComponent(docBase)) return "";
                string docWc = PathGuard.Canonical(Path.Combine(docBase, "WeChat Files"));
                if (docWc.Length == 0 || IsDisallowedSystemOrSelfDir(docWc)) return "";
                if (PathGuard.HasAnyReparseComponent(docWc)) return "";
                return docWc;
            }

            string baseDir = NormalizeLocalAbsolutePath(line);
            if (baseDir.Length == 0 || !PathGuard.IsLocalDrivePath(baseDir) || !PathGuard.IsFixedLocalDrive(baseDir)) continue;
            if (IsDisallowedSystemOrSelfDir(baseDir)) return "";
            if (PathGuard.HasAnyReparseComponent(baseDir))
                return "";

            string leaf = GetLeafName(baseDir);
            if (string.Equals(leaf, "WeChat Files", StringComparison.OrdinalIgnoreCase)
                || string.Equals(leaf, "xwechat_files", StringComparison.OrdinalIgnoreCase))
            {
                string canonLeaf = PathGuard.Canonical(baseDir);
                if (canonLeaf.Length == 0 || IsDisallowedSystemOrSelfDir(canonLeaf)
                    || IsUserPersonalRootOrAncestor(canonLeaf)
                    || PathGuard.HasAnyReparseComponent(canonLeaf))
                    return "";
                return canonLeaf;
            }

            string wcChild = PathGuard.Canonical(Path.Combine(baseDir, "WeChat Files"));
            string xwChild = PathGuard.Canonical(Path.Combine(baseDir, "xwechat_files"));
            if (wcChild.Length == 0) return "";
            if (IsDisallowedSystemOrSelfDir(wcChild)) return "";

            if (Directory.Exists(wcChild))
            {
                if (PathGuard.HasAnyReparseComponent(wcChild)) return "";
                return wcChild;
            }
            if (xwChild.Length > 0 && Directory.Exists(xwChild))
            {
                if (IsDisallowedSystemOrSelfDir(xwChild) || PathGuard.HasAnyReparseComponent(xwChild)) return "";
                return xwChild;
            }

            if (!IsDriveRootPath(baseDir) && !IsUserPersonalRootOrAncestor(baseDir) && Directory.Exists(baseDir))
            {
                string allUsers = Path.Combine(baseDir, "All Users");
                if (Directory.Exists(allUsers) && !PathGuard.HasAnyReparseComponent(allUsers))
                {
                    if (HasWeChatRootSignature(baseDir, allUsers))
                        return PathGuard.Canonical(baseDir);
                }
            }

            return wcChild;
        }

        return "";
    }

    /// <summary>
    /// 跨盘自动定位本机存在的微信、企业微信、QQ 数据存储根目录。
    /// 若处于单元测试沙盒模式则严格隔离真实用户目录。
    /// </summary>
    public static ChatDataFolder[] DiscoverChatDataFolders()
    {
        ChatDataFolder[] mockSnapshot;
        lock (mockGate)
        {
            mockSnapshot = mockChatRoots;
        }

        if (mockSnapshot != null)
        {
            return NormalizeMockFolders(mockSnapshot);
        }

        if (CacheRoots.HasInjectedForTest)
        {
            return new ChatDataFolder[0];
        }

        List<ChatDataFolder> list = new List<ChatDataFolder>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string roaming = SafeGetSpecialFolder(Environment.SpecialFolder.ApplicationData);
        string myDocs = SafeGetMyDocuments();

        // 1) 读取微信 3ebffe94.ini 与 xwechat\config\*.ini
        if (roaming.Length > 0 && Directory.Exists(roaming) && !PathGuard.HasAnyReparseComponent(roaming))
        {
            string wcIni = Path.Combine(Path.Combine(Path.Combine(Path.Combine(roaming, "Tencent"), "WeChat"), "All Users"), Path.Combine("config", "3ebffe94.ini"));
            TryProbeWeChatIniFile(list, seen, roaming, wcIni, myDocs, "wechat");

            string xwConfigDir = Path.Combine(Path.Combine(Path.Combine(roaming, "Tencent"), "xwechat"), "config");
            if (Directory.Exists(xwConfigDir) && !PathGuard.HasAnyReparseComponent(xwConfigDir))
            {
                try
                {
                    string[] iniFiles = Directory.GetFiles(xwConfigDir, "*.ini");
                    int limit = Math.Min(iniFiles.Length, MaxConfigIniFiles);
                    for (int i = 0; i < limit; i++)
                    {
                        TryProbeWeChatIniFile(list, seen, roaming, iniFiles[i], myDocs, "xwechat");
                    }
                }
                catch { }
            }
        }

        // 2) 检查当前用户 Documents 下的默认存储目录
        if (myDocs.Length > 0 && Directory.Exists(myDocs) && !PathGuard.HasAnyReparseComponent(myDocs))
        {
            TryAddExistingChatFolder(list, seen, myDocs, Path.Combine(myDocs, "WeChat Files"), "微信", "wechat");
            TryAddExistingChatFolder(list, seen, myDocs, Path.Combine(myDocs, "xwechat_files"), "微信", "xwechat");
            TryAddExistingChatFolder(list, seen, myDocs, Path.Combine(myDocs, "WXWork"), "企业微信", "wxwork");
            TryAddExistingChatFolder(list, seen, myDocs, Path.Combine(myDocs, "Tencent Files"), "QQ", "qq");
        }

        // 3) 遍历所有就绪固定磁盘盘符下的常见跨盘迁移目录（仅做顶层存在性探测，< 10ms）
        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); }
        catch { drives = new DriveInfo[0]; }

        for (int i = 0; i < drives.Length; i++)
        {
            DriveInfo drv = drives[i];
            try
            {
                if (drv.DriveType != DriveType.Fixed || !drv.IsReady) continue;
                string root = drv.RootDirectory.FullName;
                if (string.IsNullOrEmpty(root)) continue;

                TryAddExistingChatFolder(list, seen, "", Path.Combine(root, "WeChat Files"), "微信", "wechat");
                TryAddExistingChatFolder(list, seen, "", Path.Combine(root, "xwechat_files"), "微信", "xwechat");
                TryAddExistingChatFolder(list, seen, "", Path.Combine(root, "WXWork"), "企业微信", "wxwork");
                TryAddExistingChatFolder(list, seen, "", Path.Combine(root, "Tencent Files"), "QQ", "qq");

                string wcCustomParent = Path.Combine(root, "WeChat");
                if (Directory.Exists(wcCustomParent) && !PathGuard.HasAnyReparseComponent(wcCustomParent))
                {
                    TryAddExistingChatFolder(list, seen, wcCustomParent, Path.Combine(wcCustomParent, "WeChat Files"), "微信", "wechat");
                    TryAddExistingChatFolder(list, seen, wcCustomParent, Path.Combine(wcCustomParent, "xwechat_files"), "微信", "xwechat");
                }

                string tencentCustomParent = Path.Combine(root, "Tencent");
                if (Directory.Exists(tencentCustomParent) && !PathGuard.HasAnyReparseComponent(tencentCustomParent))
                {
                    TryAddExistingChatFolder(list, seen, tencentCustomParent, Path.Combine(tencentCustomParent, "WeChat Files"), "微信", "wechat");
                    TryAddExistingChatFolder(list, seen, tencentCustomParent, Path.Combine(tencentCustomParent, "xwechat_files"), "微信", "xwechat");
                    TryAddExistingChatFolder(list, seen, tencentCustomParent, Path.Combine(tencentCustomParent, "WXWork"), "企业微信", "wxwork");
                    TryAddExistingChatFolder(list, seen, tencentCustomParent, Path.Combine(tencentCustomParent, "Tencent Files"), "QQ", "qq");
                }

                string qqCustomParent = Path.Combine(root, "QQ");
                if (Directory.Exists(qqCustomParent) && !PathGuard.HasAnyReparseComponent(qqCustomParent))
                {
                    TryAddExistingChatFolder(list, seen, qqCustomParent, Path.Combine(qqCustomParent, "Tencent Files"), "QQ", "qq");
                }
            }
            catch { }
        }

        ChatDataFolder[] discovered = list.ToArray();
        string[] paths = new string[discovered.Length];
        for (int i = 0; i < discovered.Length; i++)
        {
            paths[i] = discovered[i].Path;
        }
        lock (discoveredGate)
        {
            cachedDiscoveredChatRoots = paths;
        }
        return discovered;
    }

    /// <summary>
    /// 仅供 TMP-CHATCACHE 挂载 100% 不含聊天记录与聊天接收原件的纯缓存子目录。
    /// 严格跳过重解析点与任何受保护用户内容路径。
    /// </summary>
    public static CacheRoots.Root[] DiscoverPureChatCacheRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        bool isMockOrInjected = HasMockChatRootsForTest || CacheRoots.HasInjectedForTest;
        ChatDataFolder[] dataFolders = DiscoverChatDataFolders();

        for (int i = 0; i < dataFolders.Length; i++)
        {
            ChatDataFolder f = dataFolders[i];
            if (f == null || string.IsNullOrEmpty(f.Path)) continue;
            string root = PathGuard.Canonical(f.Path);
            if (root.Length == 0 || !Directory.Exists(root) || PathGuard.HasAnyReparseComponent(root))
                continue;

            string kind = (f.Kind ?? "").ToLowerInvariant();
            if (kind == "wechat" || kind == "xwechat")
            {
                ProbeWeChatPureCacheSubdirs(list, seen, root);
            }
            else if (kind == "wxwork")
            {
                ProbeWxWorkPureCacheSubdirs(list, seen, root);
            }
            else if (kind == "qq")
            {
                ProbeQqPureCacheSubdirs(list, seen, root);
            }
            else
            {
                ProbeWeChatPureCacheSubdirs(list, seen, root);
                ProbeWxWorkPureCacheSubdirs(list, seen, root);
                ProbeQqPureCacheSubdirs(list, seen, root);
            }
        }

        // 非测试沙盒模式下补充 AppData 下微信/QQ 的纯组件与内置网页缓存目录
        if (!isMockOrInjected)
        {
            string roaming = SafeGetSpecialFolder(Environment.SpecialFolder.ApplicationData);
            string local = SafeGetSpecialFolder(Environment.SpecialFolder.LocalApplicationData);

            if (roaming.Length > 0 && Directory.Exists(roaming) && !PathGuard.HasAnyReparseComponent(roaming))
            {
                AddPureCacheDirIfValid(list, seen, roaming,
                    Path.Combine(Path.Combine(roaming, "Tencent"), Path.Combine("WeChat", "XPlugin")),
                    "微信 XPlugin 组件缓存目录（排除可执行模块与用户数据）");
            }

            if (local.Length > 0 && Directory.Exists(local) && !PathGuard.HasAnyReparseComponent(local))
            {
                AddPureCacheDirIfValid(list, seen, local,
                    Path.Combine(Path.Combine(local, "Tencent"), Path.Combine("WeChat", "xweb")),
                    "微信内置浏览器 xweb 缓存目录");
                AddPureCacheDirIfValid(list, seen, local,
                    Path.Combine(Path.Combine(local, "Tencent"), Path.Combine("QQ", "webkit_cache")),
                    "QQ 内置网页 webkit_cache 纯缓存目录");
            }
        }

        return list.ToArray();
    }

    /// <summary>
    /// 是否命中微信/企业微信/QQ 聊天核心数据库（Msg / nt_msg / nt_db / db_storage / nt_data 下的
    /// .db / .db-wal / .db-shm / .db-journal / .idx，以及 QQ 经典 Msg2.0.db / Msg3.0.db）。
    /// 供 KEEP-CHATDB 无条件保留保护。纯线性分段匹配，零正则回溯风险。
    /// </summary>
    public static bool IsChatDatabasePath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath)) return false;

        string normalized = NormalizePathForClassification(fullPath);
        string[] segs = SplitPathSegments(normalized);
        if (segs.Length < 2) return false;

        string fileName = segs[segs.Length - 1];
        if (!IsChatDbFileName(fileName)) return false;

        int chatRootIdx = FindStandardChatRootSegmentIndex(segs);
        bool underKnownChatRoot = chatRootIdx >= 0 || IsInsideMockOrDiscoveredChatRoots(normalized);
        if (!underKnownChatRoot) return false;

        if (IsClassicQqMsgDbName(fileName))
            return true;

        int startSearch = chatRootIdx >= 0 ? chatRootIdx + 1 : 0;
        for (int i = startSearch; i < segs.Length - 1; i++)
        {
            if (IsChatDbDirSegment(segs[i]))
                return true;
        }
        return false;
    }

    /// <summary>
    /// 三重硬拦截：路径是否属于聊天核心数据库或用户接收/收藏/表情/聊天图片视频文件。
    /// 注意：\FileStorage\Sns\Cache\ 为朋友圈纯缓存，不在此黑名单内。纯线性分段匹配。
    /// </summary>
    public static bool IsChatProtectedUserContent(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath)) return false;
        if (IsChatDatabasePath(fullPath)) return true;

        string normalized = NormalizePathForClassification(fullPath);
        string[] segs = SplitPathSegments(normalized);
        if (segs.Length == 0) return false;

        int chatRootIdx = FindStandardChatRootSegmentIndex(segs);
        bool underKnownChatRoot = chatRootIdx >= 0 || IsInsideMockOrDiscoveredChatRoots(normalized);
        bool underWxWork = HasSegment(segs, "wxwork");

        for (int i = 0; i < segs.Length; i++)
        {
            string s = segs[i];
            if (EqualsSeg(s, "nt_msg") || EqualsSeg(s, "nt_db") || EqualsSeg(s, "db_storage") || EqualsSeg(s, "nt_data")
                || EqualsSeg(s, "filerecv") || EqualsSeg(s, "mobilefile") || EqualsSeg(s, "customemotion") || EqualsSeg(s, "fav"))
            {
                return true;
            }

            if (underKnownChatRoot && (chatRootIdx < 0 || i > chatRootIdx) && EqualsSeg(s, "msg"))
            {
                return true;
            }

            if (i + 1 < segs.Length)
            {
                string next = segs[i + 1];
                if (EqualsSeg(s, "filestorage")
                    && (EqualsSeg(next, "file") || EqualsSeg(next, "msgattach") || EqualsSeg(next, "video")
                        || EqualsSeg(next, "image") || EqualsSeg(next, "customemotion") || EqualsSeg(next, "fav")))
                {
                    return true;
                }
                if (EqualsSeg(s, "image")
                    && (EqualsSeg(next, "group") || EqualsSeg(next, "group2") || EqualsSeg(next, "c2c")))
                {
                    return true;
                }
                if (underWxWork && EqualsSeg(s, "cache")
                    && (EqualsSeg(next, "file") || EqualsSeg(next, "video")))
                {
                    return true;
                }
            }
        }
        return false;
    }

    /// <summary>
    /// 路径是否为微信/企业微信/QQ 聊天接收的独立用户文件（FileStorage\File|Video|MsgAttach、FileRecv、MobileFile），
    /// 排除聊天数据库文件。供「大文件 -> 聊天接收文件」专向筛选使用。纯线性分段匹配。
    /// </summary>
    public static bool IsChatReceivedUserFile(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath)) return false;
        char last = fullPath[fullPath.Length - 1];
        if (last == '\\' || last == '/') return false;
        if (IsChatDatabasePath(fullPath)) return false;

        string normalized = NormalizePathForClassification(fullPath);
        string[] segs = SplitPathSegments(normalized);
        if (segs.Length < 3) return false;

        int chatRootIdx = FindStandardChatRootSegmentIndex(segs);
        bool underChatRoot = chatRootIdx >= 0 || IsInsideMockOrDiscoveredChatRoots(normalized);
        if (!underChatRoot) return false;

        bool underWxWork = HasSegment(segs, "wxwork");
        int lastDirIdx = segs.Length - 2; // 最后一段是文件名，至少有一个父目录

        for (int i = 0; i <= lastDirIdx; i++)
        {
            string s = segs[i];
            if (EqualsSeg(s, "filerecv") || EqualsSeg(s, "mobilefile"))
                return true;

            if (i + 1 <= lastDirIdx)
            {
                string next = segs[i + 1];
                if (EqualsSeg(s, "filestorage")
                    && (EqualsSeg(next, "file") || EqualsSeg(next, "video") || EqualsSeg(next, "msgattach")))
                {
                    return true;
                }
                if (underWxWork && EqualsSeg(s, "cache")
                    && (EqualsSeg(next, "file") || EqualsSeg(next, "video")))
                {
                    return true;
                }
            }
        }
        return false;
    }

    // ==================== 内部辅助实现 ====================

    private static string NormalizePathForClassification(string raw)
    {
        string canon = PathGuard.CanonicalFast(raw);
        if (canon.Length > 0) return canon;
        string s = raw.Trim();
        if (s.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
            return s;
        if (s.StartsWith("\\\\?\\", StringComparison.Ordinal) || s.StartsWith("\\\\.\\", StringComparison.Ordinal))
            s = s.Substring(4);
        return s;
    }

    private static string[] SplitPathSegments(string path)
    {
        if (string.IsNullOrEmpty(path)) return new string[0];
        return path.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
    }

    private static bool EqualsSeg(string a, string b)
    {
        return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasSegment(string[] segs, string target)
    {
        for (int i = 0; i < segs.Length; i++)
        {
            if (EqualsSeg(segs[i], target)) return true;
        }
        return false;
    }

    private static int FindStandardChatRootSegmentIndex(string[] segs)
    {
        for (int i = 0; i < segs.Length; i++)
        {
            string s = segs[i];
            if (EqualsSeg(s, "wechat files")
                || EqualsSeg(s, "xwechat_files")
                || EqualsSeg(s, "wxwork")
                || EqualsSeg(s, "tencent files"))
            {
                return i;
            }
        }
        return -1;
    }

    private static bool IsChatDbDirSegment(string seg)
    {
        return EqualsSeg(seg, "msg")
            || EqualsSeg(seg, "nt_msg")
            || EqualsSeg(seg, "nt_db")
            || EqualsSeg(seg, "db_storage")
            || EqualsSeg(seg, "nt_data");
    }

    private static bool IsChatDbFileName(string fileName)
    {
        if (string.IsNullOrEmpty(fileName)) return false;
        return fileName.EndsWith(".db", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".db-wal", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".db-shm", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".db-journal", StringComparison.OrdinalIgnoreCase)
            || fileName.EndsWith(".idx", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsClassicQqMsgDbName(string fileName)
    {
        if (string.IsNullOrEmpty(fileName)) return false;
        try { return MsgClassicDbNameRegex.IsMatch(fileName); }
        catch { return true; }
    }

    private static bool IsInsideMockOrDiscoveredChatRoots(string fullPath)
    {
        ChatDataFolder[] snap;
        lock (mockGate)
        {
            snap = mockChatRoots;
        }
        if (snap != null)
        {
            for (int i = 0; i < snap.Length; i++)
            {
                ChatDataFolder f = snap[i];
                if (f == null || string.IsNullOrEmpty(f.Path)) continue;
                if (PathGuard.IsInside(f.Path, fullPath))
                    return true;
            }
            return false;
        }

        string[] realSnap;
        lock (discoveredGate)
        {
            realSnap = cachedDiscoveredChatRoots;
        }
        if (realSnap == null || realSnap.Length == 0) return false;
        for (int i = 0; i < realSnap.Length; i++)
        {
            string r = realSnap[i];
            if (string.IsNullOrEmpty(r)) continue;
            if (PathGuard.IsInside(r, fullPath))
                return true;
        }
        return false;
    }

    private static bool IsDisallowedSystemOrSelfDir(string canon)
    {
        if (string.IsNullOrEmpty(canon)) return true;
        string winDir = SafeGetSpecialFolder(Environment.SpecialFolder.Windows);
        if (winDir.Length > 0 && PathGuard.IsInside(winDir, canon)) return true;
        string pf = SafeGetSpecialFolder(Environment.SpecialFolder.ProgramFiles);
        if (pf.Length > 0 && PathGuard.IsInside(pf, canon)) return true;
        string pf86 = SafeGetSpecialFolder(Environment.SpecialFolder.ProgramFilesX86);
        if (pf86.Length > 0 && PathGuard.IsInside(pf86, canon)) return true;
        string progData = SafeGetSpecialFolder(Environment.SpecialFolder.CommonApplicationData);
        if (progData.Length > 0 && PathGuard.IsInside(progData, canon)) return true;

        try
        {
            string baseDir = PathGuard.Canonical(AppDomain.CurrentDomain.BaseDirectory);
            if (baseDir.Length > 0 && (PathGuard.IsInside(baseDir, canon) || PathGuard.IsInside(canon, baseDir)))
                return true;
        }
        catch { }

        try
        {
            string envWv = Environment.GetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER");
            if (!string.IsNullOrEmpty(envWv))
            {
                string canonWv = PathGuard.Canonical(envWv);
                if (canonWv.Length > 0 && (PathGuard.IsInside(canonWv, canon) || PathGuard.IsInside(canon, canonWv)))
                    return true;
            }
        }
        catch { }

        return false;
    }

    private static bool IsUserPersonalRootOrAncestor(string path)
    {
        string canon = PathGuard.Canonical(path);
        if (canon.Length == 0) return true;
        Environment.SpecialFolder[] protectedFolders = new Environment.SpecialFolder[]
        {
            Environment.SpecialFolder.UserProfile,
            Environment.SpecialFolder.Desktop,
            Environment.SpecialFolder.MyDocuments,
            Environment.SpecialFolder.MyPictures,
            Environment.SpecialFolder.MyVideos
        };
        for (int i = 0; i < protectedFolders.Length; i++)
        {
            string sp = SafeGetSpecialFolder(protectedFolders[i]);
            if (sp.Length > 0 && PathGuard.IsInside(canon, sp))
                return true;
        }
        return false;
    }

    private static bool HasWeChatRootSignature(string baseDir, string allUsersDir)
    {
        try
        {
            string configData = Path.Combine(Path.Combine(allUsersDir, "config"), "config.data");
            if (File.Exists(configData) && !PathGuard.HasAnyReparseComponent(configData))
                return true;

            DirectoryInfo[] children = new DirectoryInfo(baseDir).GetDirectories();
            int limit = Math.Min(children.Length, MaxAccountDirsPerRoot);
            for (int i = 0; i < limit; i++)
            {
                DirectoryInfo ch = children[i];
                if ((ch.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (!ch.Name.StartsWith("wxid_", StringComparison.OrdinalIgnoreCase)) continue;
                string msgDir = Path.Combine(ch.FullName, "Msg");
                string fsDir = Path.Combine(ch.FullName, "FileStorage");
                if ((Directory.Exists(msgDir) && !PathGuard.HasAnyReparseComponent(msgDir))
                    || (Directory.Exists(fsDir) && !PathGuard.HasAnyReparseComponent(fsDir)))
                {
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    private static ChatDataFolder[] NormalizeMockFolders(ChatDataFolder[] raw)
    {
        List<ChatDataFolder> list = new List<ChatDataFolder>(raw.Length);
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < raw.Length; i++)
        {
            ChatDataFolder item = raw[i];
            if (item == null || string.IsNullOrEmpty(item.Path)) continue;
            string canon = PathGuard.Canonical(item.Path);
            if (canon.Length == 0) continue;
            try
            {
                if (!Directory.Exists(canon)) continue;
                if (PathGuard.HasAnyReparseComponent(canon)) continue;
            }
            catch { continue; }

            if (!seen.Add(canon)) continue;

            string kind = string.IsNullOrEmpty(item.Kind) ? InferKindFromPath(canon) : item.Kind;
            string appName = string.IsNullOrEmpty(item.AppName) ? InferAppNameFromKind(kind) : item.AppName;
            list.Add(new ChatDataFolder
            {
                AppName = appName,
                Kind = kind,
                Path = canon
            });
        }
        return list.ToArray();
    }

    private static string InferKindFromPath(string path)
    {
        string leaf = GetLeafName(path);
        if (string.Equals(leaf, "xwechat_files", StringComparison.OrdinalIgnoreCase)) return "xwechat";
        if (string.Equals(leaf, "WXWork", StringComparison.OrdinalIgnoreCase)) return "wxwork";
        if (string.Equals(leaf, "Tencent Files", StringComparison.OrdinalIgnoreCase)) return "qq";
        if (path.IndexOf("xwechat", StringComparison.OrdinalIgnoreCase) >= 0) return "xwechat";
        if (path.IndexOf("wxwork", StringComparison.OrdinalIgnoreCase) >= 0) return "wxwork";
        if (path.IndexOf("tencent files", StringComparison.OrdinalIgnoreCase) >= 0
            || path.IndexOf("\\qq", StringComparison.OrdinalIgnoreCase) >= 0) return "qq";
        return "wechat";
    }

    private static string InferAppNameFromKind(string kind)
    {
        string k = (kind ?? "").ToLowerInvariant();
        if (k == "wxwork") return "企业微信";
        if (k == "qq") return "QQ";
        return "微信";
    }

    private static void TryProbeWeChatIniFile(
        List<ChatDataFolder> list,
        HashSet<string> seen,
        string roamingAnchor,
        string iniPath,
        string myDocs,
        string defaultKind)
    {
        try
        {
            if (string.IsNullOrEmpty(iniPath)) return;
            if (!string.IsNullOrEmpty(roamingAnchor) && PathGuard.HasReparseAncestor(roamingAnchor, iniPath))
                return;
            if (PathGuard.HasAnyReparseComponent(iniPath))
                return;

            FileInfo fi = new FileInfo(iniPath);
            if (!fi.Exists) return;
            if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) return;
            if (fi.Length <= 0 || fi.Length > MaxConfigIniBytes) return;

            string text = File.ReadAllText(iniPath, Encoding.UTF8);
            string parsed = ParseWeChatConfigIniContent(text, myDocs);
            if (parsed.Length == 0) return;

            string leaf = GetLeafName(parsed);
            string kind = string.Equals(leaf, "xwechat_files", StringComparison.OrdinalIgnoreCase)
                ? "xwechat"
                : defaultKind;
            TryAddExistingChatFolder(list, seen, "", parsed, "微信", kind);

            // 若同一自定义父目录下同时存在 xwechat_files，一并探测加入
            string parent = "";
            try { parent = Path.GetDirectoryName(parsed) ?? ""; } catch { parent = ""; }
            if (parent.Length > 0 && !PathGuard.HasAnyReparseComponent(parent))
            {
                TryAddExistingChatFolder(list, seen, "", Path.Combine(parent, "xwechat_files"), "微信", "xwechat");
                TryAddExistingChatFolder(list, seen, "", Path.Combine(parent, "WeChat Files"), "微信", "wechat");
            }
        }
        catch { }
    }

    private static void TryAddExistingChatFolder(
        List<ChatDataFolder> list,
        HashSet<string> seen,
        string anchor,
        string candidateDir,
        string appName,
        string kind)
    {
        try
        {
            if (string.IsNullOrEmpty(candidateDir) || !Directory.Exists(candidateDir)) return;
            string canon = PathGuard.Canonical(candidateDir);
            if (canon.Length == 0 || IsDriveRootPath(canon)) return;
            if (!PathGuard.IsFixedLocalDrive(canon)) return;
            if (IsDisallowedSystemOrSelfDir(canon)) return;
            if (!seen.Contains(canon))
            {
                if (!Directory.Exists(canon)) return;
                if (PathGuard.HasAnyReparseComponent(canon)) return;
                if (!string.IsNullOrEmpty(anchor) && PathGuard.IsInside(anchor, canon)
                    && PathGuard.HasReparseAncestor(anchor, canon))
                    return;
                seen.Add(canon);
                list.Add(new ChatDataFolder
                {
                    AppName = appName,
                    Kind = kind,
                    Path = canon
                });
            }
        }
        catch { }
    }

    private static void ProbeWeChatPureCacheSubdirs(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string root)
    {
        AddPureCacheDirIfValid(list, seen, root,
            Path.Combine(Path.Combine(root, "All Users"), "Applet"),
            "微信小程序公共运行包缓存目录（不含聊天记录与接收文件）");
        AddPureCacheDirIfValid(list, seen, root,
            Path.Combine(root, "WMPFRuntime"),
            "微信小程序运行时缓存目录（不含聊天记录与接收文件）");
        AddPureCacheDirIfValid(list, seen, root,
            Path.Combine(Path.Combine(root, "All Users"), "WMPFRuntime"),
            "微信小程序运行时缓存目录（不含聊天记录与接收文件）");

        DirectoryInfo[] accounts;
        try { accounts = new DirectoryInfo(root).GetDirectories(); }
        catch { return; }

        int limit = Math.Min(accounts.Length, MaxAccountDirsPerRoot);
        for (int i = 0; i < limit; i++)
        {
            DirectoryInfo acc = accounts[i];
            try
            {
                if ((acc.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                string accName = acc.Name;
                if (string.Equals(accName, "All Users", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(accName, "WMPFRuntime", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(accName, "Applet", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string accFull = acc.FullName;
                AddPureCacheDirIfValid(list, seen, root,
                    Path.Combine(Path.Combine(accFull, "FileStorage"), Path.Combine("Sns", "Cache")),
                    "微信朋友圈图片与视频纯缓存目录（不含聊天原件）");
                AddPureCacheDirIfValid(list, seen, root,
                    Path.Combine(accFull, Path.Combine("Sns", "Cache")),
                    "微信朋友圈纯缓存目录（不含聊天原件）");
                AddPureCacheDirIfValid(list, seen, root,
                    Path.Combine(accFull, "Applet"),
                    "微信账号小程序包纯缓存目录");
                AddPureCacheDirIfValid(list, seen, root,
                    Path.Combine(Path.Combine(accFull, "radium"), Path.Combine("web", "cache")),
                    "微信内置网页纯缓存目录");
            }
            catch { }
        }
    }

    private static void ProbeWxWorkPureCacheSubdirs(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string root)
    {
        AddPureCacheDirIfValid(list, seen, root,
            Path.Combine(root, "CefCache"),
            "企业微信内置网页 CefCache 纯缓存目录");

        DirectoryInfo[] level1;
        try { level1 = new DirectoryInfo(root).GetDirectories(); }
        catch { return; }

        int limit1 = Math.Min(level1.Length, MaxAccountDirsPerRoot);
        for (int i = 0; i < limit1; i++)
        {
            DirectoryInfo d1 = level1[i];
            try
            {
                if ((d1.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                string n1 = d1.Name;
                if (string.Equals(n1, "CefCache", StringComparison.OrdinalIgnoreCase)) continue;

                AddPureCacheDirIfValid(list, seen, root,
                    Path.Combine(d1.FullName, Path.Combine("Cache", "Sns")),
                    "企业微信朋友圈纯缓存目录（不含办公文件与聊天记录）");

                if (string.Equals(n1, "Data", StringComparison.OrdinalIgnoreCase))
                {
                    DirectoryInfo[] level2;
                    try { level2 = d1.GetDirectories(); }
                    catch { continue; }
                    int limit2 = Math.Min(level2.Length, MaxAccountDirsPerRoot);
                    for (int k = 0; k < limit2; k++)
                    {
                        DirectoryInfo d2 = level2[k];
                        try
                        {
                            if ((d2.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                            AddPureCacheDirIfValid(list, seen, root,
                                Path.Combine(d2.FullName, Path.Combine("Cache", "Sns")),
                                "企业微信朋友圈纯缓存目录（不含办公文件与聊天记录）");
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
    }

    private static void ProbeQqPureCacheSubdirs(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string root)
    {
        // QQ 严禁挂载 <Account>\Image\Group2、FileRecv、MobileFile、nt_db；仅挂载纯缓存子目录
        AddPureCacheDirIfValid(list, seen, root,
            Path.Combine(Path.Combine(root, "nt_qq"), Path.Combine("global", "nt_temp")),
            "QQ NT 全局纯临时缓存目录（不含聊天记录与群文件）");
        AddPureCacheDirIfValid(list, seen, root,
            Path.Combine(root, "webkit_cache"),
            "QQ 内置网页 webkit_cache 纯缓存目录");
    }

    private static void AddPureCacheDirIfValid(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string baseAnchor,
        string candidateDir,
        string why)
    {
        try
        {
            if (string.IsNullOrEmpty(candidateDir) || !Directory.Exists(candidateDir)) return;
            string canon = PathGuard.Canonical(candidateDir);
            if (canon.Length == 0 || IsDriveRootPath(canon)) return;
            if (IsDisallowedSystemOrSelfDir(canon)) return;
            if (IsChatProtectedUserContent(canon)) return;
            if (!seen.Add(canon)) return;
            if (!Directory.Exists(canon)) return;
            if (PathGuard.HasAnyReparseComponent(canon)) return;
            if (!string.IsNullOrEmpty(baseAnchor) && PathGuard.IsInside(baseAnchor, canon)
                && PathGuard.HasReparseAncestor(baseAnchor, canon))
            {
                return;
            }
            list.Add(new CacheRoots.Root
            {
                RuleId = "TMP-CHATCACHE",
                Directory = canon,
                Why = why
            });
        }
        catch { }
    }

    private static string SafeGetSpecialFolder(Environment.SpecialFolder folder)
    {
        try
        {
            string p = Environment.GetFolderPath(folder);
            return PathGuard.Canonical(p);
        }
        catch { return ""; }
    }

    private static string SafeGetMyDocuments()
    {
        string docs = SafeGetSpecialFolder(Environment.SpecialFolder.MyDocuments);
        if (docs.Length > 0) return docs;
        string profile = SafeGetSpecialFolder(Environment.SpecialFolder.UserProfile);
        if (profile.Length > 0) return PathGuard.Canonical(Path.Combine(profile, "Documents"));
        return "";
    }

    private static string NormalizeLocalAbsolutePath(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return "";
        string s = raw.Trim();
        if (s.Length < 2) return "";
        char d = s[0];
        if (!((d >= 'A' && d <= 'Z') || (d >= 'a' && d <= 'z')) || s[1] != ':')
            return "";
        if (s.Length == 2)
            s = s + "\\";
        else if (s[2] != '\\' && s[2] != '/')
            return "";

        for (int i = 2; i < s.Length; i++)
        {
            char c = s[i];
            if (c < 32 || c == ':' || c == '"' || c == '*' || c == '?' || c == '<' || c == '>' || c == '|')
                return "";
        }

        try
        {
            string full = Path.GetFullPath(s);
            if (!PathGuard.IsLocalDrivePath(full)) return "";
            string root = Path.GetPathRoot(full);
            if (!string.IsNullOrEmpty(root) && string.Equals(full, root, StringComparison.OrdinalIgnoreCase))
                return root;
            return full.TrimEnd('\\', '/');
        }
        catch { return ""; }
    }

    private static bool IsDriveRootPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string s = path.TrimEnd('\\', '/');
        return s.Length == 2 && s[1] == ':';
    }

    private static string GetLeafName(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        string trimmed = path.TrimEnd('\\', '/');
        if (trimmed.Length <= 2 && trimmed.EndsWith(":", StringComparison.Ordinal)) return "";
        try { return Path.GetFileName(trimmed) ?? ""; }
        catch { return ""; }
    }
}
