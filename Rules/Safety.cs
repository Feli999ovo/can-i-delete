using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

// =====================================================================
// 安全核心（P0）：路径守卫、受控缓存根（委托 CacheRuleRegistry）、占用探测、有界目录遍历、安全策略。
//
// 本文件不得依赖 WinForms —— 它必须能被控制台测试程序直接引用。
//
// 设计原则（Fail-Closed）：
//   * 无法证明可删 → 不授权；任何探测异常一律按“不安全”处理。
//   * 风险分级（Risk，用于展示）与删除授权（PolicyEligible，用于执行）分离。
// =====================================================================

/// <summary>文件占用状态。Unknown 表示无法探测，必须按“不安全”处理。</summary>
public enum LockState { Free, Occupied, Unknown }

/// <summary>扫描到的一个条目（文件或目录）的快照身份。</summary>
public sealed class ScanItem
{
    public string Path = "";
    public string Name = "";
    public bool IsDirectory;
    public long Bytes;
    public int Days;
    public DateTime LastWriteUtc;
    public bool IsReparse;
    public bool SizeComplete = true;   // 目录体积是否完整统计
    public bool HasChildren;           // 目录是否非空
    public FileIdentity Id;            // 强身份（卷号 + 文件索引）
}

/// <summary>
/// 目标的强身份：卷序列号 + 文件索引（NTFS File ID）。
/// Ok=false 表示无法取得身份 —— 此时一律按“不可信”处理。
/// </summary>
public struct FileIdentity
{
    public bool Ok;
    public uint VolumeSerial;
    public uint IndexHigh;
    public uint IndexLow;

    public ulong Index { get { return ((ulong)IndexHigh << 32) | IndexLow; } }

    public bool SameAs(FileIdentity other)
    {
        return Ok && other.Ok
            && VolumeSerial == other.VolumeSerial
            && IndexHigh == other.IndexHigh
            && IndexLow == other.IndexLow;
    }

    public override string ToString()
    {
        return Ok ? (VolumeSerial.ToString("X8") + ":" + Index.ToString("X16")) : "unknown";
    }
}

/// <summary>用 Win32 句柄取文件身份（对目录同样有效，需 FILE_FLAG_BACKUP_SEMANTICS）。</summary>
public static class FileIdentityProbe
{
    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint SHARE_ALL = 0x01 | 0x02 | 0x04;   // read | write | delete
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_ATTR_DIRECTORY = 0x00000010;
    private const uint FILE_ATTR_REPARSE_POINT = 0x00000400;
    private const int ERROR_SHARING_VIOLATION = 32;
    private const int ERROR_LOCK_VIOLATION = 33;

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
    private static extern bool ReadFile(IntPtr handle, byte[] buffer, uint bytesToRead, out uint bytesRead, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>
    /// 单次打开句柄同时完成：独占占用探测（FileShare.None）+ 强身份捕获（卷号/索引）+ 前 64 字节结构头预读。
    /// 被其他进程占用时直接通过 Win32 错误码返回 Occupied（零异常开销）；异常边界回退至 LockProbe.Probe。
    /// </summary>
    internal static LockState ProbeLockAndPrefetch(string path, FileAttributes knownAttrs,
                                                   out FileIdentity id, out byte[] head, out long fileLen)
    {
        id = new FileIdentity();
        head = null;
        fileLen = 0;
        if (string.IsNullOrEmpty(path)) return LockState.Unknown;

        uint access = (((knownAttrs & FileAttributes.ReadOnly) != 0)
            ? GENERIC_READ
            : (GENERIC_READ | GENERIC_WRITE)) | FILE_READ_ATTRIBUTES;

        IntPtr h = IntPtr.Zero;
        try
        {
            h = CreateFileW(path, access, 0, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (h == new IntPtr(-1) || h == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                h = IntPtr.Zero;
                if (err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION)
                    return LockState.Occupied;
                return LockProbe.Probe(path);
            }

            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info))
                return LockState.Free;

            if ((info.FileAttributes & FILE_ATTR_DIRECTORY) != 0)
                return LockState.Free;
            if ((info.FileAttributes & FILE_ATTR_REPARSE_POINT) != 0)
                return LockState.Unknown;

            id.Ok = true;
            id.VolumeSerial = info.VolumeSerialNumber;
            id.IndexHigh = info.FileIndexHigh;
            id.IndexLow = info.FileIndexLow;
            fileLen = ((long)info.FileSizeHigh << 32) | info.FileSizeLow;

            if (fileLen <= 0)
            {
                head = new byte[0];
            }
            else
            {
                int want = (int)Math.Min(fileLen, (long)ContentVerifier.StructuredHeadBytes);
                byte[] buf = new byte[want];
                uint got;
                if (ReadFile(h, buf, (uint)want, out got, IntPtr.Zero))
                {
                    if ((int)got == want)
                    {
                        head = buf;
                    }
                    else
                    {
                        byte[] trimmed = new byte[(int)got];
                        Array.Copy(buf, trimmed, (int)got);
                        head = trimmed;
                    }
                }
            }
            return LockState.Free;
        }
        catch
        {
            id = new FileIdentity();
            head = null;
            return LockProbe.Probe(path);
        }
        finally
        {
            if (h != IntPtr.Zero && h != new IntPtr(-1))
            {
                try { CloseHandle(h); } catch { }
            }
        }
    }

    public static FileIdentity Capture(string path)
    {
        FileIdentity id = new FileIdentity();
        IntPtr h = IntPtr.Zero;
        try
        {
            h = CreateFileW(path, FILE_READ_ATTRIBUTES, SHARE_ALL, IntPtr.Zero,
                            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (h == new IntPtr(-1) || h == IntPtr.Zero) return id;

            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) return id;

            id.Ok = true;
            id.VolumeSerial = info.VolumeSerialNumber;
            id.IndexHigh = info.FileIndexHigh;
            id.IndexLow = info.FileIndexLow;
            return id;
        }
        catch { return id; }
        finally
        {
            if (h != IntPtr.Zero && h != new IntPtr(-1))
            {
                try { CloseHandle(h); } catch { }
            }
        }
    }
}

/// <summary>路径守卫：规范化、范围判定、重解析点识别。</summary>
public static class PathGuard
{
    private sealed class ControlledRootEntry
    {
        public string Canon;
        public string PrefixWithSep;
    }

    private const long ControlledRootsTtlTicks = 5L * TimeSpan.TicksPerSecond;
    private static readonly object controlledGate = new object();
    private static string[] cachedControlledRaw;
    private static ControlledRootEntry[] cachedControlledEntries;
    private static long cachedControlledAtUtcTicks;

    internal static void InvalidateControlledRootsCache()
    {
        lock (controlledGate)
        {
            cachedControlledRaw = null;
            cachedControlledEntries = null;
            cachedControlledAtUtcTicks = 0;
        }
    }

    public static string Canonical(string path)
    {
        if (path == null) return "";
        try { return Path.GetFullPath(path.Trim()).TrimEnd('\\', '/'); }
        catch { return ""; }
    }

    /// <summary>对已规范化的本地绝对路径零分配返回原字符串；存在相对段或非常规字符时回退 Canonical。</summary>
    internal static string CanonicalFast(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        if (IsAlreadyCanonicalDrivePath(path)) return path;
        return Canonical(path);
    }

    private static bool IsAlreadyCanonicalDrivePath(string path)
    {
        int len = path.Length;
        if (len < 4) return false;
        char d = path[0];
        if (!((d >= 'A' && d <= 'Z') || (d >= 'a' && d <= 'z'))) return false;
        if (path[1] != ':' || path[2] != '\\') return false;

        char last = path[len - 1];
        if (last == '\\' || last == '/' || last == ' ' || last == '.') return false;

        char prev = '\\';
        for (int i = 3; i < len; i++)
        {
            char c = path[i];
            if (c < 32 || c == '/') return false;
            if (c == '\\')
            {
                if (prev == '\\' || prev == ' ' || prev == '.') return false;
            }
            else if (c == '.' && prev == '\\')
            {
                if (i + 1 == len || path[i + 1] == '\\') return false;
                if (path[i + 1] == '.' && (i + 2 == len || path[i + 2] == '\\')) return false;
            }
            prev = c;
        }
        return true;
    }

    /// <summary>path 是否等于 root 或位于 root 之内（词法判定，已规范化）。</summary>
    public static bool IsInside(string root, string path)
    {
        string r = CanonicalFast(root);
        string p = CanonicalFast(path);
        if (r.Length == 0 || p.Length == 0) return false;
        if (p.Length < r.Length) return false;
        if (p.Length == r.Length) return string.Equals(r, p, StringComparison.OrdinalIgnoreCase);
        return p[r.Length] == Path.DirectorySeparatorChar
            && p.StartsWith(r, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>是否为符号链接 / 目录联接点 / 其他重解析点。探测失败一律返回 true（保守）。</summary>
    public static bool IsReparsePoint(string path)
    {
        try
        {
            FileAttributes a = File.GetAttributes(path);
            return (a & FileAttributes.ReparsePoint) != 0;
        }
        catch { return true; }
    }

    /// <summary>是否为本地固定磁盘（回收站通常只对固定磁盘有效）。</summary>
    public static bool IsFixedLocalDrive(string path)
    {
        try
        {
            string p = CanonicalFast(path);
            if (p.Length == 0) return false;
            string root = Path.GetPathRoot(p);
            if (root == null || root.Length == 0) return false;
            return new DriveInfo(root).DriveType == DriveType.Fixed;
        }
        catch { return false; }
    }

    /// <summary>受控临时根：只有位于这些根之内，文件才有资格被判定为“安全”。</summary>
    public static string[] ControlledRoots()
    {
        ControlledRootEntry[] entries;
        string[] raw = GetControlledCached(out entries);
        string[] copy = new string[raw.Length];
        Array.Copy(raw, copy, raw.Length);
        return copy;
    }

    private static string[] GetControlledCached(out ControlledRootEntry[] entries)
    {
        long nowTicks = DateTime.UtcNow.Ticks;
        lock (controlledGate)
        {
            if (cachedControlledRaw != null && cachedControlledEntries != null
                && nowTicks >= cachedControlledAtUtcTicks
                && (nowTicks - cachedControlledAtUtcTicks) < ControlledRootsTtlTicks)
            {
                entries = cachedControlledEntries;
                return cachedControlledRaw;
            }
        }

        List<string> roots = new List<string>();
        AddRoot(roots, Path.GetTempPath());
        try
        {
            AddRoot(roots, Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
        }
        catch { }

        string[] builtRaw = roots.ToArray();
        ControlledRootEntry[] builtEntries = new ControlledRootEntry[builtRaw.Length];
        for (int i = 0; i < builtRaw.Length; i++)
        {
            builtEntries[i] = new ControlledRootEntry
            {
                Canon = builtRaw[i],
                PrefixWithSep = builtRaw[i] + Path.DirectorySeparatorChar
            };
        }

        lock (controlledGate)
        {
            cachedControlledRaw = builtRaw;
            cachedControlledEntries = builtEntries;
            cachedControlledAtUtcTicks = DateTime.UtcNow.Ticks;
            entries = cachedControlledEntries;
            return cachedControlledRaw;
        }
    }

    private static void AddRoot(List<string> roots, string p)
    {
        string c = Canonical(p);
        if (c.Length > 0 && !roots.Contains(c)) roots.Add(c);
    }

    /// <summary>是否位于受控临时根之内（纯内存前缀匹配）。</summary>
    public static bool IsInControlledRoot(string path)
    {
        string p = CanonicalFast(path);
        if (p.Length == 0) return false;
        ControlledRootEntry[] entries;
        GetControlledCached(out entries);
        for (int i = 0; i < entries.Length; i++)
        {
            ControlledRootEntry e = entries[i];
            if (p.Length > e.Canon.Length)
            {
                if (p.StartsWith(e.PrefixWithSep, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else if (p.Length == e.Canon.Length)
            {
                if (string.Equals(p, e.Canon, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    /// <summary>
    /// 目标的祖先链中是否夹带了重解析点（符号链接 / 目录联接点 / 卷挂载点）。
    /// 注意：不检查 root 自身（那是用户明确选定的扫描范围），仅检查 root 之下、目标之上的层级。
    /// 任何探测失败一律返回 true（保守拒绝）。
    /// </summary>
    public static bool HasReparseAncestor(string root, string path)
    {
        string r = Canonical(root);
        string p = Canonical(path);
        if (r.Length == 0 || p.Length == 0) return true;
        if (!IsInside(r, p)) return true;
        if (string.Equals(r, p, StringComparison.OrdinalIgnoreCase)) return false;

        string rest = p.Substring(r.Length).TrimStart('\\', '/');
        string[] parts = rest.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        string cur = r;
        for (int i = 0; i < parts.Length - 1; i++)
        {
            cur = cur + Path.DirectorySeparatorChar + parts[i];
            try
            {
                if ((File.GetAttributes(cur) & FileAttributes.ReparsePoint) != 0) return true;
            }
            catch { return true; }
        }
        return false;
    }
}

/// <summary>
/// 可授权的已知缓存根：默认受控根目录统一由 CacheRuleRegistry 动态探测提供，
/// 同时保留测试沙盒注入机制（InjectForTest / ClearInjectedForTest）。
/// </summary>
public static class CacheRoots
{
    public sealed class Root
    {
        public string RuleId;
        public string Directory;     // 绝对路径（不存在则该规则自然不生效）
        public string Why;           // 为什么这个位置算「可追溯」
    }

    private static readonly string[] BrowserProtectedItems = new string[]
    {
        "Cookies", "Cookies-journal", "Cookies-wal", "Cookies-shm",
        "Login Data", "Login Data-journal", "Login Data For Account", "Login Data For Account-journal",
        "Web Data", "Web Data-journal",
        "History", "History-journal",
        "Bookmarks", "Bookmarks.bak", "Bookmarks.msbak",
        "Preferences", "Secure Preferences",
        "Local Storage", "Session Storage", "Sessions",
        "IndexedDB", "Sync Data", "Extensions",
        "Local Extension Settings", "Sync Extension Settings",
        "Favicons", "Favicons-journal", "Top Sites", "Shortcuts", "Visited Links", "Trust Tokens",
        // Mozilla Firefox / Gecko 受保护凭据、历史书签与会话数据库
        "cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm", "cookies.sqlite-journal",
        "places.sqlite", "places.sqlite-wal", "places.sqlite-shm", "places.sqlite-journal",
        "key4.db", "key3.db", "logins.json", "logins-backup.json",
        "cert9.db", "cert8.db",
        "formhistory.sqlite", "webappsstore.sqlite", "favicons.sqlite",
        "permissions.sqlite", "content-prefs.sqlite", "sessionCheckpoints.json"
    };

    private static readonly string[] AppProtectedItems = new string[]
    {
        "storage.json", "settings.json", "keybindings.json", "argv.json",
        "workspaceStorage", "globalStorage", "snippets"
    };

    private sealed class CompiledRoot
    {
        public string RuleId;
        public string CanonDir;
        public string PrefixWithSep;
        public string Why;
        public bool Injected;
        public int OrderIndex;
    }

    private static readonly object cacheGate = new object();
    private static readonly List<Root> injected = new List<Root>();
    private static int injectedGeneration = 1;
    private static CompiledRoot[] compiledRootsCache;
    private static int compiledExistingGen = -1;
    private static int compiledInjectedGen = -1;

    internal static void InvalidateCompiledCache()
    {
        lock (cacheGate)
        {
            compiledRootsCache = null;
            compiledExistingGen = -1;
            compiledInjectedGen = -1;
        }
    }

    /// <summary>列出本机存在的已知缓存根（直接委托给 CacheRuleRegistry 单一注册表，带短 TTL 缓存）。</summary>
    public static Root[] Existing()
    {
        return CacheRuleRegistry.DiscoverExistingRoots();
    }

    /// <summary>硬性排除浏览器登录凭据、历史、书签、会话、存储与扩展目录/文件。</summary>
    public static bool IsBrowserProtectedPath(string name, string fullPath)
    {
        if (!string.IsNullOrEmpty(name) && MatchesBrowserProtectedSegment(name)) return true;
        if (string.IsNullOrEmpty(fullPath)) return false;
        int start = 0;
        int len = fullPath.Length;
        for (int i = 0; i <= len; i++)
        {
            if (i == len || fullPath[i] == '\\' || fullPath[i] == '/')
            {
                int segLen = i - start;
                if (segLen > 0 && MatchesBrowserProtectedRange(fullPath, start, segLen))
                    return true;
                start = i + 1;
            }
        }
        return false;
    }

    private static bool MatchesBrowserProtectedSegment(string seg)
    {
        if (seg.StartsWith("sessionstore", StringComparison.OrdinalIgnoreCase))
            return true;
        for (int i = 0; i < BrowserProtectedItems.Length; i++)
        {
            if (string.Equals(seg, BrowserProtectedItems[i], StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool MatchesBrowserProtectedRange(string fullPath, int start, int segLen)
    {
        if (segLen >= 12
            && string.Compare(fullPath, start, "sessionstore", 0, 12, StringComparison.OrdinalIgnoreCase) == 0)
            return true;
        for (int i = 0; i < BrowserProtectedItems.Length; i++)
        {
            string item = BrowserProtectedItems[i];
            if (item.Length == segLen
                && string.Compare(fullPath, start, item, 0, segLen, StringComparison.OrdinalIgnoreCase) == 0)
                return true;
        }
        return false;
    }

    /// <summary>硬性排除桌面软件与编辑器（VS Code / Cursor / Electron / WebView2）的配置、登录态与本地数据库。</summary>
    public static bool IsAppProtectedPath(string name, string fullPath)
    {
        if (IsBrowserProtectedPath(name, fullPath)) return true;
        if (!string.IsNullOrEmpty(name) && MatchesAppProtectedSegment(name)) return true;
        if (string.IsNullOrEmpty(fullPath)) return false;

        int start = 0;
        int len = fullPath.Length;
        int prevStart = -1;
        int prevLen = 0;
        for (int i = 0; i <= len; i++)
        {
            if (i == len || fullPath[i] == '\\' || fullPath[i] == '/')
            {
                int segLen = i - start;
                if (segLen > 0)
                {
                    if (MatchesAppProtectedRange(fullPath, start, segLen))
                        return true;
                    if (segLen == 4
                        && string.Compare(fullPath, start, "User", 0, 4, StringComparison.OrdinalIgnoreCase) == 0
                        && prevStart >= 0
                        && ((prevLen == 4 && string.Compare(fullPath, prevStart, "Code", 0, 4, StringComparison.OrdinalIgnoreCase) == 0)
                            || (prevLen == 6 && string.Compare(fullPath, prevStart, "Cursor", 0, 6, StringComparison.OrdinalIgnoreCase) == 0)))
                    {
                        return true;
                    }
                    prevStart = start;
                    prevLen = segLen;
                }
                start = i + 1;
            }
        }
        return false;
    }

    private static bool MatchesAppProtectedSegment(string seg)
    {
        if (seg.StartsWith("state.vscdb", StringComparison.OrdinalIgnoreCase))
            return true;
        for (int i = 0; i < AppProtectedItems.Length; i++)
        {
            if (string.Equals(seg, AppProtectedItems[i], StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool MatchesAppProtectedRange(string fullPath, int start, int segLen)
    {
        if (segLen >= 11
            && string.Compare(fullPath, start, "state.vscdb", 0, 11, StringComparison.OrdinalIgnoreCase) == 0)
            return true;
        for (int i = 0; i < AppProtectedItems.Length; i++)
        {
            string item = AppProtectedItems[i];
            if (item.Length == segLen
                && string.Compare(fullPath, start, item, 0, segLen, StringComparison.OrdinalIgnoreCase) == 0)
                return true;
        }
        return false;
    }

    /// <summary>仅供自动化测试注入的额外沙盒缓存根。生产路径从不调用。</summary>
    public static void InjectForTest(string ruleId, string dir)
    {
        string canon = PathGuard.Canonical(dir);
        lock (cacheGate)
        {
            injected.Add(new Root
            {
                RuleId = ruleId,
                Directory = canon,
                Why = "（测试注入）"
            });
            injectedGeneration++;
            compiledRootsCache = null;
        }
        ContentVerifier.ClearDirectoryVerifyCache();
    }

    public static void ClearInjectedForTest()
    {
        lock (cacheGate)
        {
            injected.Clear();
            injectedGeneration++;
            compiledRootsCache = null;
        }
        CacheRuleRegistry.ClearQuickScanRootsForTest();
    }

    internal static bool HasInjectedForTest
    {
        get { lock (cacheGate) { return injected.Count > 0; } }
    }

    internal static string[] GetInjectedDirectoriesForTest()
    {
        lock (cacheGate)
        {
            List<string> dirs = new List<string>(injected.Count);
            for (int i = 0; i < injected.Count; i++)
            {
                dirs.Add(injected[i].Directory);
            }
            return dirs.ToArray();
        }
    }

    // 只读列出同一份既有范围；扫描排序用，不增加根也不更改授权条件。
    public static string[] ScanDirectories()
    {
        CompiledRoot[] all = GetCompiledRoots();
        string[] paths = new string[all.Length];
        for (int i = 0; i < all.Length; i++)
        {
            paths[i] = all[i].CanonDir;
        }
        return paths;
    }

    private static CompiledRoot[] GetCompiledRoots()
    {
        int existingGen;
        Root[] existing = CacheRuleRegistry.DiscoverExistingRootsCached(out existingGen);

        lock (cacheGate)
        {
            if (compiledRootsCache != null
                && compiledExistingGen == existingGen
                && compiledInjectedGen == injectedGeneration)
            {
                return compiledRootsCache;
            }

            List<CompiledRoot> list = new List<CompiledRoot>(injected.Count + existing.Length);
            for (int i = 0; i < injected.Count; i++)
            {
                Root r = injected[i];
                string canon = PathGuard.CanonicalFast(r.Directory);
                if (canon.Length == 0) continue;
                list.Add(new CompiledRoot
                {
                    RuleId = r.RuleId,
                    CanonDir = canon,
                    PrefixWithSep = canon + Path.DirectorySeparatorChar,
                    Why = r.Why,
                    Injected = true,
                    OrderIndex = i
                });
            }
            for (int i = 0; i < existing.Length; i++)
            {
                Root r = existing[i];
                if (r == null) continue;
                string canon = PathGuard.CanonicalFast(r.Directory);
                if (canon.Length == 0) continue;
                list.Add(new CompiledRoot
                {
                    RuleId = r.RuleId,
                    CanonDir = canon,
                    PrefixWithSep = canon + Path.DirectorySeparatorChar,
                    Why = r.Why,
                    Injected = false,
                    OrderIndex = i
                });
            }

            CompiledRoot[] sorted = list.ToArray();
            Array.Sort(sorted, delegate(CompiledRoot a, CompiledRoot b)
            {
                int lenCmp = b.CanonDir.Length.CompareTo(a.CanonDir.Length);
                if (lenCmp != 0) return lenCmp;
                if (a.Injected != b.Injected) return a.Injected ? -1 : 1;
                return b.OrderIndex.CompareTo(a.OrderIndex);
            });

            compiledRootsCache = sorted;
            compiledExistingGen = existingGen;
            compiledInjectedGen = injectedGeneration;
            return sorted;
        }
    }

    /// <summary>
    /// path 是否位于某个已知缓存根内；按预构建降序规范化数组做纯内存前缀匹配（零磁盘 I/O），
    /// 最长路径（最具体子目录）优先匹配，同长度时测试注入根优先。
    /// </summary>
    public static bool Match(string path, out string ruleId, out string why)
    {
        ruleId = "";
        why = "";
        string p = PathGuard.CanonicalFast(path);
        if (p.Length == 0) return false;

        CompiledRoot[] roots = GetCompiledRoots();
        for (int i = 0; i < roots.Length; i++)
        {
            CompiledRoot r = roots[i];
            int rLen = r.CanonDir.Length;
            if (p.Length > rLen)
            {
                if (p.StartsWith(r.PrefixWithSep, StringComparison.OrdinalIgnoreCase))
                {
                    ruleId = r.RuleId;
                    why = r.Why;
                    return true;
                }
            }
            else if (p.Length == rLen)
            {
                if (string.Equals(p, r.CanonDir, StringComparison.OrdinalIgnoreCase))
                {
                    ruleId = r.RuleId;
                    why = r.Why;
                    return true;
                }
            }
        }
        return false;
    }
}

/// <summary>占用探测：唯一实现入口，任何异常都不得被解释为“未占用”。</summary>
public static class LockProbe
{
    public static LockState Probe(string path)
    {
        FileAttributes a;
        try { a = File.GetAttributes(path); }
        catch (FileNotFoundException) { return LockState.Unknown; }
        catch (DirectoryNotFoundException) { return LockState.Unknown; }
        catch { return LockState.Unknown; }

        if ((a & FileAttributes.Directory) != 0) return LockState.Free;   // 目录不做独占探测

        FileAccess access = ((a & FileAttributes.ReadOnly) != 0) ? FileAccess.Read : FileAccess.ReadWrite;
        try
        {
            using (FileStream fs = File.Open(path, FileMode.Open, access, FileShare.None)) { }
            return LockState.Free;
        }
        catch (IOException) { return LockState.Occupied; }
        catch (UnauthorizedAccessException) { return LockState.Unknown; }
        catch { return LockState.Unknown; }
    }
}

/// <summary>体积统计提前停止 / 结果不完整的原因码。</summary>
public enum SizeStopReason
{
    None = 0,
    FileLimit,
    DirLimit,
    ReparsePoint,
    OutOfRoot,
    Unreadable,
    AttributeError,
    SizeError,
    Deleted,
    Cancelled
}

/// <summary>体积统计的结果与不完整原因。</summary>
public sealed class SizeScanResult
{
    public long Bytes;
    public bool Complete = true;
    /// <summary>目录内是否存在任何条目。探测失败或未完成一律保守为 true（按“非空”处理）。</summary>
    public bool HasChildren;
    public SizeStopReason FirstReason = SizeStopReason.None;
    public readonly List<SizeStopReason> Reasons = new List<SizeStopReason>();
    public long FileStats;
    public long DirVisits;

    private readonly List<string> notes = new List<string>();

    public void AddReason(SizeStopReason r, string note)
    {
        if (FirstReason == SizeStopReason.None) FirstReason = r;
        if (!Reasons.Contains(r)) Reasons.Add(r);
        if (note != null && note.Length > 0 && notes.Count < 8 && !notes.Contains(note)) notes.Add(note);
    }

    public string Explain()
    {
        if (Complete) return "完整";
        if (notes.Count == 0) return "不完整";
        return "不完整：" + String.Join("；", notes.ToArray());
    }
}

/// <summary>体积统计的资源上限。</summary>
public sealed class SizeLimits
{
    public int MaxFiles = DirScan.DefaultMaxFiles;
    public int MaxDirs = DirScan.MaxDirsVisited;

    public SizeLimits() { }
    public SizeLimits(int maxFiles, int maxDirs) { MaxFiles = maxFiles; MaxDirs = maxDirs; }
}

/// <summary>有界目录遍历：不跟随重解析点、不越出根目录、有文件数上限。</summary>
public static class DirScan
{
    public const int DefaultMaxFiles = 5000;
    public const int MaxDirsVisited = 20000;

    public static long SizeBounded(string root, out bool complete)
    {
        return SizeBounded(root, out complete, DefaultMaxFiles);
    }

    public static long SizeBounded(string root, out bool complete, int maxFiles)
    {
        complete = true;
        long total = 0;
        int seen = 0, visited = 0;
        string canonRoot = PathGuard.Canonical(root);
        if (canonRoot.Length == 0) { complete = false; return 0; }
        if (maxFiles <= 0) maxFiles = DefaultMaxFiles;

        Stack<string> stack = new Stack<string>();
        stack.Push(canonRoot);
        while (stack.Count > 0)
        {
            if (++visited > MaxDirsVisited) { complete = false; break; }
            string cur = stack.Pop();

            string[] dirs;
            try { dirs = Directory.GetDirectories(cur); }
            catch { complete = false; continue; }
            foreach (string d in dirs)
            {
                if (PathGuard.IsReparsePoint(d)) { complete = false; continue; }
                if (!PathGuard.IsInside(canonRoot, d)) { complete = false; continue; }
                stack.Push(d);
            }

            string[] files;
            try { files = Directory.GetFiles(cur); }
            catch { complete = false; continue; }
            foreach (string f in files)
            {
                try { total += new FileInfo(f).Length; }
                catch { complete = false; }
                if (++seen >= maxFiles) { complete = false; return total; }
            }
        }
        return total;
    }

    public static long SizeBounded(string root, out SizeScanResult result)
    {
        return SizeBounded(root, out result, null, null);
    }

    public static long SizeBounded(string root, out SizeScanResult result,
                                   SizeLimits limits, Func<bool> cancelled)
    {
        result = new SizeScanResult();
        if (limits == null) limits = new SizeLimits();

        string canonRoot = PathGuard.Canonical(root);
        if (canonRoot.Length == 0)
        {
            result.Complete = false;
            result.HasChildren = true;
            result.AddReason(SizeStopReason.AttributeError, "路径无法解析");
            return 0;
        }
        if (!Directory.Exists(canonRoot))
        {
            result.Complete = false;
            result.HasChildren = true;
            result.AddReason(SizeStopReason.Deleted, "目录不存在或已被移除");
            return 0;
        }

        long total = 0;
        Stack<string> stack = new Stack<string>();
        stack.Push(canonRoot);

        while (stack.Count > 0)
        {
            if (cancelled != null && cancelled())
            {
                result.Complete = false;
                result.AddReason(SizeStopReason.Cancelled, "扫描已取消，体积为部分统计");
                break;
            }
            if (result.DirVisits >= limits.MaxDirs)
            {
                result.Complete = false;
                result.AddReason(SizeStopReason.DirLimit, "达到目录访问上限 " + limits.MaxDirs);
                break;
            }
            result.DirVisits++;
            string cur = stack.Pop();

            try
            {
                foreach (string d in Directory.EnumerateDirectories(cur))
                {
                    result.HasChildren = true;
                    if (PathGuard.IsReparsePoint(d))
                    {
                        result.Complete = false;
                        result.AddReason(SizeStopReason.ReparsePoint, "跳过符号链接 / 目录联接点（不跟随）");
                        continue;
                    }
                    if (!PathGuard.IsInside(canonRoot, d))
                    {
                        result.Complete = false;
                        result.AddReason(SizeStopReason.OutOfRoot, "跳过越出扫描根的路径");
                        continue;
                    }
                    stack.Push(d);
                }
            }
            catch
            {
                result.Complete = false;
                result.HasChildren = true;
                result.AddReason(SizeStopReason.Unreadable, "子目录枚举中断（权限不足或已被移除）");
                continue;
            }

            try
            {
                foreach (string f in Directory.EnumerateFiles(cur))
                {
                    if (cancelled != null && cancelled())
                    {
                        result.Complete = false;
                        result.AddReason(SizeStopReason.Cancelled, "扫描已取消，体积为部分统计");
                        result.Bytes = total;
                        if (!result.HasChildren) result.HasChildren = true;
                        return total;
                    }
                    result.HasChildren = true;
                    if (result.FileStats >= limits.MaxFiles)
                    {
                        result.Complete = false;
                        result.AddReason(SizeStopReason.FileLimit, "达到文件统计上限 " + limits.MaxFiles);
                        result.Bytes = total;
                        return total;
                    }
                    result.FileStats++;
                    try { total += new FileInfo(f).Length; }
                    catch
                    {
                        result.Complete = false;
                        result.AddReason(SizeStopReason.SizeError, "读取文件大小失败");
                    }
                }
            }
            catch
            {
                result.Complete = false;
                result.HasChildren = true;
                result.AddReason(SizeStopReason.Unreadable, "文件枚举中断（权限不足或已被移除）");
            }
        }

        if (!result.Complete && !result.HasChildren) result.HasChildren = true;
        result.Bytes = total;
        return total;
    }

    public static bool IsEmptyDirectory(string dir)
    {
        try { return Directory.GetFileSystemEntries(dir).Length == 0; }
        catch { return false; }
    }
}

/// <summary>安全策略：由规则层结论 + 受控范围 + 实时状态 得出最终分级与删除授权。</summary>
public static class SafetyPolicy
{
    public const bool RecursiveDirectoryDeleteEnabled = false;

    public static Evidence Decide(ScanItem it, LockState ls)
    {
        return DecideCore(it, ls, null, null, null, null, 0);
    }

    public static Evidence Decide(ScanItem it, LockState ls, HashBudget hash, Func<bool> cancelled)
    {
        return DecideCore(it, ls, hash, cancelled, null, null, 0);
    }

    /// <summary>接收已计算好的规则层初判结论，避免扫描热路径对同一文件重复执行正则与根目录匹配。</summary>
    public static Evidence Decide(ScanItem it, LockState ls, HashBudget hash, Func<bool> cancelled, Evidence preEvaluated)
    {
        return DecideCore(it, ls, hash, cancelled, preEvaluated, null, 0);
    }

    internal static Evidence DecideWithPrefetch(ScanItem it, LockState ls, HashBudget hash, Func<bool> cancelled,
                                                Evidence preEvaluated, byte[] prefetchedHead, long prefetchedLen)
    {
        return DecideCore(it, ls, hash, cancelled, preEvaluated, prefetchedHead, prefetchedLen);
    }

    private static Evidence CloneEvidence(Evidence src)
    {
        return new Evidence
        {
            Risk = src.Risk,
            App = src.App,
            Reason = src.Reason,
            Consequence = src.Consequence,
            Locked = src.Locked,
            LockedCleanableCache = src.LockedCleanableCache,
            PolicyEligible = src.PolicyEligible,
            DenyReason = src.DenyReason,
            RuleId = src.RuleId,
            Scope = src.Scope,
            Excludes = src.Excludes,
            RootBound = src.RootBound,
            MinAgeHours = src.MinAgeHours,
            EvidenceKind = src.EvidenceKind,
            EvidenceDetail = src.EvidenceDetail,
            ContentVerified = src.ContentVerified
        };
    }

    private static Evidence DecideCore(ScanItem it, LockState ls, HashBudget hash, Func<bool> cancelled,
                                       Evidence preEvaluated, byte[] prefetchedHead, long prefetchedLen)
    {
        Evidence ev = preEvaluated != null
            ? CloneEvidence(preEvaluated)
            : EvidenceRules.Evaluate(it.Name, it.Path, it.Days);

        // ---- 目录：一律不授权 ----
        if (it.IsDirectory)
        {
            if (ev.Risk == EvidenceRules.RiskSafe)
            {
                ev.Risk = EvidenceRules.RiskReview;
                ev.Reason = "目录内容尚未逐项核验。" + ev.Reason;
            }
            ev.PolicyEligible = false;
            ev.DenyReason = "非空目录禁止递归删除；当前版本未实现目录内容的逐项核验。";
            if (!it.HasChildren) ev.DenyReason = "目录删除未启用（需逐项核验后再开放）。";
            if (!RecursiveDirectoryDeleteEnabled)
                ev.DenyReason += "[开关：RecursiveDirectoryDeleteEnabled=false]";
            return ev;
        }

        // ---- 重解析点：保守拒绝 ----
        if (it.IsReparse)
        {
            ev.Risk = EvidenceRules.RiskKeep;
            ev.Reason = "这是一个符号链接 / 目录联接点，指向的目标不在本次删除范围内";
            ev.Consequence = "拒绝处理。删除链接本身风险不可控，请手动确认。";
            ev.PolicyEligible = false;
            ev.DenyReason = "重解析点（符号链接 / 联接点）一律拒绝";
            return ev;
        }

        // ---- 聊天核心数据库硬保护兜底（即使调用方传入预评估快照也不得绕过）----
        if (ChatStorageLocator.IsChatDatabasePath(it.Path) && ev.Risk != EvidenceRules.RiskKeep)
        {
            ev.RuleId = "KEEP-CHATDB";
            ev.Risk = EvidenceRules.RiskKeep;
            ev.App = "微信 / QQ 聊天数据库";
            ev.Reason = "聊天记录核心数据库";
            ev.Consequence = "严禁删除。删除会导致本地聊天记录永久丢失。";
        }

        // ---- 范围 + 内容证据 ----
        bool inTemp = PathGuard.IsInControlledRoot(it.Path);
        string cacheRule, cacheWhy;
        bool inCacheRoot = CacheRoots.Match(it.Path, out cacheRule, out cacheWhy);
        CacheRuleSpec spec = CacheRuleRegistry.Find(ev.RuleId);

        int effMinHours = ev.MinAgeHours > 0 ? ev.MinAgeHours : (spec != null ? spec.MinAgeHours : 0);

        if (ev.Risk == EvidenceRules.RiskSafe)
        {
            int minDays = effMinHours > 0 ? Math.Max(1, effMinHours / 24) : 0;

            if (ChatStorageLocator.IsChatProtectedUserContent(it.Path))
                EvidenceRules.Downgrade(ev, "命中微信/QQ聊天记录或接收原件保护目录，严禁自动清理");
            else if (ev.RuleId == "TMP-WINUPDATE" && IsWinUpdateDataStorePath(it.Path))
                EvidenceRules.Downgrade(ev, "位于 Windows Update DataStore 数据库目录，严禁自动清理");
            else if (spec == null)
                EvidenceRules.Downgrade(ev, "该规则未在注册表中登记，不允许授权");
            else if (ev.EvidenceKind == EvidenceKind.None)
                EvidenceRules.Downgrade(ev, "该规则没有声明内容级证据，不允许授权");
            else if (ev.RootBound && !inCacheRoot)
                EvidenceRules.Downgrade(ev, "该规则要求位于指定的已知缓存根内（临时目录位置不算证据）");
            else if (inCacheRoot && cacheRule != ev.RuleId)
                EvidenceRules.Downgrade(ev, "所在缓存根只对规则 " + cacheRule + " 生效，本文件命中 " + ev.RuleId);
            else if (!inTemp && !inCacheRoot)
                EvidenceRules.Downgrade(ev, "位置既不在受控临时目录，也不在任何已知缓存根内");
            else if (effMinHours > 0 && (it.Days < minDays || !IsFileOlderThanHours(it.Path, effMinHours)))
                EvidenceRules.Downgrade(ev,
                    (ev.RuleId == "TMP-WINUPDATE" ? "系统更新缓存修改时间未满 " : "系统临时文件修改时间未满 ")
                    + effMinHours + " 小时，暂不纳入清理");
            else if (ls == LockState.Free)
            {
                ContentEvidence ce = prefetchedHead != null
                    ? ContentVerifier.VerifyPrefetched(ev.RuleId, it.Path, prefetchedHead, prefetchedLen, hash, cancelled)
                    : ContentVerifier.Verify(ev.RuleId, it.Path, hash, cancelled);
                ev.EvidenceKind = ce.Kind;
                ev.EvidenceDetail = ce.Detail;
                ev.ContentVerified = ce.Verified;
                if (!ev.ContentVerified)
                    EvidenceRules.Downgrade(ev, "内容校验未通过：" + ev.EvidenceDetail);
            }
            else
            {
                ev.ContentVerified = false;
                ev.EvidenceDetail = (ls == LockState.Occupied)
                    ? "文件正被占用，跳过内容读取"
                    : "无法确认占用状态，跳过内容读取";
            }
        }

        // ---- 占用状态：异常按不安全处理 ----
        if (ls == LockState.Occupied)
        {
            ev.Locked = true;
            if (spec != null && inCacheRoot && string.Equals(cacheRule, ev.RuleId, StringComparison.Ordinal))
            {
                int minDaysForLock = effMinHours > 0 ? Math.Max(1, effMinHours / 24) : 0;
                if (minDaysForLock == 0 || it.Days >= minDaysForLock)
                    ev.LockedCleanableCache = true;
            }
            ev.Risk = EvidenceRules.RiskKeep;
            ev.Reason = "正被某个程序占用中";
            ev.Consequence = "暂时不要删除。请先关闭相关软件后再试。";
        }
        else if (ls == LockState.Unknown)
        {
            ev.Risk = EvidenceRules.RiskKeep;
            ev.Reason = "无法确认该文件是否正被使用（读取属性或占用探测失败）";
            ev.Consequence = "拒绝处理。无法确认状态的文件不予删除。";
        }

        // ---- 授权：完全由分级决定（不变量）----
        ev.PolicyEligible = (ev.Risk == EvidenceRules.RiskSafe) && ev.ContentVerified;
        if (ev.PolicyEligible)
        {
            ev.DenyReason = "";
            return ev;
        }

        if (ls == LockState.Occupied) ev.DenyReason = "正被某个程序占用";
        else if (ls == LockState.Unknown) ev.DenyReason = "无法确认该文件是否正被使用";
        else if (ev.Risk == EvidenceRules.RiskKeep) ev.DenyReason = "风险等级为「保留」，不允许删除";
        else if (effMinHours > 0 && ev.Reason.IndexOf("小时", StringComparison.Ordinal) >= 0)
            ev.DenyReason = "临时文件修改时间未满 " + effMinHours + " 小时，暂不纳入清理";
        else ev.DenyReason = "证据不足，未获删除授权（仅靠位置/名称/扩展名/时间不足以符合清理规则）";
        return ev;
    }

    private static bool IsWinUpdateDataStorePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        return path.IndexOf("\\DataStore\\", StringComparison.OrdinalIgnoreCase) >= 0
            || path.IndexOf("/DataStore/", StringComparison.OrdinalIgnoreCase) >= 0
            || path.EndsWith("\\DataStore", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("/DataStore", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsFileOlderThanHours(string path, int hours)
    {
        try
        {
            FileInfo fi = new FileInfo(path);
            if (!fi.Exists) return false;
            return (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalHours >= (double)hours;
        }
        catch { return false; }
    }
}
