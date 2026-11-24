using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

// =====================================================================
// 内容级正向证据与独占句柄流复核：
// 规则分发由 CacheRuleRegistry 单一注册表驱动；无法做内容校验的规则一律不予授权。
// =====================================================================

/// <summary>内容证据的强度。</summary>
public enum EvidenceKind
{
    None,                 // 无内容级证据 → 不得授权
    MagicHeader,          // 文件头魔数与结构校验通过
    ContentAddressedHash  // 结构与内容哈希双重校验通过
}

/// <summary>
/// 内容校验的字节预算。预算不足 ⇒ 校验不得通过（fail-closed）。线程安全。
/// </summary>
public sealed class HashBudget
{
    public static readonly HashBudget Unlimited = new HashBudget(-1);

    private readonly object gate = new object();
    private readonly long total;
    private long remaining;
    private bool denied;

    public HashBudget(long bytes)
    {
        total = bytes < 0 ? -1 : bytes;
        remaining = total;
    }

    public long Total { get { return total; } }
    public long Remaining { get { lock (gate) { return remaining; } } }
    public bool IsUnlimited { get { return total < 0; } }
    public bool Exhausted { get { if (IsUnlimited) return false; lock (gate) { return denied || remaining < 8; } } }
    public bool Denied { get { lock (gate) { return denied; } } }

    public bool TryConsume(long bytes)
    {
        if (IsUnlimited) return true;
        if (bytes < 0) return false;
        lock (gate)
        {
            if (remaining < bytes) { denied = true; return false; }
            remaining -= bytes;
            return true;
        }
    }
}

/// <summary>一次内容校验的结果。</summary>
public sealed class ContentEvidence
{
    public bool Verified;
    public EvidenceKind Kind = EvidenceKind.None;
    public string Detail = "未做内容校验";

    public override string ToString()
    {
        return (Verified ? "verified:" : "unverified:") + Kind + " " + Detail;
    }
}

/// <summary>内容校验器：按 CacheRuleRegistry 注册的委托分发扫描期与句柄复核期校验。</summary>
public static class ContentVerifier
{
    /// <summary>超过该体积不做哈希校验（避免扫描卡死），直接判为证据不足。</summary>
    public const long MaxHashBytes = 64L * 1024 * 1024;
    public const int StructuredHeadBytes = 64;
    public const int HashChunkBytes = 1024 * 1024;

    private const uint GENERIC_READ = 0x80000000u;
    private const uint FILE_READ_ATTRIBUTES = 0x00000080u;
    private const uint SHARE_ALL = 0x01u | 0x02u | 0x04u;
    private const uint OPEN_EXISTING = 3u;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000u;
    private const uint FILE_ATTR_DIRECTORY = 0x00000010u;
    private const uint FILE_ATTR_REPARSE_POINT = 0x00000400u;
    private const int ERROR_SHARING_VIOLATION = 32;

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

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    private static readonly Regex BrowserUserDataRegex =
        new Regex(@"[\\/]user data[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex BrowserBlockfileSubdirRegex =
        new Regex(@"[\\/](cache[\\/]cache_data|gpucache|dawncache)[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex BrowserCodeCacheSubdirRegex =
        new Regex(@"[\\/]code cache[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex BrowserBlockfileShardNameRegex =
        new Regex(@"^f_[0-9a-f]{6,8}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex BrowserCodeCacheEntryNameRegex =
        new Regex(@"^[0-9a-f]{16}_([0-9a-f]+|s)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex FirefoxCache2SubdirRegex =
        new Regex(@"[\\/]cache2[\\/]entries[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex FirefoxStartupSubdirRegex =
        new Regex(@"[\\/]startupcache[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex FirefoxEntryNameRegex =
        new Regex(@"^[0-9a-f]{40}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex FirefoxStartupFileNameRegex =
        new Regex(@"^.+\.(little|bin)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex AppCachedDataSubdirRegex =
        new Regex(@"[\\/](code|cursor)[\\/]cacheddata[\\/][0-9a-f]{8,64}[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex AppCachedVsixSubdirRegex =
        new Regex(@"[\\/](code|cursor)[\\/]cachedextensionvsixs[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex D3dsCacheSubdirRegex =
        new Regex(@"[\\/]d3dscache[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex VendorShaderSubdirRegex =
        new Regex(@"[\\/](dxcache|dxccache|glcache|nv_cache|vkcache|shadercache)[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex VendorShaderHexFileRegex =
        new Regex(@"^[0-9a-fA-F_]{6,64}(\.(?!lock$)[a-z0-9]{1,6})?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex PipHttpSubdirRegex =
        new Regex(@"[\\/]pip[\\/]cache[\\/](http|http-v2)[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex NuGetCacheSubdirRegex =
        new Regex(@"[\\/](nuget[\\/]v3-cache|v3-cache|nuget[-_a-z0-9]*)[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex YarnPnpmCacheSubdirRegex =
        new Regex(@"[\\/](yarn[\\/]cache|yarn-cache|pnpm-cache|pnpm[\\/]cache)[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex GoBuildEntryRegex =
        new Regex(@"[\\/]go-build[\\/]([0-9a-f]{2}[\\/][0-9a-f]{64}-[ad]|trim\.txt|README)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex UvCacheSubdirRegex =
        new Regex(@"[\\/]uv[\\/]cache[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex OfficeTempDraftNameRegex =
        new Regex(@"^(~\$|~df|~wr)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex TempDirSegmentRegex =
        new Regex(@"[\\/]temp[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex ArchivePreviewTempDirRegex =
        new Regex(@"[\\/]temp[\\/](7z[oO][^\\/]*|rar\$[^\\/]*|wz[0-9a-f]{4})[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex TempInstallerSandboxSubdirRegex =
        new Regex(@"[\\/]temp[\\/](is-[a-z0-9]+\.tmp|ns[a-z0-9]+\.tmp|squirreltemp|scoped_dir[0-9]+_[0-9]+|msi[0-9a-f]+\.tmp|\{[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}\}|(edge|chrome)_bits_[0-9]+_[0-9]+|(msedge|chrome)_installer[^\\/]*|pip-(unpack|ephem|req-build)-[^\\/]+|npm-[0-9]+-[0-9a-f]+|pyinstaller-[^\\/]+)[\\/]",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex ChatSnsCacheSubdirRegex =
        new Regex(@"[\\/](sns[\\/]cache|cache[\\/]sns)([\\/]|$)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex ChatWebOrAppletSubdirRegex =
        new Regex(@"[\\/](applet|wmpfruntime|xplugin|xweb|radium[\\/]web[\\/]cache|cefcache|webkit_cache|nt_qq[\\/]global[\\/]nt_temp|nt_temp)([\\/]|$)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex WinUpdateDownloadSubdirRegex =
        new Regex(@"[\\/]softwaredistribution[\\/]download([\\/]|$)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex WinUpdateDataStoreSubdirRegex =
        new Regex(@"[\\/]datastore([\\/]|$)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);

    private const long PoolCacheTtlTicks = 5L * TimeSpan.TicksPerSecond;
    private static readonly object poolCacheGate = new object();
    private static int poolCacheEpoch = -1;
    private static readonly Dictionary<string, long> confirmedBlockfileDirs =
        new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, long> confirmedCodeCacheDirs =
        new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

    [ThreadStatic]
    private static HashBudget activeVerifyBudget;
    [ThreadStatic]
    private static bool inPrefetchedScanVerify;

    private static bool ConsumeOpcBudget(long bytes)
    {
        if (bytes <= 0) return true;
        HashBudget b = activeVerifyBudget;
        if (b == null || b.IsUnlimited) return true;
        return b.TryConsume(bytes);
    }

    internal static void ClearDirectoryVerifyCache()
    {
        lock (poolCacheGate)
        {
            confirmedBlockfileDirs.Clear();
            confirmedCodeCacheDirs.Clear();
            poolCacheEpoch = CacheRuleRegistry.CurrentRefreshEpoch;
        }
    }

    private static void EnsurePoolCacheEpochLocked()
    {
        int cur = CacheRuleRegistry.CurrentRefreshEpoch;
        if (poolCacheEpoch != cur)
        {
            confirmedBlockfileDirs.Clear();
            confirmedCodeCacheDirs.Clear();
            poolCacheEpoch = cur;
        }
    }

    internal static ContentEvidence VerifyPrefetched(string ruleId, string path, byte[] head, long len,
                                                     HashBudget budget, Func<bool> cancelled)
    {
        HashBudget prevBudget = activeVerifyBudget;
        bool prevPrefetch = inPrefetchedScanVerify;
        activeVerifyBudget = budget;
        inPrefetchedScanVerify = true;
        try
        {
            string fail;
            if (ruleId == "TMP-BROWSERCACHE")
            {
                if (!CheckPrefetchedHead(head, 1, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifyBrowserCacheBytes(path, head, len);
            }
            if (ruleId == "TMP-APPCACHE")
            {
                if (!CheckPrefetchedHead(head, 1, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifyAppCacheBytes(path, head, len);
            }
            if (ruleId == "TMP-THUMBCACHE")
            {
                if (!CheckPrefetchedHead(head, 4, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifyThumbcacheBytes(path, head, len);
            }
            if (ruleId == "TMP-SHADERCACHE")
            {
                if (!CheckPrefetchedHead(head, 16, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifyShaderCacheBytes(path, head, len);
            }
            if (ruleId == "TMP-SYSTEMP")
            {
                if (!CheckPrefetchedHead(head, 1, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifySystemTempBytes(path, head, len);
            }
            if (ruleId == "TMP-WER")
            {
                string werExt = "";
                try { werExt = (Path.GetExtension(path) ?? "").ToLowerInvariant(); } catch { werExt = ""; }
                if (werExt == ".dmp" || werExt == ".mdmp" || werExt == ".hdmp")
                    return VerifyCrashDump(path, budget, cancelled);
                if (!CheckPrefetchedHead(head, 8, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifyWerBytes(path, head, len);
            }
            if (ruleId == "TMP-CHATCACHE")
            {
                if (!CheckPrefetchedHead(head, 16, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifyChatCacheBytes(path, head, len);
            }
            if (ruleId == "TMP-WINUPDATE")
            {
                if (!CheckPrefetchedHead(head, 16, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifyWinUpdateBytes(path, head, len);
            }
            if (ruleId == "TMP-PKGCACHE")
            {
                string expected;
                if (TryParseCacachePath(path, out expected)
                    || (path != null && path.IndexOf("_cacache", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    return VerifyCacache(path, budget, cancelled);
                }
                if (!CheckPrefetchedHead(head, 1, budget, cancelled, out fail))
                    return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
                return VerifyNonCacachePkgBytes(path, head, len);
            }
            return Verify(ruleId, path, budget, cancelled);
        }
        catch (Exception ex)
        {
            return new ContentEvidence
            {
                Verified = false,
                Kind = EvidenceKind.None,
                Detail = "内容校验异常：" + ex.GetType().Name
            };
        }
        finally
        {
            activeVerifyBudget = prevBudget;
            inPrefetchedScanVerify = prevPrefetch;
        }
    }

    public static ContentEvidence Verify(string ruleId, string path)
    {
        return Verify(ruleId, path, null, null);
    }

    public static ContentEvidence Verify(string ruleId, string path, HashBudget budget, Func<bool> cancelled)
    {
        HashBudget prevBudget = activeVerifyBudget;
        activeVerifyBudget = budget;
        try
        {
            CacheRuleSpec spec = CacheRuleRegistry.Find(ruleId);
            if (spec == null || spec.VerifyFile == null)
            {
                return new ContentEvidence
                {
                    Verified = false,
                    Kind = EvidenceKind.None,
                    Detail = "该规则没有内容级证据"
                };
            }
            return spec.VerifyFile(path, budget, cancelled);
        }
        catch (Exception ex)
        {
            return new ContentEvidence
            {
                Verified = false,
                Kind = EvidenceKind.None,
                Detail = "内容校验异常：" + ex.GetType().Name
            };
        }
        finally
        {
            activeVerifyBudget = prevBudget;
        }
    }

    /// <summary>
    /// 供永久删除在独占句柄上调用：按 CacheRuleRegistry 绑定的流校验器重新核对同一打开句柄的内容。
    /// 返回 null 表示通过，否则返回拒绝原因。
    /// </summary>
    public static string VerifyOpenStream(string ruleId, string path, Stream s)
    {
        try
        {
            if (s == null) return "文件流为空";
            if (s.CanSeek) s.Position = 0;

            CacheRuleSpec spec = CacheRuleRegistry.Find(ruleId);
            if (spec == null || spec.VerifyStream == null)
                return "该规则没有内容级证据";

            return spec.VerifyStream(path, s);
        }
        catch (Exception ex)
        {
            return "复核读取失败：" + ex.GetType().Name;
        }
    }

    // ---------- 通用魔数校验 ---------- //

    public static ContentEvidence VerifyMagic(string path, string[] magics, string what)
    {
        return VerifyMagic(path, magics, what, null, null);
    }

    public static ContentEvidence VerifyMagic(string path, string[] magics, string what,
                                              HashBudget budget, Func<bool> cancelled)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (cancelled != null && cancelled()) { e.Detail = "内容校验已取消，未校验"; return e; }
        HashBudget b = budget == null ? HashBudget.Unlimited : budget;
        if (!b.TryConsume(8)) { e.Detail = "内容校验字节预算不足（需 8 字节），未校验"; return e; }
        byte[] head;
        try { head = ReadHead(path, 8); }
        catch { e.Detail = "无法读取文件头"; return e; }
        if (head.Length == 0) { e.Detail = "文件为空，无法校验"; return e; }

        foreach (string m in magics)
        {
            if (head.Length < m.Length) continue;
            bool ok = true;
            for (int i = 0; i < m.Length; i++) if (head[i] != (byte)m[i]) { ok = false; break; }
            if (!ok) continue;
            e.Verified = true;
            e.Detail = "文件头匹配 " + m + "（" + what + "）";
            return e;
        }
        e.Detail = "文件头不匹配 " + String.Join("/", magics) + "（" + what + "）";
        return e;
    }

    // ---------- 1. 崩溃转储（MDMP） ---------- //

    public static ContentEvidence VerifyCrashDump(string path, HashBudget budget, Func<bool> cancelled)
    {
        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 8, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };

        string sig8 = Encoding.ASCII.GetString(head, 0, 8);
        if (sig8 == "PAGEDU64" || sig8 == "PAGEDUMP")
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = "内核转储头（" + sig8 + "）：未做结构校验，不授权清理" };
        if (head.Length < 32 || Encoding.ASCII.GetString(head, 0, 4) != "MDMP")
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = "文件头不匹配 MDMP（或不足 32 字节）" };

        uint version = BitConverter.ToUInt32(head, 4);
        uint streams = BitConverter.ToUInt32(head, 8);
        uint rva = BitConverter.ToUInt32(head, 12);
        if ((version & 0xFFFFu) != 0xA793u)
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = "MDMP 版本标记不是 0xA793，结构不符" };
        if (streams == 0 || streams > 512)
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = "MDMP 流数量异常（" + streams + "），结构不符" };
        if (rva < 32 || (long)rva + (long)streams * 12L > len)
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = "MDMP 流目录越出文件范围，结构不符" };

        HashBudget b = budget == null ? HashBudget.Unlimited : budget;
        if (!b.TryConsume((long)streams * 12L))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = "内容校验字节预算不足，未校验" };
        try
        {
            using (FileStream fs = OpenNoReparseRead(path))
                return VerifyCrashDumpBytes(head, fs.Length, fs);
        }
        catch { return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = "无法读取结构数据" }; }
    }

    public static string VerifyCrashDumpStream(string path, Stream s)
    {
        if (s == null || !s.CanSeek) return "文件流不可定位";
        try
        {
            byte[] head = ReadStreamHead(s, StructuredHeadBytes);
            ContentEvidence ce = VerifyCrashDumpBytes(head, s.Length, s);
            return ce.Verified ? null : ce.Detail;
        }
        catch (Exception ex)
        {
            return "读取转储流失败：" + ex.GetType().Name;
        }
    }

    public static ContentEvidence VerifyCrashDumpBytes(byte[] head, long len, Stream s)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (head == null || head.Length < 8) { e.Detail = "文件不足 8 字节，结构不完整"; return e; }
        if (s == null || !s.CanSeek) { e.Detail = "转储数据流为空或不可定位"; return e; }
        string sig8 = Encoding.ASCII.GetString(head, 0, 8);
        if (sig8 == "PAGEDU64" || sig8 == "PAGEDUMP") { e.Detail = "内核转储头（" + sig8 + "）：未做结构校验，不授权清理"; return e; }
        if (len < 32 || head.Length < 32 || Encoding.ASCII.GetString(head, 0, 4) != "MDMP") { e.Detail = "文件头不匹配 MDMP（或不足 32 字节）"; return e; }
        uint version = BitConverter.ToUInt32(head, 4), streams = BitConverter.ToUInt32(head, 8), rva = BitConverter.ToUInt32(head, 12);
        if ((version & 0xFFFFu) != 0xA793u) { e.Detail = "MDMP 版本标记不是 0xA793，结构不符"; return e; }
        if (streams == 0 || streams > 512) { e.Detail = "MDMP 流数量异常（" + streams + "），结构不符"; return e; }
        if (rva < 32 || (long)rva + (long)streams * 12L > len) { e.Detail = "MDMP 流目录越出文件范围，结构不符"; return e; }
        int dirBytes = (int)streams * 12;
        byte[] dir = new byte[dirBytes];
        int read = 0;
        try
        {
            s.Position = rva;
            while (read < dirBytes) { int n = s.Read(dir, read, dirBytes - read); if (n <= 0) break; read += n; }
        }
        catch (Exception ex)
        {
            e.Detail = "读取 MDMP 流目录失败：" + ex.GetType().Name;
            return e;
        }
        if (read != dirBytes) { e.Detail = "读取 MDMP 流目录不完整"; return e; }
        int nonEmpty = 0;
        for (int i = 0; i < (int)streams; i++)
        {
            uint streamType = BitConverter.ToUInt32(dir, i * 12);
            uint size = BitConverter.ToUInt32(dir, i * 12 + 4);
            uint at = BitConverter.ToUInt32(dir, i * 12 + 8);
            if (streamType == 0 || size == 0) continue;
            if (at < 32 || (long)at + (long)size > len) { e.Detail = "MDMP 第 " + (i + 1) + " 个流的数据越出文件范围，结构不符"; return e; }
            if ((long)at < (long)rva + (long)dirBytes && (long)at + (long)size > (long)rva) { e.Detail = "MDMP 第 " + (i + 1) + " 个流的数据与流目录重叠，结构不符"; return e; }
            nonEmpty++;
        }
        if (nonEmpty == 0) { e.Detail = "MDMP 没有非空数据流，结构不符"; return e; }
        e.Verified = true;
        e.Detail = "MDMP 结构校验通过：版本 0xA793，" + streams + " 个流在文件内";
        return e;
    }

    // ---------- 2. 缩略图与图标缓存（CMMM） ---------- //

    public static ContentEvidence VerifyThumbcache(string path, HashBudget budget, Func<bool> cancelled)
    {
        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 4, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifyThumbcacheBytes(path, head, len);
    }

    public static string VerifyThumbcacheStream(string path, Stream s)
    {
        if (s == null) return "文件流为空";
        byte[] head = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence ce = VerifyThumbcacheBytes(path, head, s.Length);
        return ce.Verified ? null : ce.Detail;
    }

    public static ContentEvidence VerifyThumbcacheBytes(string path, byte[] head, long len)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path)) { e.Detail = "路径为空"; return e; }
        string fn = Path.GetFileName(path) ?? "";
        if (!fn.StartsWith("thumbcache_", StringComparison.OrdinalIgnoreCase)
            && !fn.StartsWith("iconcache_", StringComparison.OrdinalIgnoreCase))
        {
            e.Detail = "文件名不符合 thumbcache_ / iconcache_ 规范";
            return e;
        }
        if (fn.EndsWith("_idx.db", StringComparison.OrdinalIgnoreCase)) { e.Detail = "索引文件（*_idx.db），不授权清理"; return e; }
        if (head == null || head.Length < 4 || Encoding.ASCII.GetString(head, 0, 4) != "CMMM") { e.Detail = "文件头不匹配 CMMM（索引文件或其他格式）"; return e; }
        if (head.Length < 24 || len < 24) { e.Detail = "CMMM 文件头不完整（不足 24 字节）"; return e; }
        uint version = BitConverter.ToUInt32(head, 4), type = BitConverter.ToUInt32(head, 8);
        uint first = BitConverter.ToUInt32(head, 16), avail = BitConverter.ToUInt32(head, 20);
        if (version < 20 || version > 40) { e.Detail = "CMMM 格式版本未知（" + version + "）"; return e; }
        if (type > 16) { e.Detail = "CMMM 缓存类型异常（" + type + "）"; return e; }
        if (first < 24 || first > len || avail < first || avail > len) { e.Detail = "CMMM 条目偏移越出文件范围，结构不符"; return e; }
        e.Verified = true;
        e.Detail = "CMMM 结构校验通过：版本 " + version + "，偏移在文件内";
        return e;
    }

    // ---------- 3. 浏览器缓存与桌面软件缓存（Chromium / Firefox / Electron / WebView2 / VS Code） ---------- //

    public static ContentEvidence VerifyBrowserCache(string path, HashBudget budget, Func<bool> cancelled)
    {
        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 1, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifyBrowserCacheBytes(path, head, len);
    }

    public static string VerifyBrowserCacheStream(string path, Stream s)
    {
        byte[] head = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence ce = VerifyBrowserCacheBytes(path, head, s.Length);
        return ce.Verified ? null : ce.Detail;
    }

    public static ContentEvidence VerifyBrowserCacheBytes(string path, byte[] head, long len)
    {
        return VerifyChromiumOrFirefoxCacheBytes(path, head, len, "TMP-BROWSERCACHE", true);
    }

    public static ContentEvidence VerifyAppCache(string path, HashBudget budget, Func<bool> cancelled)
    {
        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 1, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifyAppCacheBytes(path, head, len);
    }

    public static string VerifyAppCacheStream(string path, Stream s)
    {
        if (s == null) return "文件流为空";
        byte[] head = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence ce = VerifyAppCacheBytesCore(path, head, s.Length, s);
        return ce.Verified ? null : ce.Detail;
    }

    public static ContentEvidence VerifyAppCacheBytes(string path, byte[] head, long len)
    {
        return VerifyAppCacheBytesCore(path, head, len, null);
    }

    private static ContentEvidence VerifyAppCacheBytesCore(string path, byte[] head, long len, Stream streamOrNull)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path))
        {
            e.Detail = "路径为空";
            return e;
        }
        if (head == null) head = new byte[0];

        string name = Path.GetFileName(path) ?? "";
        if (CacheRoots.IsAppProtectedPath(name, path))
        {
            e.Detail = "命中桌面软件受保护数据项（配置/登录态/数据库/工作区存储）";
            return e;
        }

        string ext = "";
        try { ext = (Path.GetExtension(name) ?? "").ToLowerInvariant(); } catch { ext = ""; }
        if (ext == ".lock" || ext == ".lck" || ext == ".lockfile")
        {
            e.Detail = "软件运行锁文件不予清理";
            return e;
        }

        bool inInjectedAppRoot = false;
        if (CacheRoots.HasInjectedForTest)
        {
            string matchedRule, matchedWhy;
            inInjectedAppRoot = CacheRoots.Match(path, out matchedRule, out matchedWhy)
                && string.Equals(matchedRule, "TMP-APPCACHE", StringComparison.Ordinal);
        }

        // 1) VS Code / Cursor CachedExtensionVsiXs：合法 ZIP (PK\x03\x04) 且拒绝 Office OpenXML 文档
        if (AppCachedVsixSubdirRegex.IsMatch(path) || (inInjectedAppRoot && ext == ".vsix"))
        {
            string nonZipForbidden = CheckNonZipForbiddenHeader(head);
            if (nonZipForbidden != null)
            {
                e.Detail = "检测到用户文档或非插件包头：" + nonZipForbidden;
                return e;
            }
            string zipErr = CheckValidZipPackageHeader(head, len, true, streamOrNull, path);
            if (zipErr != null)
            {
                e.Detail = "插件包缓存校验未通过：" + zipErr;
                return e;
            }
            e.Verified = true;
            e.Detail = "桌面编辑器插件包缓存（ZIP/VSIX 包头）校验通过";
            return e;
        }

        // 2) VS Code / Cursor CachedData\<commit-hash>\*：V8 编译缓存
        if (AppCachedDataSubdirRegex.IsMatch(path))
        {
            string docSig = CheckForbiddenImportantHeader(head);
            if (docSig != null)
            {
                e.Detail = "拒绝非缓存结构：" + docSig;
                return e;
            }
            if (len < 16 || head.Length < 16)
            {
                e.Detail = "CachedData 文件不足 16 字节，结构不完整";
                return e;
            }
            if (IsAllSameByte(head))
            {
                e.Detail = "文件头全为同一填充字节，疑似伪造空壳";
                return e;
            }
            if (StartsWithBytes(head, 0xEF, 0xBB, 0xBF) || StartsWithBytes(head, 0xFF, 0xFE) || StartsWithBytes(head, 0xFE, 0xFF))
            {
                e.Detail = "检测到文本 BOM 头，非二进制 V8 缓存";
                return e;
            }
            uint m32 = BitConverter.ToUInt32(head, 0);
            if ((m32 & 0xFFFF0000u) != 0xC0DE0000u && !HasBinaryFraming(head, Math.Min(head.Length, 24)))
            {
                e.Detail = "内容为纯可见文本，不具备 V8 编译缓存二进制特征";
                return e;
            }
            e.Verified = true;
            e.Detail = "V8 编译缓存（CachedData）二进制结构校验通过";
            return e;
        }

        // 3) Electron / CEF / WebView2 / Steam htmlcache 纯缓存四件套：直接复用严谨 Chromium 缓存校验
        return VerifyChromiumOrFirefoxCacheBytes(path, head, len, "TMP-APPCACHE", false);
    }

    private static ContentEvidence VerifyChromiumOrFirefoxCacheBytes(
        string path, byte[] head, long len, string expectedRuleId, bool allowFirefox)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path))
        {
            e.Detail = "路径为空";
            return e;
        }
        if (head == null) head = new byte[0];

        string name = Path.GetFileName(path);
        if (name == null) name = "";

        if (CacheRoots.IsBrowserProtectedPath(name, path))
        {
            e.Detail = "命中浏览器受保护数据项（Cookie/密码/历史/书签等）";
            return e;
        }

        bool inBlockfileSubdir = BrowserBlockfileSubdirRegex.IsMatch(path);
        bool inCodeCacheSubdir = !inBlockfileSubdir && BrowserCodeCacheSubdirRegex.IsMatch(path);
        bool inFirefoxCache2 = allowFirefox && !inBlockfileSubdir && !inCodeCacheSubdir && FirefoxCache2SubdirRegex.IsMatch(path);
        bool inFirefoxStartup = allowFirefox && !inBlockfileSubdir && !inCodeCacheSubdir && !inFirefoxCache2 && FirefoxStartupSubdirRegex.IsMatch(path);
        bool inPureCacheSubdir = inBlockfileSubdir || inCodeCacheSubdir || inFirefoxCache2 || inFirefoxStartup;
        bool inInjectedRoot = false;

        if (!inPureCacheSubdir)
        {
            if (BrowserUserDataRegex.IsMatch(path))
            {
                e.Detail = "不在浏览器纯缓存子目录内";
                return e;
            }
            if (CacheRoots.HasInjectedForTest)
            {
                string matchedRule, matchedWhy;
                inInjectedRoot = CacheRoots.Match(path, out matchedRule, out matchedWhy)
                    && string.Equals(matchedRule, expectedRuleId, StringComparison.Ordinal);
            }
            if (!inInjectedRoot)
            {
                e.Detail = "不在受控纯缓存子目录内";
                return e;
            }
        }

        // f1) Mozilla Firefox cache2\entries\<40-hex>：原始网页响应体 + 尾部元数据（硬拦截受保护数据库/可执行程序/私钥头）
        if (allowFirefox && (inFirefoxCache2 || inInjectedRoot) && FirefoxEntryNameRegex.IsMatch(name))
        {
            if (len <= 0 || head.Length == 0)
            {
                e.Detail = "Firefox cache2 缓存条目为空";
                return e;
            }
            if (StartsWithAscii(head, "SQLite format 3") || StartsWithAscii(head, "SQLite"))
            {
                e.Detail = "拒绝 SQLite 数据库头";
                return e;
            }
            if (StartsWithBytes(head, 0x4D, 0x5A))
            {
                e.Detail = "拒绝 PE 可执行程序或动态库头（MZ）";
                return e;
            }
            if (StartsWithAscii(head, "-----BEGIN ") || StartsWithAscii(head, "regf"))
            {
                e.Detail = "拒绝证书私钥或注册表配置单元头";
                return e;
            }
            e.Verified = true;
            e.Detail = "Firefox cache2 网页缓存条目校验通过";
            return e;
        }

        // f2) Mozilla Firefox startupCache\*.little / *.bin：排除重要文档头，len >= 16 且具备二进制帧头
        if (allowFirefox && (inFirefoxStartup || inInjectedRoot) && FirefoxStartupFileNameRegex.IsMatch(name))
        {
            string ffDocSig = CheckForbiddenImportantHeader(head);
            if (ffDocSig != null)
            {
                e.Detail = "拒绝非缓存结构：" + ffDocSig;
                return e;
            }
            if (len < 16 || head.Length < 16 || IsAllSameByte(head))
            {
                e.Detail = "Firefox startupCache 文件不足 16 字节或为空壳";
                return e;
            }
            if (StartsWithBytes(head, 0xEF, 0xBB, 0xBF) || StartsWithBytes(head, 0xFF, 0xFE) || StartsWithBytes(head, 0xFE, 0xFF))
            {
                e.Detail = "检测到文本 BOM 头，非二进制 startupCache";
                return e;
            }
            if (!StartsWithAscii(head, "mozXulCache") && !StartsWithAscii(head, "scache") && !HasBinaryFraming(head, Math.Min(head.Length, 24)))
            {
                e.Detail = "内容为纯文本，不具备 Firefox startupCache 二进制帧特征";
                return e;
            }
            e.Verified = true;
            e.Detail = "Firefox startupCache 启动缓存结构校验通过";
            return e;
        }

        // b) Chromium Blockfile 外部缓存体文件 ^f_[0-9a-f]{6,8}$（无后缀，存储原始 HTTP 响应体，无包装魔数头）
        //    要求位于 Cache\Cache_Data / GPUCache / DawnCache（或测试注入根）内，且同目录存在合法的 Blockfile index 或 data_0 缓存池。
        //    保留网页响应体（PNG/JPEG/GZIP/PDF/ZIP）的同时硬拦截 SQLite / PEM 私钥 / 注册表 / ESE / KDBX 头。
        if ((inBlockfileSubdir || inInjectedRoot)
            && BrowserBlockfileShardNameRegex.IsMatch(name))
        {
            if (len <= 0 || head.Length == 0)
            {
                e.Detail = "Blockfile 独立缓存块为空";
                return e;
            }
            if (StartsWithAscii(head, "SQLite format 3") || StartsWithAscii(head, "SQLite")
                || StartsWithSqliteWalMagic(head))
            {
                e.Detail = "拒绝 SQLite 数据库或 WAL 日志头";
                return e;
            }
            if (StartsWithAscii(head, "-----BEGIN ") || StartsWithAscii(head, "regf")
                || StartsWithEseDbMagic(head) || StartsWithKdbxMagic(head))
            {
                e.Detail = "拒绝凭据密钥、密码库、ESE 数据库或注册表头";
                return e;
            }
            string parentDir = TryGetParentDir(path);
            if (HasValidBlockfilePool(parentDir))
            {
                e.Verified = true;
                e.Detail = "Chromium Blockfile 独立缓存块校验通过";
                return e;
            }
            e.Detail = "同目录未发现有效的 Chromium Blockfile 索引或数据池（index / data_0）";
            return e;
        }

        // 对非 f_xxxxxx 命名的文件保留受保护重要文档/程序头硬拦截
        string docSig = CheckForbiddenImportantHeader(head);
        if (docSig != null)
        {
            e.Detail = "拒绝非缓存结构：" + docSig;
            return e;
        }
        if (len < 16 || head.Length < 16)
        {
            e.Detail = "文件不足 16 字节，疑似空壳或残缺头";
            return e;
        }
        if (IsAllSameByte(head))
        {
            e.Detail = "文件头全为同一填充字节，疑似伪造空壳";
            return e;
        }

        // a1) Chromium Simple Cache 数据项头（小端 0xfcfb6d1ba7725c30，SimpleFileHeader 为 24 字节）
        if (len >= 24 && head.Length >= 24 && BitConverter.ToUInt64(head, 0) == 0xfcfb6d1ba7725c30UL)
        {
            e.Verified = true;
            e.Detail = "Chromium Simple Cache 头校验通过";
            return e;
        }

        // a2) Chromium Simple Cache 索引文件（index / the-real-index）
        if (len >= 24 && head.Length >= 16
            && string.Equals(name, "the-real-index", StringComparison.OrdinalIgnoreCase)
            && (BitConverter.ToUInt64(head, 8) == 0xfcfb6d1ba7725c30UL
                || ContainsUInt64Magic(head, 0x656e74657220796fUL)))
        {
            e.Verified = true;
            e.Detail = "Chromium Simple Cache 真实索引头校验通过";
            return e;
        }
        if (len >= 16 && head.Length >= 8
            && string.Equals(name, "index", StringComparison.OrdinalIgnoreCase)
            && (BitConverter.ToUInt64(head, 0) == 0x656e74657220796fUL
                || BitConverter.ToUInt64(head, 0) == 0xfcfb6d1ba7725c30UL))
        {
            e.Verified = true;
            e.Detail = "Chromium Simple Cache 索引标记校验通过";
            return e;
        }

        // a3) Chromium Blockfile index (0xc103cac3) / data_* (0xc104cac3)
        uint m32 = BitConverter.ToUInt32(head, 0);
        if (len >= 32 && head.Length >= 32 && (m32 == 0xc103cac3u || m32 == 0xc104cac3u))
        {
            string poolDir = TryGetParentDir(path);
            RecordConfirmedBlockfileDir(poolDir);
            e.Verified = true;
            e.Detail = "Chromium Blockfile 魔数校验通过（0x" + m32.ToString("x8") + "）";
            return e;
        }

        // a4) V8 字节码魔数 0xC0DE....
        if ((inCodeCacheSubdir || inBlockfileSubdir || inInjectedRoot)
            && len >= 24 && head.Length >= 16 && (m32 & 0xFFFF0000u) == 0xC0DE0000u)
        {
            e.Verified = true;
            e.Detail = "Chromium Code Cache 头校验通过（0x" + m32.ToString("x8") + "）";
            return e;
        }

        // c) Code Cache（js / wasm）下 ^[0-9a-f]{16}_([0-9a-f]+|s)$ 条目：
        //    同级或上级 Code Cache 目录存在 index / the-real-index，len >= 24，且通过非空二进制头校验（已排除 Office/ZIP/PDF/PE 头）
        if ((inCodeCacheSubdir || inInjectedRoot)
            && BrowserCodeCacheEntryNameRegex.IsMatch(name)
            && len >= 24 && head.Length >= 16)
        {
            if (StartsWithBytes(head, 0xEF, 0xBB, 0xBF) || StartsWithBytes(head, 0xFF, 0xFE) || StartsWithBytes(head, 0xFE, 0xFF))
            {
                e.Detail = "检测到文本 BOM 头，非二进制 Code Cache 条目";
                return e;
            }
            if (HasBinaryFraming(head, Math.Min(head.Length, 24)))
            {
                string codeDir = TryGetParentDir(path);
                if (HasValidCodeCachePool(codeDir))
                {
                    e.Verified = true;
                    e.Detail = "Chromium Code Cache 条目校验通过";
                    return e;
                }
                e.Detail = "同级或上级 Code Cache 目录未发现 index / the-real-index";
                return e;
            }
        }

        e.Detail = "文件头不匹配 Chromium 缓存魔数";
        return e;
    }

    private static string TryGetParentDir(string path)
    {
        try { return PathGuard.CanonicalFast(Path.GetDirectoryName(path) ?? ""); }
        catch { return ""; }
    }

    private static void RecordConfirmedBlockfileDir(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return;
        lock (poolCacheGate)
        {
            EnsurePoolCacheEpochLocked();
            if (confirmedBlockfileDirs.Count >= 4096)
                confirmedBlockfileDirs.Clear();
            confirmedBlockfileDirs[dir] = DateTime.UtcNow.Ticks;
        }
    }

    private static bool HasValidBlockfilePool(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return false;
        lock (poolCacheGate)
        {
            EnsurePoolCacheEpochLocked();
            long ts;
            if (confirmedBlockfileDirs.TryGetValue(dir, out ts))
            {
                long now = DateTime.UtcNow.Ticks;
                if (now >= ts && (now - ts) < PoolCacheTtlTicks)
                    return true;
                confirmedBlockfileDirs.Remove(dir);
            }
        }

        bool valid = IsValidBlockfileAnchor(Path.Combine(dir, "index"), true)
            || IsValidBlockfileAnchor(Path.Combine(dir, "data_0"), false)
            || IsValidBlockfileAnchor(Path.Combine(dir, "data_1"), false);

        if (valid)
        {
            RecordConfirmedBlockfileDir(dir);
        }
        return valid;
    }

    private static bool IsValidBlockfileAnchor(string filePath, bool isIndex)
    {
        try
        {
            if (string.IsNullOrEmpty(filePath) || PathGuard.HasAnyReparseComponent(filePath))
                return false;
            FileInfo fi = new FileInfo(filePath);
            if (!fi.Exists) return false;
            FileAttributes attr = fi.Attributes;
            if ((attr & FileAttributes.Directory) != 0 || (attr & FileAttributes.ReparsePoint) != 0)
                return false;
            long flen = fi.Length;
            if (flen < (isIndex ? 16L : 32L))
                return false;

            try
            {
                byte[] head = ReadHead(filePath, 16);
                if (isIndex)
                {
                    if (flen >= 32 && head.Length >= 8 && BitConverter.ToUInt32(head, 0) == 0xc103cac3u)
                    {
                        uint ver = BitConverter.ToUInt32(head, 4);
                        return ver == 0x00020000u || ver == 0x00020001u;
                    }
                    if (flen >= 16 && head.Length >= 8
                        && (BitConverter.ToUInt64(head, 0) == 0x656e74657220796fUL
                            || BitConverter.ToUInt64(head, 0) == 0xfcfb6d1ba7725c30UL))
                        return true;
                    return false;
                }
                if (flen >= 32 && head.Length >= 8 && BitConverter.ToUInt32(head, 0) == 0xc104cac3u)
                {
                    uint ver = BitConverter.ToUInt32(head, 4);
                    return ver == 0x00020000u || ver == 0x00020001u;
                }
                return false;
            }
            catch (IOException ioEx)
            {
                // 仅当真实 Chromium Blockfile 纯缓存子目录内的非重解析点池文件因共享冲突 (ERROR_SHARING_VIOLATION=0x20) 被浏览器独占锁定时才放行；其余 IOException 一律 fail-closed
                bool isSharingViolation = (ioEx.HResult & 0xFFFF) == ERROR_SHARING_VIOLATION;
                return isSharingViolation
                    && BrowserBlockfileSubdirRegex.IsMatch(filePath)
                    && flen >= (isIndex ? 24L : 32L);
            }
        }
        catch
        {
            return false;
        }
    }

    private static bool HasValidCodeCachePool(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return false;
        lock (poolCacheGate)
        {
            EnsurePoolCacheEpochLocked();
            long ts;
            if (confirmedCodeCacheDirs.TryGetValue(dir, out ts))
            {
                long now = DateTime.UtcNow.Ticks;
                if (now >= ts && (now - ts) < PoolCacheTtlTicks)
                    return true;
                confirmedCodeCacheDirs.Remove(dir);
            }
        }

        bool valid = HasCodeCacheIndexFilesInDir(dir);
        if (!valid)
        {
            string parent = TryGetParentDir(dir);
            if (parent.Length > 0)
            {
                string parentLeaf = Path.GetFileName(parent) ?? "";
                if (string.Equals(parentLeaf, "Code Cache", StringComparison.OrdinalIgnoreCase)
                    || BrowserCodeCacheSubdirRegex.IsMatch(parent + "\\"))
                {
                    valid = HasCodeCacheIndexFilesInDir(parent);
                }
            }
        }

        if (valid)
        {
            lock (poolCacheGate)
            {
                EnsurePoolCacheEpochLocked();
                if (confirmedCodeCacheDirs.Count >= 4096)
                    confirmedCodeCacheDirs.Clear();
                confirmedCodeCacheDirs[dir] = DateTime.UtcNow.Ticks;
            }
        }
        return valid;
    }

    private static bool HasCodeCacheIndexFilesInDir(string dir)
    {
        return IsValidCodeCacheIndexFile(Path.Combine(dir, "index"))
            || IsValidCodeCacheIndexFile(Path.Combine(dir, "the-real-index"))
            || IsValidCodeCacheIndexFile(Path.Combine(dir, Path.Combine("index-dir", "the-real-index")));
    }

    private static bool IsValidCodeCacheIndexFile(string filePath)
    {
        try
        {
            if (string.IsNullOrEmpty(filePath) || PathGuard.HasAnyReparseComponent(filePath))
                return false;
            FileInfo fi = new FileInfo(filePath);
            if (!fi.Exists) return false;
            FileAttributes attr = fi.Attributes;
            if ((attr & FileAttributes.Directory) != 0 || (attr & FileAttributes.ReparsePoint) != 0)
                return false;
            long flen = fi.Length;
            if (flen < 16L) return false;

            byte[] head = ReadHead(filePath, 32);
            if (head.Length < 8) return false;
            if (CheckForbiddenImportantHeader(head) != null) return false;
            if (IsAllSameByte(head)) return false;

            // 必须命中 Chromium Simple Cache 索引魔数（0x656e74657220796f 或 0xfcfb6d1ba7725c30），IOException 一律 fail-closed
            ulong m0 = BitConverter.ToUInt64(head, 0);
            if (m0 == 0x656e74657220796fUL || m0 == 0xfcfb6d1ba7725c30UL)
                return true;
            if (head.Length >= 16 && BitConverter.ToUInt64(head, 8) == 0xfcfb6d1ba7725c30UL)
                return true;
            return ContainsUInt64Magic(head, 0x656e74657220796fUL);
        }
        catch
        {
            return false;
        }
    }

    private static bool ContainsUInt64Magic(byte[] head, ulong magic)
    {
        if (head == null || head.Length < 8) return false;
        for (int i = 0; i <= head.Length - 8; i += 4)
        {
            if (BitConverter.ToUInt64(head, i) == magic)
                return true;
        }
        return false;
    }

    // ---------- 4. 图形与着色器缓存（D3DSCache / NVIDIA / AMD / Intel） ---------- //

    public static ContentEvidence VerifyShaderCache(string path, HashBudget budget, Func<bool> cancelled)
    {
        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 16, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifyShaderCacheBytes(path, head, len);
    }

    public static string VerifyShaderCacheStream(string path, Stream s)
    {
        byte[] head = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence ce = VerifyShaderCacheBytes(path, head, s.Length);
        return ce.Verified ? null : ce.Detail;
    }

    public static ContentEvidence VerifyShaderCacheBytes(string path, byte[] head, long len)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path)) { e.Detail = "路径为空"; return e; }

        string name = Path.GetFileName(path) ?? "";
        string ext = "";
        try { ext = (Path.GetExtension(name) ?? "").ToLowerInvariant(); } catch { ext = ""; }
        if (ext == ".lock")
        {
            e.Detail = "着色器锁文件（.lock）不予清理";
            return e;
        }

        bool inD3dsCache = D3dsCacheSubdirRegex.IsMatch(path);
        if (inD3dsCache)
        {
            if (ext != ".val" && ext != ".idx")
            {
                e.Detail = "D3DSCache 下仅允许 .val / .idx 着色器缓存";
                return e;
            }
        }
        else
        {
            bool inVendorShader = VendorShaderSubdirRegex.IsMatch(path);
            bool inInjectedShader = false;
            if (!inVendorShader && CacheRoots.HasInjectedForTest)
            {
                string matchedRule, matchedWhy;
                inInjectedShader = CacheRoots.Match(path, out matchedRule, out matchedWhy)
                    && string.Equals(matchedRule, "TMP-SHADERCACHE", StringComparison.Ordinal);
            }

            bool knownShaderExt = ext == ".val" || ext == ".idx" || ext == ".bin"
                || ext == ".toc" || ext == ".parc" || ext == ".dxbc" || ext == ".nvph";
            bool hexEntryInVendor = inVendorShader && VendorShaderHexFileRegex.IsMatch(name);
            if (!knownShaderExt && !hexEntryInVendor)
            {
                e.Detail = "文件名或扩展名不符合图形着色器缓存规范";
                return e;
            }
            if (!inVendorShader && !inInjectedShader && ext != ".val" && ext != ".idx"
                && ext != ".dxbc" && ext != ".nvph" && ext != ".parc")
            {
                e.Detail = "不在受控显卡着色器缓存子目录内";
                return e;
            }
        }

        if (len < 16 || head == null || head.Length < 16)
        {
            e.Detail = "文件不足 16 字节，着色器缓存结构不完整";
            return e;
        }
        if (IsAllSameByte(head))
        {
            e.Detail = "文件头全为同一填充字节，疑似伪造空壳";
            return e;
        }
        string docSig = CheckForbiddenImportantHeader(head);
        if (docSig != null)
        {
            e.Detail = "拒绝非着色器结构：" + docSig;
            return e;
        }
        if (StartsWithBytes(head, 0xEF, 0xBB, 0xBF) || StartsWithBytes(head, 0xFF, 0xFE) || StartsWithBytes(head, 0xFE, 0xFF))
        {
            e.Detail = "检测到文本 BOM 头，非二进制着色器缓存";
            return e;
        }

        bool gpuMagic = StartsWithAscii(head, "DXBC") || StartsWithAscii(head, "DXIL")
            || StartsWithAscii(head, "D3DC") || StartsWithAscii(head, "SHDR")
            || StartsWithAscii(head, "NVDA") || StartsWithAscii(head, "NVPK")
            || StartsWithAscii(head, "AMDX") || StartsWithAscii(head, "VKSC");
        if (!gpuMagic && !HasBinaryFraming(head, 16))
        {
            e.Detail = "内容为纯可见文本，不具备着色器二进制头特征";
            return e;
        }

        e.Verified = true;
        e.Detail = "图形着色器缓存（" + (ext.Length > 0 ? ext : "hex") + "）二进制结构校验通过";
        return e;
    }

    // ---------- 5. 开发包管理器缓存（npm cacache / pip / NuGet / Yarn / pnpm / go-build / uv） ---------- //

    public static ContentEvidence VerifyPkgCache(string path, HashBudget budget, Func<bool> cancelled)
    {
        string expected;
        if (TryParseCacachePath(path, out expected)
            || (path != null && path.IndexOf("_cacache", StringComparison.OrdinalIgnoreCase) >= 0))
        {
            return VerifyCacache(path, budget, cancelled);
        }

        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 1, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifyNonCacachePkgBytes(path, head, len);
    }

    public static string VerifyPkgCacheStream(string path, Stream s)
    {
        if (s == null) return "文件流为空";
        string expected;
        if (TryParseCacachePath(path, out expected)
            || (path != null && path.IndexOf("_cacache", StringComparison.OrdinalIgnoreCase) >= 0))
        {
            if (!TryParseCacachePath(path, out expected)) return "路径结构不符";
            if (s.CanSeek && s.Length > MaxHashBytes) return "文件超过哈希校验上限";
            if (s.CanSeek) s.Position = 0;
            string hex;
            byte[] buf = new byte[HashChunkBytes];
            long totalRead = 0;
            using (SHA512 sha = SHA512.Create())
            {
                while (true)
                {
                    int n = s.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    totalRead += n;
                    if (totalRead > MaxHashBytes) return "文件超过哈希校验上限";
                    sha.TransformBlock(buf, 0, n, null, 0);
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                byte[] d = sha.Hash;
                StringBuilder sb = new StringBuilder(d.Length * 2);
                foreach (byte x in d) sb.Append(x.ToString("x2"));
                hex = sb.ToString();
            }
            return string.Equals(hex, expected, StringComparison.OrdinalIgnoreCase) ? null : "内容哈希与文件名不符";
        }

        byte[] pkgHead = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence pkgCe = VerifyNonCacachePkgBytesCore(path, pkgHead, s.Length, s);
        return pkgCe.Verified ? null : pkgCe.Detail;
    }

    public static ContentEvidence VerifyNonCacachePkgBytes(string path, byte[] head, long len)
    {
        return VerifyNonCacachePkgBytesCore(path, head, len, null);
    }

    private static ContentEvidence VerifyNonCacachePkgBytesCore(string path, byte[] head, long len, Stream streamOrNull)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path)) { e.Detail = "路径为空"; return e; }
        if (head == null) head = new byte[0];
        string ext = "";
        try { ext = (Path.GetExtension(path) ?? "").ToLowerInvariant(); } catch { ext = ""; }
        if (ext == ".lock" || ext == ".lck" || ext == ".lockfile") { e.Detail = "包管理器锁文件不予清理"; return e; }

        // 1) pip / uv .whl 与 NuGet .nupkg：合法 ZIP Local File Header (PK\x03\x04，且头 >= 30 字节，排除 Office 文档)
        if (ext == ".whl" || ext == ".nupkg")
        {
            string zipFail = CheckValidZipPackageHeader(head, len, true, streamOrNull, path);
            if (zipFail != null)
            {
                e.Detail = (ext == ".whl" ? "wheel " : "NuGet .nupkg ") + zipFail;
                return e;
            }
            e.Verified = true;
            e.Detail = (ext == ".whl" ? "Python wheel" : "NuGet nupkg") + " ZIP 包头校验通过";
            return e;
        }

        // 2) Yarn / pnpm / npm / uv .tgz 或 .tar.gz 压缩包缓存：GZIP deflate 魔数 1F 8B 08 且 >= 18 字节
        bool isTarGz = ext == ".tgz" || path.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase);
        if (isTarGz)
        {
            string nonZipForbidden = CheckNonZipForbiddenHeader(head);
            if (nonZipForbidden != null)
            {
                e.Detail = "检测到用户文档或程序头：" + nonZipForbidden;
                return e;
            }
            if (len < 18 || head.Length < 10 || IsAllSameByte(head) || !StartsWithBytes(head, 0x1F, 0x8B, 0x08))
            {
                e.Detail = "压缩归档头不匹配 GZIP 压缩流魔数 1F 8B 08";
                return e;
            }
            e.Verified = true;
            e.Detail = "包缓存压缩归档（GZIP 头）校验通过";
            return e;
        }

        // 2b) Go 编译缓存 (%LOCALAPPDATA%\go-build)
        if (GoBuildEntryRegex.IsMatch(path))
        {
            if (len <= 0 || head == null || head.Length == 0)
            {
                e.Detail = "Go 编译缓存项为空";
                return e;
            }
            string forbidden = CheckForbiddenImportantHeader(head);
            if (forbidden != null)
            {
                e.Detail = "检测到非缓存文档/程序/数据库头：" + forbidden;
                return e;
            }
            string fileName = Path.GetFileName(path) ?? "";
            if (string.Equals(fileName, "trim.txt", StringComparison.OrdinalIgnoreCase))
            {
                if (len > 128 || !IsValidGoTrimTimestamp(head))
                {
                    e.Detail = "go-build trim.txt 内容不符合短时间戳格式";
                    return e;
                }
                e.Verified = true;
                e.Detail = "Go 编译缓存时间戳（trim.txt）校验通过";
                return e;
            }
            if (string.Equals(fileName, "README", StringComparison.OrdinalIgnoreCase))
            {
                if (len > 4096)
                {
                    e.Detail = "go-build README 体积超出预期上限";
                    return e;
                }
                e.Verified = true;
                e.Detail = "Go 编译缓存说明文件校验通过";
                return e;
            }
            e.Verified = true;
            e.Detail = "Go 编译缓存项（哈希分片与结构）校验通过";
            return e;
        }

        // 2c) Python uv 包缓存 (%LOCALAPPDATA%\uv\cache 下 .msgpack / .http；.whl 与 .tgz/.tar.gz 已由上方分支校验)
        if (UvCacheSubdirRegex.IsMatch(path) && (ext == ".msgpack" || ext == ".http"))
        {
            if (len <= 0 || head == null || head.Length == 0)
            {
                e.Detail = "uv 缓存元数据文件为空";
                return e;
            }
            string forbidden = CheckForbiddenImportantHeader(head);
            if (forbidden != null)
            {
                e.Detail = "检测到重要文档/SQLite/PE 头：" + forbidden;
                return e;
            }
            e.Verified = true;
            e.Detail = "Python uv 缓存项（" + ext + "）结构校验通过";
            return e;
        }

        // 3) pip HTTP 缓存体（%LOCALAPPDATA%\pip\cache\http 或 http-v2）
        if (PipHttpSubdirRegex.IsMatch(path))
        {
            if (len < 12 || head.Length < 12 || IsAllSameByte(head))
            {
                e.Detail = "pip HTTP 缓存文件过短或为空壳";
                return e;
            }
            string nonZipForbidden = CheckNonZipForbiddenHeader(head);
            if (nonZipForbidden != null)
            {
                e.Detail = "检测到非缓存文档/程序头：" + nonZipForbidden;
                return e;
            }
            if (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04))
            {
                string pipZipErr = CheckValidZipPackageHeader(head, len, true, streamOrNull, path);
                if (pipZipErr != null)
                {
                    e.Detail = "pip HTTP 缓存 ZIP 校验未通过：" + pipZipErr;
                    return e;
                }
                e.Verified = true;
                e.Detail = "pip HTTP 缓存条目（ZIP 包头）校验通过";
                return e;
            }
            bool okPip = StartsWithAscii(head, "cc=4")
                || (len >= 16 && ((head[0] >= 0x81 && head[0] <= 0x8F) || head[0] == 0xDE))
                || (len >= 18 && StartsWithBytes(head, 0x1F, 0x8B, 0x08))
                || (len >= 16 && (StartsWithAscii(head, "BZh") || StartsWithBytes(head, 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00)
                                  || StartsWithBytes(head, 0x28, 0xB5, 0x2F, 0xFD)))
                || (len >= 16 && (StartsWithJsonPayload(head) || StartsWithHtmlIndex(head)));
            if (!okPip)
            {
                e.Detail = "pip HTTP 缓存体不匹配序列化或压缩包格式";
                return e;
            }
            e.Verified = true;
            e.Detail = "pip HTTP 缓存条目头与响应格式校验通过";
            return e;
        }

        // 4) NuGet v3-cache .dat HTTP 缓存
        if (ext == ".dat" && NuGetCacheSubdirRegex.IsMatch(path))
        {
            if (len < 16 || head.Length < 16 || IsAllSameByte(head))
            {
                e.Detail = "NuGet HTTP 缓存文件不足 16 字节或为空壳";
                return e;
            }
            string nonZipForbidden = CheckNonZipForbiddenHeader(head);
            if (nonZipForbidden != null)
            {
                e.Detail = "检测到文档/程序/数据库头：" + nonZipForbidden;
                return e;
            }
            if (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04))
            {
                string nugetZipErr = CheckValidZipPackageHeader(head, len, true, streamOrNull, path);
                if (nugetZipErr != null)
                {
                    e.Detail = "NuGet .dat ZIP 校验未通过：" + nugetZipErr;
                    return e;
                }
                e.Verified = true;
                e.Detail = "NuGet v3 HTTP 缓存（.dat ZIP）结构校验通过";
                return e;
            }
            bool okNuGet = StartsWithJsonPayload(head)
                || StartsWithXmlFeed(head)
                || (len >= 18 && StartsWithBytes(head, 0x1F, 0x8B, 0x08))
                || (!StartsWithBytes(head, 0x50, 0x4B) && HasBinaryFraming(head, 16));
            if (!okNuGet)
            {
                e.Detail = "NuGet .dat 内容不匹配 JSON/XML/压缩或二进制缓存结构";
                return e;
            }
            e.Verified = true;
            e.Detail = "NuGet v3 HTTP 缓存（.dat）结构校验通过";
            return e;
        }

        // 5) Yarn (%LOCALAPPDATA%\Yarn\Cache) 与 pnpm (%LOCALAPPDATA%\pnpm-cache) 受控缓存项
        if (YarnPnpmCacheSubdirRegex.IsMatch(path))
        {
            if (len < 12 || head.Length < 12 || IsAllSameByte(head))
            {
                e.Detail = "Yarn/pnpm 缓存文件过短或为空壳";
                return e;
            }
            string nonZipForbidden = CheckNonZipForbiddenHeader(head);
            if (nonZipForbidden != null)
            {
                e.Detail = "检测到用户文档/程序/数据库头：" + nonZipForbidden;
                return e;
            }

            if (ext == ".zip")
            {
                string zipErr = CheckValidZipPackageHeader(head, len, true, streamOrNull, path);
                if (zipErr != null)
                {
                    e.Detail = "Yarn/pnpm .zip " + zipErr;
                    return e;
                }
                e.Verified = true;
                e.Detail = "Yarn/pnpm 压缩包缓存（ZIP PK 头）校验通过";
                return e;
            }

            if (ext == ".json")
            {
                if (!StartsWithJsonPayload(head))
                {
                    e.Detail = "Yarn/pnpm .json 不符合 JSON 元数据结构";
                    return e;
                }
                e.Verified = true;
                e.Detail = "Yarn/pnpm 包元数据缓存（JSON）校验通过";
                return e;
            }

            if (ext == ".dat")
            {
                if (len < 16 || head.Length < 16)
                {
                    e.Detail = "Yarn/pnpm .dat 缓存文件不足 16 字节";
                    return e;
                }
                bool okDat = (len >= 18 && StartsWithBytes(head, 0x1F, 0x8B, 0x08))
                    || (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04) && CheckValidZipPackageHeader(head, len, true, streamOrNull, path) == null)
                    || StartsWithJsonPayload(head)
                    || (!StartsWithBytes(head, 0x50, 0x4B) && HasBinaryFraming(head, 16));
                if (!okDat)
                {
                    e.Detail = "Yarn/pnpm .dat 不匹配 GZIP/ZIP/JSON 或二进制缓存结构";
                    return e;
                }
                e.Verified = true;
                e.Detail = "Yarn/pnpm 缓存数据（.dat）结构校验通过";
                return e;
            }

            // pnpm-cache 下无扩展名的压缩/元数据缓存块（校验 GZIP 1F 8B / ZIP PK\x03\x04 / JSON 元数据）
            if (ext.Length == 0)
            {
                bool okBlob = (len >= 18 && StartsWithBytes(head, 0x1F, 0x8B, 0x08))
                    || (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04) && CheckValidZipPackageHeader(head, len, true, streamOrNull, path) == null)
                    || StartsWithJsonPayload(head);
                if (!okBlob)
                {
                    e.Detail = "pnpm 缓存块不匹配 GZIP/ZIP 或 JSON 元数据头";
                    return e;
                }
                e.Verified = true;
                e.Detail = "pnpm 缓存数据块格式校验通过";
                return e;
            }
        }

        e.Detail = "路径或内容不符合 npm/pip/NuGet/Yarn/pnpm/go-build/uv 缓存结构";
        return e;
    }

    private static bool IsValidGoTrimTimestamp(byte[] head)
    {
        if (head == null || head.Length == 0) return false;
        int digits = 0;
        for (int i = 0; i < head.Length; i++)
        {
            byte b = head[i];
            if (b >= (byte)'0' && b <= (byte)'9') { digits++; continue; }
            if (b == (byte)' ' || b == (byte)'\r' || b == (byte)'\n' || b == (byte)'\t'
                || b == (byte)'.' || b == (byte)'-' || b == (byte)':' || b == (byte)'T' || b == (byte)'Z')
                continue;
            return false;
        }
        return digits >= 6;
    }

    private static string CheckValidZipPackageHeader(byte[] head, long len, bool rejectOfficeInnerDirs, Stream streamOrNull, string pathOrNull)
    {
        if (!StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04))
            return "文件头不匹配 ZIP 魔数 PK\\x03\\x04";
        if (len < 30 || head == null || head.Length < 30)
            return "ZIP 包头不足 30 字节，结构不完整";
        ushort fileNameLen = BitConverter.ToUInt16(head, 26);
        ushort extraFieldLen = BitConverter.ToUInt16(head, 28);
        if (fileNameLen == 0)
            return "ZIP 本地文件头条目名为空，结构不完整";
        if (30L + (long)fileNameLen + (long)extraFieldLen > len)
            return "ZIP 本地文件头记录长度越出文件边界";

        if (rejectOfficeInnerDirs)
        {
            if (IsOfficeDocumentZip(head))
                return "命中 Office 文档内部目录特征，拒绝作为缓存清理";

            bool isOpcFirst = IsOpcCandidateFirstEntry(head);
            if (streamOrNull != null)
            {
                if (IsOfficeOpcZipStream(streamOrNull, isOpcFirst, pathOrNull))
                    return "命中 Office OpenXML 文档包结构（Central Directory 含 word/xl/ppt/visio），拒绝作为缓存清理";
            }
            else if (!string.IsNullOrEmpty(pathOrNull))
            {
                if (IsOfficeOpcZipFile(pathOrNull, isOpcFirst))
                    return "命中 Office OpenXML 文档包结构（Central Directory 含 word/xl/ppt/visio），拒绝作为缓存清理";
            }
            else if (isOpcFirst)
            {
                return "命中 OPC 压缩包头且无法检查 Central Directory，保守拒绝清理";
            }
        }
        return null;
    }

    private static bool IsOfficeDocumentZip(byte[] head)
    {
        if (head == null || head.Length <= 30) return false;
        ushort nameLen = BitConverter.ToUInt16(head, 26);
        int avail = Math.Min((int)nameLen, head.Length - 30);
        if (avail <= 0) return false;
        string entry = Encoding.ASCII.GetString(head, 30, avail);
        return IsOfficeZipEntryName(entry);
    }

    private static bool IsOpcCandidateFirstEntry(byte[] head)
    {
        if (head == null || head.Length <= 30) return false;
        ushort nameLen = BitConverter.ToUInt16(head, 26);
        int avail = Math.Min((int)nameLen, head.Length - 30);
        if (avail <= 0) return false;
        string entry = Encoding.ASCII.GetString(head, 30, avail);
        return entry.StartsWith("[Content_Types].xml", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("_rels/", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("_rels\\", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("docProps/", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("docProps\\", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsOfficeZipEntryName(string entry)
    {
        if (string.IsNullOrEmpty(entry)) return false;
        return entry.StartsWith("word/", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("word\\", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("xl/", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("xl\\", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("ppt/", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("ppt\\", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("visio/", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("visio\\", StringComparison.OrdinalIgnoreCase)
            || string.Equals(entry, "mimetype", StringComparison.OrdinalIgnoreCase)
            || entry.StartsWith("mimetype", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsOfficeOpcZipFile(string path, bool failClosedOnUnreadable)
    {
        try
        {
            if (string.IsNullOrEmpty(path)) return failClosedOnUnreadable;
            using (FileStream fs = OpenNoReparseRead(path))
            {
                return IsOfficeOpcZipStream(fs, failClosedOnUnreadable, path);
            }
        }
        catch
        {
            return failClosedOnUnreadable;
        }
    }

    private static bool IsOfficeOpcZipStream(Stream s, bool failClosedOnMissingEocd, string pathOrNull)
    {
        if (s == null || !s.CanSeek) return failClosedOnMissingEocd;
        long savedPos = s.Position;
        try
        {
            long fileLen = s.Length;
            if (fileLen < 22) return failClosedOnMissingEocd;

            const int MinEocdLen = 22;
            const int MaxTailRead = 65536;
            const int MaxCdRead = 512 * 1024;
            const int MaxCdEntries = 4096;

            // 先只读末尾 22 字节快速定位无注释 EOCD；未命中再放宽到 64KB 尾部扫描，并将读取计入 HashBudget
            int tailLen = MinEocdLen;
            long tailStart = fileLen - tailLen;
            byte[] tail = new byte[tailLen];
            s.Position = tailStart;
            int tailRead = ReadExactUpTo(s, tail, tailLen);
            if (tailRead < 22) return failClosedOnMissingEocd;
            if (!ConsumeOpcBudget(tailRead)) return true;

            int eocdPos = -1;
            if (tail[0] == 0x50 && tail[1] == 0x4B && tail[2] == 0x05 && tail[3] == 0x06
                && BitConverter.ToUInt16(tail, 20) == 0)
            {
                eocdPos = 0;
            }
            else if (fileLen > MinEocdLen)
            {
                tailLen = (int)Math.Min(fileLen, (long)MaxTailRead);
                tailStart = fileLen - tailLen;
                tail = new byte[tailLen];
                s.Position = tailStart;
                tailRead = ReadExactUpTo(s, tail, tailLen);
                if (tailRead < 22) return failClosedOnMissingEocd;
                if (!ConsumeOpcBudget(tailRead)) return true;

                for (int pos = tailRead - 22; pos >= 0; pos--)
                {
                    if (tail[pos] == 0x50 && tail[pos + 1] == 0x4B && tail[pos + 2] == 0x05 && tail[pos + 3] == 0x06)
                    {
                        ushort commentLen = BitConverter.ToUInt16(tail, pos + 20);
                        if (pos + 22 + commentLen <= tailRead)
                        {
                            eocdPos = pos;
                            break;
                        }
                    }
                }
            }
            if (eocdPos < 0) return failClosedOnMissingEocd;

            ushort totalEntries = BitConverter.ToUInt16(tail, eocdPos + 10);
            uint cdSize = BitConverter.ToUInt32(tail, eocdPos + 12);
            uint cdOffset = BitConverter.ToUInt32(tail, eocdPos + 16);

            // ZIP64 哨兵（如 System.IO.Packaging 将 [Content_Types].xml 写在末尾）：
            // 若首条目已命中 OPC 则一律拒绝；否则仅允许已知非 Office 扩展名（.nupkg/.vsix/.whl）
            bool isZip64 = (totalEntries == 0xFFFF || cdSize == 0xFFFFFFFFu || cdOffset == 0xFFFFFFFFu);
            if (isZip64)
            {
                if (failClosedOnMissingEocd) return true;
                string zExt = "";
                try { zExt = string.IsNullOrEmpty(pathOrNull) ? "" : (Path.GetExtension(pathOrNull) ?? "").ToLowerInvariant(); } catch { zExt = ""; }
                if (zExt != ".nupkg" && zExt != ".vsix" && zExt != ".whl")
                    return true;
                return false;
            }

            // totalEntries==0 却声明非空 Central Directory 视为损坏/畸形，保守拒绝
            if (totalEntries == 0)
                return cdSize > 0 ? true : failClosedOnMissingEocd;
            if (cdSize == 0)
                return failClosedOnMissingEocd;
            if ((long)cdOffset + (long)cdSize > fileLen)
                return failClosedOnMissingEocd;

            int readCdLen = (int)Math.Min((long)cdSize, (long)MaxCdRead);
            byte[] cdBuf;
            int cdBufStart;
            if ((long)cdOffset >= tailStart && (long)cdOffset + readCdLen <= tailStart + tailRead)
            {
                cdBuf = tail;
                cdBufStart = (int)((long)cdOffset - tailStart);
            }
            else
            {
                cdBuf = new byte[readCdLen];
                s.Position = cdOffset;
                int got = ReadExactUpTo(s, cdBuf, readCdLen);
                if (!ConsumeOpcBudget(got)) return true;
                if (got < 46) return failClosedOnMissingEocd;
                readCdLen = got;
                cdBufStart = 0;
            }

            int p = cdBufStart;
            int end = cdBufStart + readCdLen;
            int scanned = 0;
            bool sawKnownNonOfficePkgMarker = false;
            int maxEntries = Math.Min((int)totalEntries, MaxCdEntries);

            while (p + 46 <= end && scanned < maxEntries)
            {
                if (cdBuf[p] != 0x50 || cdBuf[p + 1] != 0x4B || cdBuf[p + 2] != 0x01 || cdBuf[p + 3] != 0x02)
                {
                    return failClosedOnMissingEocd;
                }
                ushort nameLen = BitConverter.ToUInt16(cdBuf, p + 28);
                ushort extraLen = BitConverter.ToUInt16(cdBuf, p + 30);
                ushort commentLen = BitConverter.ToUInt16(cdBuf, p + 32);
                int entryTotal = 46 + nameLen + extraLen + commentLen;
                if (p + 46 + nameLen > end)
                    return failClosedOnMissingEocd;

                if (nameLen > 0)
                {
                    string entryName = Encoding.UTF8.GetString(cdBuf, p + 46, nameLen);
                    if (IsOfficeZipEntryName(entryName))
                        return true;
                    if (entryName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(entryName, "extension.vsixmanifest", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(entryName, "extension/package.json", StringComparison.OrdinalIgnoreCase))
                    {
                        sawKnownNonOfficePkgMarker = true;
                    }
                }

                scanned++;
                p += entryTotal;
            }

            // 若 OPC 压缩包的 Central Directory 未完全扫完（截断、超 512KB 或超 4096 项）且未见明确 .nupkg/.vsix 标识，保守拒绝
            if (failClosedOnMissingEocd && !sawKnownNonOfficePkgMarker
                && (cdSize > (uint)MaxCdRead || totalEntries > MaxCdEntries || scanned < (int)totalEntries))
            {
                return true;
            }

            return false;
        }
        catch
        {
            return failClosedOnMissingEocd;
        }
        finally
        {
            try { if (s.CanSeek) s.Position = savedPos; } catch { }
        }
    }

    private static int ReadExactUpTo(Stream s, byte[] buf, int count)
    {
        int read = 0;
        while (read < count)
        {
            int n = s.Read(buf, read, count - read);
            if (n <= 0) break;
            read += n;
        }
        return read;
    }

    // ---------- 6. 系统与软件临时文件（%LOCALAPPDATA%\Temp 下分级冷却与结构保护） ---------- //

    public static ContentEvidence VerifySystemTemp(string path, HashBudget budget, Func<bool> cancelled)
    {
        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 1, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifySystemTempBytesCore(path, head, len, null);
    }

    public static string VerifySystemTempStream(string path, Stream s)
    {
        if (s == null) return "文件流为空";
        byte[] head = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence ce = VerifySystemTempBytesCore(path, head, s.Length, s);
        return ce.Verified ? null : ce.Detail;
    }

    public static ContentEvidence VerifySystemTempBytes(string path, byte[] head, long len)
    {
        return VerifySystemTempBytesCore(path, head, len, null);
    }

    private static ContentEvidence VerifySystemTempBytesCore(string path, byte[] head, long len, Stream streamOrNull)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path))
        {
            e.Detail = "路径为空";
            return e;
        }

        // 直接调用防护：必须位于受控 Temp 路径或测试注入的 TMP-SYSTEMP 根目录内
        bool inTempScope = TempDirSegmentRegex.IsMatch(path) || PathGuard.IsInControlledRoot(path);
        if (!inTempScope && CacheRoots.HasInjectedForTest)
        {
            string matchedRule, matchedWhy;
            inTempScope = CacheRoots.Match(path, out matchedRule, out matchedWhy)
                && string.Equals(matchedRule, "TMP-SYSTEMP", StringComparison.Ordinal);
        }
        if (!inTempScope)
        {
            e.Detail = "不在受控系统或用户临时目录内";
            return e;
        }

        string name = Path.GetFileName(path);
        if (name == null) name = "";
        string ext = "";
        try { ext = (Path.GetExtension(name) ?? "").ToLowerInvariant(); } catch { ext = ""; }

        if (OfficeTempDraftNameRegex.IsMatch(name))
        {
            e.Detail = "命中 Office 临时草稿前缀（~$ / ~df / ~wr），拒绝授权";
            return e;
        }
        if (ArchivePreviewTempDirRegex.IsMatch(path))
        {
            e.Detail = "位于压缩包预览临时目录（7zO* / Rar$*），拒绝自动清理";
            return e;
        }

        DateTime lastWriteUtc;
        if (!TryGetLastWriteUtcFromStream(streamOrNull, path, out lastWriteUtc))
        {
            e.Detail = "无法从句柄安全读取文件修改时间";
            return e;
        }

        double ageHours = (DateTime.UtcNow - lastWriteUtc).TotalHours;
        if (len <= 0 || head == null || head.Length == 0)
        {
            e.Detail = "文件为空，无法确认内容";
            return e;
        }

        // 模式 3：Temp 专用安装器/更新器/浏览器/包管理解包沙盒子目录（满 48 小时 + 硬拦截个人创作与敏感数据头）
        if (TempInstallerSandboxSubdirRegex.IsMatch(path))
        {
            if (!IsAllowedInstallerSandboxExt(ext))
            {
                e.Detail = "扩展名不在专用安装临时沙盒白名单内";
                return e;
            }
            if (ageHours < 48.0)
            {
                e.Detail = "修改时间未满 48 小时";
                return e;
            }
            string personalForbidden = CheckInstallerSandboxForbiddenHeader(head, len, streamOrNull, path);
            if (personalForbidden != null)
            {
                e.Detail = "含受保护文档或程序头（" + personalForbidden + "）";
                return e;
            }
            e.Verified = true;
            e.Detail = "专用安装或解包临时残留已满 48 小时，且排除个人文档与敏感数据头";
            return e;
        }

        // 模式 1 & 2：普通 .tmp/.temp 或 Temp 目录下的 .log/.etl（满 24 小时 + 拒绝全部重要文档/程序/压缩包头）
        bool isTmpExt = (ext == ".tmp" || ext == ".temp");
        bool isTempLogExt = (ext == ".log" || ext == ".etl") && TempDirSegmentRegex.IsMatch(path);
        if (!isTmpExt && !isTempLogExt)
        {
            e.Detail = "扩展名或路径不符合系统临时文件规范";
            return e;
        }
        if (ageHours < 24.0)
        {
            e.Detail = "修改时间未满 24 小时";
            return e;
        }

        string forbidden = CheckForbiddenImportantHeader(head);
        if (forbidden != null)
        {
            e.Detail = "含受保护文档或程序头（" + forbidden + "）";
            return e;
        }

        e.Verified = true;
        e.Detail = isTempLogExt
            ? "临时诊断日志已满 24 小时，且无受保护文档或程序头"
            : "修改已满 24 小时，且无受保护文档或程序头";
        return e;
    }

    private static bool IsAllowedInstallerSandboxExt(string ext)
    {
        switch (ext)
        {
            case ".exe":
            case ".dll":
            case ".cab":
            case ".nupkg":
            case ".zip":
            case ".7z":
            case ".tgz":
            case ".pak":
            case ".dat":
            case ".bin":
            case ".json":
            case ".xml":
            case ".js":
            case ".css":
            case ".tmp":
            case ".temp":
            case ".log":
            case ".etl":
                return true;
            default:
                return false;
        }
    }

    private static string CheckInstallerSandboxForbiddenHeader(byte[] head, long len, Stream streamOrNull, string pathOrNull)
    {
        if (head == null || head.Length == 0) return null;
        if (StartsWithBytes(head, 0xD0, 0xCF, 0x11, 0xE0))
            return "Office OLE2 复合文档头";
        if (StartsWithAscii(head, "%PDF"))
            return "PDF 文档头";
        if (StartsWithAscii(head, "8BPS"))
            return "Photoshop PSD 文档头";
        if (StartsWithAscii(head, "SQLite format 3") || StartsWithAscii(head, "SQLite") || StartsWithSqliteWalMagic(head))
            return "SQLite 数据库或 WAL 头";
        if (StartsWithAscii(head, "-----BEGIN "))
            return "PEM 证书或私钥头";
        if (StartsWithKdbxMagic(head))
            return "KeePass 密码库头（KDBX）";
        if (StartsWithPkcs12Magic(head))
            return "PKCS#12 证书私钥头";
        if (StartsWithAscii(head, "regf"))
            return "注册表配置单元头";
        if (StartsWithAscii(head, "{\\rtf"))
            return "RTF 文档头";
        if (StartsWithBytes(head, 0x52, 0x61, 0x72, 0x21))
            return "RAR 压缩包头";

        if (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04))
        {
            string zipCheck = CheckValidZipPackageHeader(head, len, true, streamOrNull, pathOrNull);
            if (zipCheck != null) return zipCheck;
        }
        else if (StartsWithBytes(head, 0x50, 0x4B, 0x05, 0x06)
                 || StartsWithBytes(head, 0x50, 0x4B, 0x07, 0x08))
        {
            return "空或分卷 ZIP 头（PK）";
        }
        return null;
    }

    // ---------- 7. Windows 错误报告历史（%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive|ReportQueue） ---------- //

    public static ContentEvidence VerifyWer(string path, HashBudget budget, Func<bool> cancelled)
    {
        string ext = "";
        try { ext = (Path.GetExtension(path) ?? "").ToLowerInvariant(); } catch { ext = ""; }
        if (ext == ".dmp" || ext == ".mdmp" || ext == ".hdmp")
        {
            return VerifyCrashDump(path, budget, cancelled);
        }

        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 8, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifyWerBytesCore(path, head, len, null);
    }

    public static string VerifyWerStream(string path, Stream s)
    {
        if (s == null) return "文件流为空";
        byte[] head = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence ce = VerifyWerBytesCore(path, head, s.Length, s);
        return ce.Verified ? null : ce.Detail;
    }

    public static ContentEvidence VerifyWerBytes(string path, byte[] head, long len)
    {
        return VerifyWerBytesCore(path, head, len, null);
    }

    private static ContentEvidence VerifyWerBytesCore(string path, byte[] head, long len, Stream streamOrNull)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path)) { e.Detail = "路径为空"; return e; }
        if (head == null || head.Length < 8) { e.Detail = "文件不足 8 字节，结构不完整"; return e; }

        string ext = "";
        try { ext = (Path.GetExtension(path) ?? "").ToLowerInvariant(); } catch { ext = ""; }

        if (ext == ".wer")
        {
            if (len < 12 || head.Length < 10)
            {
                e.Detail = "WER 报告文件过短，结构不完整";
                return e;
            }
            if (head[0] == 0xFF && head[1] == 0xFE)
            {
                int evenBytes = (head.Length - 2) & ~1;
                if (evenBytes <= 0)
                {
                    e.Detail = "UTF-16LE WER 头内容为空";
                    return e;
                }
                string u16 = Encoding.Unicode.GetString(head, 2, evenBytes);
                if (!ContainsWerHeaderMarker(u16))
                {
                    e.Detail = "UTF-16LE 文本未匹配 Version= / EventType= / Sig[ 标识";
                    return e;
                }
                e.Verified = true;
                e.Detail = "Windows 错误报告（UTF-16LE .wer）结构校验通过";
                return e;
            }

            string forbidden = CheckForbiddenImportantHeader(head);
            if (forbidden != null)
            {
                e.Detail = "检测到非 WER 报告头：" + forbidden;
                return e;
            }
            int offset = SkipUtf8BomAndWhitespace(head);
            if (offset >= head.Length)
            {
                e.Detail = "WER 报告内容为空白";
                return e;
            }
            string utf8 = Encoding.UTF8.GetString(head, offset, head.Length - offset);
            if (!ContainsWerHeaderMarker(utf8))
            {
                e.Detail = "文本头未匹配 Version= / EventType= / Sig[ 标识";
                return e;
            }
            e.Verified = true;
            e.Detail = "Windows 错误报告（.wer）结构校验通过";
            return e;
        }

        if (ext == ".cab")
        {
            if (len < 36 || head.Length < 4 || !StartsWithBytes(head, 0x4D, 0x53, 0x43, 0x46))
            {
                e.Detail = "文件头不匹配 Microsoft Cabinet 魔数 MSCF（或不足 36 字节）";
                return e;
            }
            e.Verified = true;
            e.Detail = "WER 诊断归档（MSCF .cab）魔数与长度校验通过";
            return e;
        }

        if (ext == ".dmp" || ext == ".mdmp" || ext == ".hdmp")
        {
            if (streamOrNull != null)
            {
                try
                {
                    return VerifyCrashDumpBytes(head, len, streamOrNull);
                }
                catch (Exception ex)
                {
                    e.Detail = "读取 WER 转储流失败：" + ex.GetType().Name;
                    return e;
                }
            }
            try
            {
                using (FileStream fs = OpenNoReparseRead(path))
                {
                    return VerifyCrashDumpBytes(head, fs.Length, fs);
                }
            }
            catch
            {
                e.Detail = "无法打开 WER 转储文件进行完整 MDMP 流目录校验";
                return e;
            }
        }

        e.Detail = "扩展名不在 WER 报告白名单（.wer / .cab / .dmp / .mdmp / .hdmp）内";
        return e;
    }

    private static bool ContainsWerHeaderMarker(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return text.IndexOf("Version=", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("EventType=", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("Sig[", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    // ---------- 8. 微信 / 企业微信 / QQ 纯缓存（朋友圈 Sns\Cache、Applet 小程序、xweb / CefCache / webkit_cache / nt_temp） ---------- //

    public static ContentEvidence VerifyChatCache(string path, HashBudget budget, Func<bool> cancelled)
    {
        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 16, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifyChatCacheBytesCore(path, head, len, null);
    }

    public static string VerifyChatCacheStream(string path, Stream s)
    {
        if (s == null) return "文件流为空";
        byte[] head = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence ce = VerifyChatCacheBytesCore(path, head, s.Length, s);
        return ce.Verified ? null : ce.Detail;
    }

    public static ContentEvidence VerifyChatCacheBytes(string path, byte[] head, long len)
    {
        return VerifyChatCacheBytesCore(path, head, len, null);
    }

    private static ContentEvidence VerifyChatCacheBytesCore(string path, byte[] head, long len, Stream streamOrNull)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path))
        {
            e.Detail = "路径为空";
            return e;
        }

        // 第一步硬性拦截：聊天数据库与聊天接收/收藏/表情/原图原视频目录一律拒绝！
        if (ChatStorageLocator.IsChatProtectedUserContent(path))
        {
            e.Detail = "命中聊天核心数据库或聊天接收原件保护目录，严禁清理";
            return e;
        }

        string name = Path.GetFileName(path) ?? "";
        if (CacheRoots.IsBrowserProtectedPath(name, path))
        {
            e.Detail = "命中受保护凭据或会话存储名称，严禁清理";
            return e;
        }
        if (OfficeTempDraftNameRegex.IsMatch(name))
        {
            e.Detail = "命中临时文档草稿前缀，拒绝清理";
            return e;
        }

        string ext = "";
        try { ext = (Path.GetExtension(name) ?? "").ToLowerInvariant(); } catch { ext = ""; }
        if (IsForbiddenChatCacheExtension(ext))
        {
            e.Detail = "锁文件、数据库、凭据私钥、程序模块或配置文件不作为聊天缓存清理";
            return e;
        }

        bool inSnsCache = ChatSnsCacheSubdirRegex.IsMatch(path);
        bool inWebOrApplet = !inSnsCache && ChatWebOrAppletSubdirRegex.IsMatch(path);
        bool inInjectedChatRoot = false;
        if (!inSnsCache && !inWebOrApplet && CacheRoots.HasInjectedForTest)
        {
            string matchedRule, matchedWhy;
            inInjectedChatRoot = CacheRoots.Match(path, out matchedRule, out matchedWhy)
                && string.Equals(matchedRule, "TMP-CHATCACHE", StringComparison.Ordinal);
        }

        if (!inSnsCache && !inWebOrApplet && !inInjectedChatRoot)
        {
            e.Detail = "不在受控聊天软件纯缓存子目录内";
            return e;
        }

        if (len < 16 || head == null || head.Length < 16)
        {
            e.Detail = "聊天缓存文件不足 16 字节，结构不完整";
            return e;
        }
        if (IsAllSameByte(head))
        {
            e.Detail = "文件头全为同一填充字节，疑似伪造空壳";
            return e;
        }

        // 分支 A：朋友圈纯缓存（Sns\Cache 或 Cache\Sns）
        if (inSnsCache)
        {
            string snsForbidden = CheckSnsCacheForbiddenHeader(head);
            if (snsForbidden != null)
            {
                e.Detail = "检测到非朋友圈缓存的受保护文档或程序头：" + snsForbidden;
                return e;
            }
            string mediaDesc = MatchChatMediaMagic(head);
            if (mediaDesc != null)
            {
                e.Verified = true;
                e.Detail = "朋友圈媒体缓存（" + mediaDesc + "）结构校验通过";
                return e;
            }
            if (!StartsWithTextBom(head) && HasBinaryFraming(head, Math.Min(head.Length, 24)))
            {
                e.Verified = true;
                e.Detail = "朋友圈加密媒体缓存块（二进制帧头）校验通过";
                return e;
            }
            e.Detail = "内容为纯文本或未知结构，不符合朋友圈媒体缓存特征";
            return e;
        }

        // 分支 B：小程序（.wxapkg / Applet）与内置网页/插件缓存（WMPFRuntime / XPlugin / xweb / CefCache / webkit_cache / nt_temp）
        string appletForbidden = CheckChatAppletOrWebForbiddenHeader(head, len, streamOrNull, path);
        if (appletForbidden != null)
        {
            e.Detail = "检测到受保护文档、数据库或程序头：" + appletForbidden;
            return e;
        }

        if (ext == ".wxapkg")
        {
            if (StartsWithAscii(head, "V1MMWX")
                || (head[0] == 0xBE && head.Length >= 14 && head[13] == 0xED)
                || (!StartsWithTextBom(head) && HasBinaryFraming(head, Math.Min(head.Length, 24))))
            {
                e.Verified = true;
                e.Detail = "微信小程序运行包（.wxapkg）结构校验通过";
                return e;
            }
            e.Detail = ".wxapkg 文件内容为纯文本，不具备小程序二进制包特征";
            return e;
        }

        // Chromium Blockfile 独立块 f_xxxxxx
        if (BrowserBlockfileShardNameRegex.IsMatch(name))
        {
            string parentDir = TryGetParentDir(path);
            if (HasValidBlockfilePool(parentDir)
                || (!StartsWithTextBom(head) && HasBinaryFraming(head, Math.Min(head.Length, 24)))
                || MatchChatMediaMagic(head) != null
                || StartsWithBytes(head, 0x1F, 0x8B, 0x08))
            {
                e.Verified = true;
                e.Detail = "聊天软件内置网页缓存块（Blockfile）校验通过";
                return e;
            }
        }

        // Chromium Simple Cache / Blockfile index & data_* / V8 Code Cache
        if (len >= 24 && head.Length >= 24 && BitConverter.ToUInt64(head, 0) == 0xfcfb6d1ba7725c30UL)
        {
            e.Verified = true;
            e.Detail = "聊天软件内置网页缓存（Simple Cache）校验通过";
            return e;
        }

        uint m32 = BitConverter.ToUInt32(head, 0);
        if (len >= 32 && head.Length >= 32 && (m32 == 0xc103cac3u || m32 == 0xc104cac3u))
        {
            RecordConfirmedBlockfileDir(TryGetParentDir(path));
            e.Verified = true;
            e.Detail = "聊天软件内置网页缓存池（0x" + m32.ToString("x8") + "）校验通过";
            return e;
        }

        if (string.Equals(name, "index", StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, "the-real-index", StringComparison.OrdinalIgnoreCase))
        {
            if (BitConverter.ToUInt64(head, 0) == 0x656e74657220796fUL
                || BitConverter.ToUInt64(head, 0) == 0xfcfb6d1ba7725c30UL
                || ContainsUInt64Magic(head, 0x656e74657220796fUL))
            {
                e.Verified = true;
                e.Detail = "聊天软件内置网页缓存索引结构校验通过";
                return e;
            }
        }

        string chatMedia = MatchChatMediaMagic(head);
        if (chatMedia != null)
        {
            e.Verified = true;
            e.Detail = "聊天软件纯缓存媒体项（" + chatMedia + "）校验通过";
            return e;
        }

        if ((len >= 18 && StartsWithBytes(head, 0x1F, 0x8B, 0x08))
            || (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04) && CheckValidZipPackageHeader(head, len, true, streamOrNull, path) == null)
            || (!StartsWithTextBom(head) && HasBinaryFraming(head, Math.Min(head.Length, 24))))
        {
            e.Verified = true;
            e.Detail = "聊天软件纯缓存二进制数据块校验通过";
            return e;
        }

        e.Detail = "内容为纯文本或未知结构，不符合聊天软件纯缓存特征";
        return e;
    }

    private static bool IsForbiddenChatCacheExtension(string ext)
    {
        switch (ext)
        {
            case ".lock":
            case ".lck":
            case ".lockfile":
            case ".db":
            case ".db-wal":
            case ".db-shm":
            case ".db-journal":
            case ".sqlite":
            case ".sqlite3":
            case ".sqlite-wal":
            case ".sqlite-shm":
            case ".exe":
            case ".dll":
            case ".sys":
            case ".ini":
            case ".cfg":
            case ".config":
            case ".key":
            case ".pem":
            case ".pfx":
            case ".p12":
            case ".cer":
            case ".crt":
            case ".env":
            case ".kdbx":
                return true;
            default:
                return false;
        }
    }

    private static string CheckSnsCacheForbiddenHeader(byte[] head)
    {
        if (StartsWithBytes(head, 0xD0, 0xCF, 0x11, 0xE0))
            return "Office OLE2 复合文档头";
        if (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04)
            || StartsWithBytes(head, 0x50, 0x4B, 0x05, 0x06)
            || StartsWithBytes(head, 0x50, 0x4B, 0x07, 0x08))
            return "ZIP 或 Office OpenXML 压缩包头（PK）";
        if (StartsWithAscii(head, "%PDF"))
            return "PDF 文档头";
        if (StartsWithAscii(head, "SQLite format 3") || StartsWithAscii(head, "SQLite") || StartsWithSqliteWalMagic(head))
            return "SQLite 数据库或 WAL 头";
        if (StartsWithBytes(head, 0x4D, 0x5A))
            return "PE 可执行程序或动态库头（MZ）";
        if (StartsWithBytes(head, 0x52, 0x61, 0x72, 0x21))
            return "RAR 压缩包头";
        if (StartsWithBytes(head, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))
            return "7z 压缩包头";
        if (StartsWithAscii(head, "{\\rtf"))
            return "RTF 文档头";
        if (StartsWithAscii(head, "8BPS"))
            return "Photoshop PSD 文档头";
        if (StartsWithAscii(head, "-----BEGIN "))
            return "PEM 证书或私钥头";
        if (StartsWithKdbxMagic(head))
            return "KeePass 密码库头（KDBX）";
        if (StartsWithPkcs12Magic(head))
            return "PKCS#12 证书私钥头";
        if (StartsWithAscii(head, "regf"))
            return "注册表配置单元头";
        return null;
    }

    private static string CheckChatAppletOrWebForbiddenHeader(byte[] head, long len, Stream streamOrNull, string pathOrNull)
    {
        if (StartsWithBytes(head, 0xD0, 0xCF, 0x11, 0xE0))
            return "Office OLE2 复合文档头";
        if (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04))
        {
            string zipErr = CheckValidZipPackageHeader(head, len, true, streamOrNull, pathOrNull);
            if (zipErr != null)
                return zipErr;
        }
        else if (StartsWithBytes(head, 0x50, 0x4B, 0x05, 0x06)
                 || StartsWithBytes(head, 0x50, 0x4B, 0x07, 0x08))
        {
            return "空或分卷 ZIP 头（PK）";
        }
        if (StartsWithAscii(head, "%PDF"))
            return "PDF 文档头";
        if (StartsWithAscii(head, "SQLite format 3") || StartsWithAscii(head, "SQLite") || StartsWithSqliteWalMagic(head))
            return "SQLite 数据库或 WAL 头";
        if (StartsWithBytes(head, 0x4D, 0x5A))
            return "PE 可执行程序或动态库头（MZ）";
        if (StartsWithBytes(head, 0x52, 0x61, 0x72, 0x21))
            return "RAR 压缩包头";
        if (StartsWithBytes(head, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))
            return "7z 压缩包头";
        if (StartsWithAscii(head, "{\\rtf"))
            return "RTF 文档头";
        if (StartsWithAscii(head, "8BPS"))
            return "Photoshop PSD 文档头";
        if (StartsWithAscii(head, "-----BEGIN "))
            return "PEM 证书或私钥头";
        if (StartsWithKdbxMagic(head))
            return "KeePass 密码库头（KDBX）";
        if (StartsWithPkcs12Magic(head))
            return "PKCS#12 证书私钥头";
        if (StartsWithAscii(head, "regf"))
            return "注册表配置单元头";
        return null;
    }

    private static string MatchChatMediaMagic(byte[] head)
    {
        if (head == null || head.Length < 12) return null;
        if (StartsWithBytes(head, 0xFF, 0xD8, 0xFF))
            return "JPEG 图像头";
        if (StartsWithBytes(head, 0x89, 0x50, 0x4E, 0x47))
            return "PNG 图像头";
        if (StartsWithAscii(head, "GIF87a") || StartsWithAscii(head, "GIF89a"))
            return "GIF 图像头";
        if (StartsWithAscii(head, "RIFF")
            && head[8] == (byte)'W' && head[9] == (byte)'E' && head[10] == (byte)'B' && head[11] == (byte)'P')
            return "WebP 图像头";
        if (head[4] == (byte)'f' && head[5] == (byte)'t' && head[6] == (byte)'y' && head[7] == (byte)'p')
            return "MP4 媒体容器头";
        return null;
    }

    // ---------- 9. Windows 更新下载缓存（%WINDIR%\SoftwareDistribution\Download；满 48 小时且严禁触碰 DataStore） ---------- //

    public static ContentEvidence VerifyWinUpdate(string path, HashBudget budget, Func<bool> cancelled)
    {
        byte[] head; long len; string fail;
        if (!ReadStructuredHead(path, 16, budget, cancelled, out head, out len, out fail))
            return new ContentEvidence { Kind = EvidenceKind.MagicHeader, Detail = fail };
        return VerifyWinUpdateBytesCore(path, head, len, null);
    }

    public static string VerifyWinUpdateStream(string path, Stream s)
    {
        if (s == null) return "文件流为空";
        byte[] head = ReadStreamHead(s, StructuredHeadBytes);
        ContentEvidence ce = VerifyWinUpdateBytesCore(path, head, s.Length, s);
        return ce.Verified ? null : ce.Detail;
    }

    public static ContentEvidence VerifyWinUpdateBytes(string path, byte[] head, long len)
    {
        return VerifyWinUpdateBytesCore(path, head, len, null);
    }

    private static ContentEvidence VerifyWinUpdateBytesCore(string path, byte[] head, long len, Stream streamOrNull)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.MagicHeader;
        if (string.IsNullOrEmpty(path))
        {
            e.Detail = "路径为空";
            return e;
        }

        if (WinUpdateDataStoreSubdirRegex.IsMatch(path))
        {
            e.Detail = "命中 Windows Update DataStore 数据库目录，严禁清理";
            return e;
        }

        bool inSdDownload = WinUpdateDownloadSubdirRegex.IsMatch(path);
        bool inInjectedWinUpd = false;
        if (!inSdDownload && CacheRoots.HasInjectedForTest)
        {
            string matchedRule, matchedWhy;
            inInjectedWinUpd = CacheRoots.Match(path, out matchedRule, out matchedWhy)
                && string.Equals(matchedRule, "TMP-WINUPDATE", StringComparison.Ordinal);
        }
        if (!inSdDownload && !inInjectedWinUpd)
        {
            e.Detail = "不在 SoftwareDistribution\\Download 受控目录内";
            return e;
        }

        string name = Path.GetFileName(path) ?? "";
        if (OfficeTempDraftNameRegex.IsMatch(name))
        {
            e.Detail = "命中临时文档草稿前缀，拒绝清理";
            return e;
        }
        string ext = "";
        try { ext = (Path.GetExtension(name) ?? "").ToLowerInvariant(); } catch { ext = ""; }
        if (IsForbiddenWinUpdateExtension(ext))
        {
            e.Detail = "文档、证书、媒体、锁文件或数据库文件不作为系统更新缓存清理";
            return e;
        }

        DateTime lastWriteUtc;
        if (!TryGetLastWriteUtcFromStream(streamOrNull, path, out lastWriteUtc))
        {
            e.Detail = "无法从句柄安全读取文件修改时间";
            return e;
        }

        double ageHours = (DateTime.UtcNow - lastWriteUtc).TotalHours;
        if (ageHours < 48.0)
        {
            e.Detail = "修改时间未满 48 小时";
            return e;
        }

        if (len < 16 || head == null || head.Length < 16)
        {
            e.Detail = "文件不足 16 字节，结构不完整";
            return e;
        }
        if (IsAllSameByte(head))
        {
            e.Detail = "文件头全为同一填充字节，疑似伪造空壳";
            return e;
        }

        string forbidden = CheckWinUpdateForbiddenHeader(head, len, streamOrNull, path);
        if (forbidden != null)
        {
            e.Detail = "检测到个人创作文档或受保护数据库头：" + forbidden;
            return e;
        }

        if (StartsWithBytes(head, 0x4D, 0x53, 0x43, 0x46))
        {
            e.Verified = true;
            e.Detail = "Windows Update Cabinet 安装包（MSCF 头，已满 48 小时）校验通过";
            return e;
        }

        if (StartsWithAscii(head, "MSWIM"))
        {
            e.Verified = true;
            e.Detail = "Windows Update 映像包（MSWIM/ESD 头，已满 48 小时）校验通过";
            return e;
        }

        if (StartsWithBytes(head, 0x4D, 0x5A))
        {
            e.Verified = true;
            e.Detail = "Windows Update 安装组件（PE MZ 头，已满 48 小时）校验通过";
            return e;
        }

        if (StartsWithJsonPayload(head) || StartsWithWinUpdateXmlManifest(head, streamOrNull, path))
        {
            e.Verified = true;
            e.Detail = "Windows Update 更新清单（XML/JSON 结构，已满 48 小时）校验通过";
            return e;
        }

        if (StartsWithAscii(head, "PSTREAM")
            || StartsWithAscii(head, "PA30")
            || StartsWithAscii(head, "PA19")
            || (len >= 18 && StartsWithBytes(head, 0x1F, 0x8B, 0x08))
            || (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04) && CheckValidZipPackageHeader(head, len, true, streamOrNull, path) == null)
            || (!StartsWithTextBom(head) && HasBinaryFraming(head, Math.Min(head.Length, 24))))
        {
            e.Verified = true;
            e.Detail = "Windows Update 补丁数据块（二进制结构，已满 48 小时）校验通过";
            return e;
        }

        e.Detail = "内容不匹配 Windows Update 安装包、补丁块或更新清单格式";
        return e;
    }

    private static bool IsForbiddenWinUpdateExtension(string ext)
    {
        switch (ext)
        {
            case ".lock":
            case ".lck":
            case ".lockfile":
            case ".edb":
            case ".docx":
            case ".doc":
            case ".xlsx":
            case ".xls":
            case ".pptx":
            case ".ppt":
            case ".pdf":
            case ".psd":
            case ".rtf":
            case ".pfx":
            case ".p12":
            case ".cer":
            case ".crt":
            case ".key":
            case ".pem":
            case ".kdbx":
            case ".jpg":
            case ".jpeg":
            case ".png":
            case ".gif":
            case ".bmp":
            case ".webp":
            case ".heic":
            case ".mp4":
            case ".mov":
            case ".avi":
            case ".mkv":
            case ".sqlite":
            case ".sqlite3":
            case ".sqlite-wal":
            case ".sqlite-shm":
            case ".db":
            case ".db-wal":
            case ".db-shm":
            case ".db-journal":
                return true;
            default:
                return false;
        }
    }

    private static string CheckWinUpdateForbiddenHeader(byte[] head, long len, Stream streamOrNull, string pathOrNull)
    {
        if (StartsWithBytes(head, 0xD0, 0xCF, 0x11, 0xE0))
            return "Office OLE2 复合文档头";
        if (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04))
        {
            string zipCheck = CheckValidZipPackageHeader(head, len, true, streamOrNull, pathOrNull);
            if (zipCheck != null)
                return zipCheck;
        }
        else if (StartsWithBytes(head, 0x50, 0x4B, 0x05, 0x06)
                 || StartsWithBytes(head, 0x50, 0x4B, 0x07, 0x08))
        {
            return "空或分卷 ZIP 头（PK）";
        }
        if (StartsWithAscii(head, "%PDF"))
            return "PDF 文档头";
        if (StartsWithAscii(head, "8BPS"))
            return "Photoshop PSD 文档头";
        if (StartsWithAscii(head, "SQLite format 3") || StartsWithAscii(head, "SQLite") || StartsWithSqliteWalMagic(head))
            return "SQLite 数据库或 WAL 头";
        if (StartsWithEseDbMagic(head))
            return "Windows ESE (DataStore.edb) 数据库头";
        if (StartsWithKdbxMagic(head))
            return "KeePass 密码库头（KDBX）";
        if (StartsWithPkcs12Magic(head))
            return "PKCS#12 证书私钥头";
        if (StartsWithBytes(head, 0x89, 0x50, 0x4E, 0x47))
            return "PNG 图像头";
        if (StartsWithBytes(head, 0xFF, 0xD8, 0xFF))
            return "JPEG 图像头";
        if (StartsWithAscii(head, "GIF87a") || StartsWithAscii(head, "GIF89a"))
            return "GIF 图像头";
        if (head.Length >= 12 && StartsWithAscii(head, "RIFF")
            && head[8] == (byte)'W' && head[9] == (byte)'E' && head[10] == (byte)'B' && head[11] == (byte)'P')
            return "WebP 图像头";
        if (head.Length >= 12 && head[4] == (byte)'f' && head[5] == (byte)'t' && head[6] == (byte)'y' && head[7] == (byte)'p')
            return "MP4 媒体容器头";
        if (StartsWithAscii(head, "-----BEGIN "))
            return "PEM 证书或私钥头";
        if (StartsWithAscii(head, "regf"))
            return "注册表配置单元头";
        if (StartsWithAscii(head, "{\\rtf"))
            return "RTF 文档头";
        if (StartsWithBytes(head, 0x52, 0x61, 0x72, 0x21))
            return "RAR 压缩包头";
        if (StartsWithBytes(head, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))
            return "7z 压缩包头";
        return null;
    }

    private static bool StartsWithTextBom(byte[] head)
    {
        return StartsWithBytes(head, 0xEF, 0xBB, 0xBF)
            || StartsWithBytes(head, 0xFF, 0xFE)
            || StartsWithBytes(head, 0xFE, 0xFF);
    }

    private static bool ContainsWinUpdateXmlTag(string text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return text.IndexOf("<Update", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("<Package", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("<assembly", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("<unattend", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("<Deployment", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("<WindowsUpdate", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("<Manifest", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("<Metadata", StringComparison.OrdinalIgnoreCase) >= 0
            || text.IndexOf("schemas.microsoft.com", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool StartsWithWinUpdateXmlManifest(byte[] head, Stream streamOrNull, string pathOrNull)
    {
        if (head == null || head.Length < 6) return false;
        byte[] sample = head;
        if (head.Length < 256)
        {
            if (streamOrNull != null && streamOrNull.CanSeek)
            {
                long saved = streamOrNull.Position;
                try
                {
                    sample = ReadStreamHead(streamOrNull, 256);
                }
                catch { sample = head; }
                finally
                {
                    try { streamOrNull.Position = saved; } catch { }
                }
            }
            else if (!string.IsNullOrEmpty(pathOrNull))
            {
                try { sample = ReadHead(pathOrNull, 256); }
                catch { sample = head; }
            }
        }

        if (sample.Length >= 10 && sample[0] == 0xFF && sample[1] == 0xFE)
        {
            int even = (sample.Length - 2) & ~1;
            if (even < 8) return false;
            string u16 = Encoding.Unicode.GetString(sample, 2, even).TrimStart();
            if (!u16.StartsWith("<", StringComparison.Ordinal)) return false;
            return ContainsWinUpdateXmlTag(u16);
        }
        int i = SkipUtf8BomAndWhitespace(sample);
        if (i + 5 > sample.Length || sample[i] != (byte)'<') return false;
        string s = Encoding.UTF8.GetString(sample, i, sample.Length - i);
        return ContainsWinUpdateXmlTag(s);
    }

    // ---------- cacache：结构 + 内容 SHA-512 哈希 ---------- //

    public static ContentEvidence VerifyCacache(string path)
    {
        return VerifyCacache(path, null, null);
    }

    public static ContentEvidence VerifyCacache(string path, HashBudget budget, Func<bool> cancelled)
    {
        ContentEvidence e = new ContentEvidence();
        e.Kind = EvidenceKind.ContentAddressedHash;

        if (cancelled != null && cancelled()) { e.Detail = "内容校验已取消，未校验"; return e; }

        string expected;
        if (!TryParseCacachePath(path, out expected))
        {
            e.Detail = "路径不符合 cacache content-v2/sha512/xx/yy/<hash> 结构";
            return e;
        }

        long len;
        DateTime mtimeBefore;
        try
        {
            if (PathGuard.HasAnyReparseComponent(path)) { e.Detail = "路径包含重解析点，未校验"; return e; }
            FileInfo before = new FileInfo(path);
            if (!before.Exists || (before.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            {
                e.Detail = "目标不存在或为重解析点";
                return e;
            }
            len = before.Length;
            mtimeBefore = before.LastWriteTimeUtc;
        }
        catch { e.Detail = "无法读取文件信息"; return e; }
        if (len > MaxHashBytes) { e.Detail = "文件超过哈希校验上限（" + MaxHashBytes + " 字节）"; return e; }

        HashBudget b = budget == null ? HashBudget.Unlimited : budget;
        long charge = Math.Max(len, (long)StructuredHeadBytes);
        if (!b.TryConsume(charge))
        {
            e.Detail = "内容校验字节预算不足（本次需 " + charge + " 字节，剩余 " + b.Remaining + "），未校验";
            return e;
        }

        string actual, fail;
        long maxRead = Math.Min(len, MaxHashBytes);
        if (!TryHashFileChunked(path, maxRead, cancelled, out actual, out fail)) { e.Detail = fail; return e; }

        try
        {
            FileInfo after = new FileInfo(path);
            if (!after.Exists || (after.Attributes & FileAttributes.ReparsePoint) != 0 || after.Length != len ||
                Math.Abs((after.LastWriteTimeUtc - mtimeBefore).TotalSeconds) > 2)
            {
                e.Detail = "校验期间文件发生变化，未校验";
                return e;
            }
        }
        catch { e.Detail = "校验后无法复核文件状态，未校验"; return e; }

        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            e.Detail = "内容哈希与文件名不符（文件名 " + expected.Substring(0, 16) + "… vs 实际 "
                     + actual.Substring(0, 16) + "…）";
            return e;
        }

        e.Verified = true;
        e.Detail = "SHA-512 内容哈希与文件名一致（" + expected.Substring(0, 16) + "…）";
        return e;
    }

    public static bool TryHashFileChunked(string path, Func<bool> cancelled, out string hex, out string fail)
    {
        return TryHashFileChunked(path, MaxHashBytes, cancelled, out hex, out fail);
    }

    public static bool TryHashFileChunked(string path, long maxBytes, Func<bool> cancelled, out string hex, out string fail)
    {
        hex = "";
        fail = "";
        if (maxBytes < 0) maxBytes = 0;
        byte[] buf = new byte[HashChunkBytes];
        try
        {
            using (FileStream fs = OpenNoReparseRead(path))
            using (SHA512 sha = SHA512.Create())
            {
                long totalRead = 0;
                while (true)
                {
                    if (cancelled != null && cancelled()) { fail = "内容校验已取消，未校验"; return false; }
                    int n = fs.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    totalRead += n;
                    if (totalRead > maxBytes)
                    {
                        fail = "文件超过哈希校验上限（读取中体积增长），未校验";
                        return false;
                    }
                    sha.TransformBlock(buf, 0, n, null, 0);
                }
                sha.TransformFinalBlock(new byte[0], 0, 0);
                byte[] digest = sha.Hash;
                StringBuilder sb = new StringBuilder(digest.Length * 2);
                foreach (byte x in digest) sb.Append(x.ToString("x2"));
                hex = sb.ToString();
                return true;
            }
        }
        catch (Exception ex)
        {
            fail = "哈希计算失败：" + ex.GetType().Name;
            return false;
        }
    }

    public static bool TryParseCacachePath(string path, out string expectedHash)
    {
        expectedHash = "";
        string canon = PathGuard.Canonical(path);
        if (canon.Length == 0) return false;
        string[] p = canon.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        int n = p.Length;
        if (n < 6) return false;

        string name = p[n - 1], yy = p[n - 2], xx = p[n - 3];
        if (!string.Equals(p[n - 4], "sha512", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(p[n - 5], "content-v2", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(p[n - 6], "_cacache", StringComparison.OrdinalIgnoreCase)) return false;

        if (name.Length != 124 || !IsHex(name)) return false;
        if (xx.Length != 2 || !IsHex(xx)) return false;
        if (yy.Length != 2 || !IsHex(yy)) return false;

        expectedHash = xx + yy + name;
        return true;
    }

    // ---------- 公共底层辅助 ---------- //

    private static FileStream OpenNoReparseRead(string path)
    {
        if (string.IsNullOrEmpty(path))
            throw new IOException("路径为空");

        IntPtr h = CreateFileW(path, GENERIC_READ | FILE_READ_ATTRIBUTES, SHARE_ALL,
            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == new IntPtr(-1) || h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            int hr = unchecked((int)(0x80070000u | (uint)(err & 0xFFFF)));
            throw new IOException("无法打开文件（Win32=" + err + "）", hr);
        }

        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(h, out info)
            || (info.FileAttributes & (FILE_ATTR_DIRECTORY | FILE_ATTR_REPARSE_POINT)) != 0)
        {
            CloseHandle(h);
            throw new IOException("目标为目录或重解析点，拒绝打开");
        }

        SafeFileHandle sfh = new SafeFileHandle(h, true);
        try
        {
            return new FileStream(sfh, FileAccess.Read);
        }
        catch
        {
            sfh.Dispose();
            throw;
        }
    }

    private static bool TryGetLastWriteUtcFromStream(Stream s, string path, out DateTime utc)
    {
        utc = DateTime.MinValue;
        FileStream fs = s as FileStream;
        if (fs != null)
        {
            try
            {
                SafeFileHandle sfh = fs.SafeFileHandle;
                if (sfh == null || sfh.IsInvalid || sfh.IsClosed) return false;
                bool addedRef = false;
                try
                {
                    sfh.DangerousAddRef(ref addedRef);
                    BY_HANDLE_FILE_INFORMATION info;
                    if (!GetFileInformationByHandle(sfh.DangerousGetHandle(), out info))
                        return false;
                    if ((info.FileAttributes & (FILE_ATTR_DIRECTORY | FILE_ATTR_REPARSE_POINT)) != 0)
                        return false;
                    long ft = ((long)info.LastWriteTime.High << 32) | info.LastWriteTime.Low;
                    utc = DateTime.FromFileTimeUtc(ft);
                    return true;
                }
                finally
                {
                    if (addedRef) sfh.DangerousRelease();
                }
            }
            catch
            {
                return false;
            }
        }

        // 非 FileStream（扫描期或内存测试流）：仅对非重解析点普通文件读取 LastWriteTimeUtc
        // 扫描预取热路径已由 SafetyPolicy.DecideCore 前置核验 HasReparseRiskForPolicy，避免重复祖先链遍历
        try
        {
            if (string.IsNullOrEmpty(path)) return false;
            if (!inPrefetchedScanVerify && PathGuard.HasAnyReparseComponent(path))
                return false;
            FileInfo fi = new FileInfo(path);
            if (!fi.Exists) return false;
            if ((fi.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                return false;
            utc = fi.LastWriteTimeUtc;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool CheckPrefetchedHead(byte[] head, int minBytes, HashBudget budget, Func<bool> cancelled, out string fail)
    {
        fail = "";
        if (cancelled != null && cancelled()) { fail = "内容校验已取消，未校验"; return false; }
        HashBudget b = budget == null ? HashBudget.Unlimited : budget;
        if (!b.TryConsume(StructuredHeadBytes)) { fail = "内容校验字节预算不足（需 " + StructuredHeadBytes + " 字节），未校验"; return false; }
        if (head == null || head.Length < minBytes) { fail = "文件不足 " + minBytes + " 字节，结构不完整"; return false; }
        return true;
    }

    private static bool ReadStructuredHead(string path, int minBytes, HashBudget budget, Func<bool> cancelled,
                                           out byte[] head, out long len, out string fail)
    {
        head = new byte[0]; len = 0; fail = "";
        if (cancelled != null && cancelled()) { fail = "内容校验已取消，未校验"; return false; }
        HashBudget b = budget == null ? HashBudget.Unlimited : budget;
        if (!b.TryConsume(StructuredHeadBytes)) { fail = "内容校验字节预算不足（需 " + StructuredHeadBytes + " 字节），未校验"; return false; }
        try
        {
            using (FileStream fs = OpenNoReparseRead(path))
            {
                len = fs.Length;
                int want = (int)Math.Min(len, (long)StructuredHeadBytes);
                if (want < 0) want = 0;
                byte[] buf = new byte[want];
                int read = 0;
                while (read < want)
                {
                    int n = fs.Read(buf, read, want - read);
                    if (n <= 0) break;
                    read += n;
                }
                if (read == want)
                {
                    head = buf;
                }
                else
                {
                    byte[] smaller = new byte[read];
                    Array.Copy(buf, smaller, read);
                    head = smaller;
                }
            }
        }
        catch { fail = "无法读取文件头"; return false; }
        if (head.Length < minBytes) { fail = "文件不足 " + minBytes + " 字节，结构不完整"; return false; }
        return true;
    }

    private static byte[] ReadStreamHead(Stream s, int maxBytes)
    {
        if (s == null || maxBytes <= 0) return new byte[0];
        if (s.CanSeek) s.Position = 0;
        long slen = s.CanSeek ? s.Length : (long)maxBytes;
        if (slen <= 0) return new byte[0];
        int want = (int)Math.Min(slen, (long)maxBytes);
        byte[] head = new byte[want];
        int read = 0;
        while (read < head.Length)
        {
            int n = s.Read(head, read, head.Length - read);
            if (n <= 0) break;
            read += n;
        }
        if (read == head.Length) return head;
        byte[] trimmed = new byte[read];
        Array.Copy(head, trimmed, read);
        return trimmed;
    }

    private static bool StartsWithSqliteWalMagic(byte[] head)
    {
        return head != null && head.Length >= 4
            && head[0] == 0x37 && head[1] == 0x7F && head[2] == 0x06
            && (head[3] == 0x82 || head[3] == 0x83);
    }

    private static bool StartsWithEseDbMagic(byte[] head)
    {
        return head != null && head.Length >= 8
            && head[4] == 0xEF && head[5] == 0xCD && head[6] == 0xAB && head[7] == 0x89;
    }

    private static bool StartsWithKdbxMagic(byte[] head)
    {
        return StartsWithBytes(head, 0x03, 0xD9, 0xA2, 0x9A);
    }

    private static bool StartsWithPkcs12Magic(byte[] head)
    {
        return head != null && head.Length >= 7
            && head[0] == 0x30 && head[1] == 0x82
            && head[4] == 0x02 && head[5] == 0x01 && head[6] == 0x03;
    }

    private static string CheckForbiddenImportantHeader(byte[] head)
    {
        if (head == null || head.Length == 0) return null;
        if (StartsWithBytes(head, 0x50, 0x4B, 0x03, 0x04)
            || StartsWithBytes(head, 0x50, 0x4B, 0x05, 0x06)
            || StartsWithBytes(head, 0x50, 0x4B, 0x07, 0x08))
            return "ZIP 或 Office OpenXML 文档头（PK）";
        return CheckNonZipForbiddenHeader(head);
    }

    private static string CheckNonZipForbiddenHeader(byte[] head)
    {
        if (head == null || head.Length == 0) return null;
        if (StartsWithBytes(head, 0xD0, 0xCF, 0x11, 0xE0))
            return "Office OLE2 复合文档头";
        if (StartsWithAscii(head, "%PDF"))
            return "PDF 文档头";
        if (StartsWithBytes(head, 0x4D, 0x5A))
            return "PE 可执行程序或动态库头（MZ）";
        if (StartsWithAscii(head, "SQLite format 3") || StartsWithAscii(head, "SQLite") || StartsWithSqliteWalMagic(head))
            return "SQLite 数据库或 WAL 头";
        if (StartsWithBytes(head, 0x52, 0x61, 0x72, 0x21))
            return "RAR 压缩包头";
        if (StartsWithBytes(head, 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C))
            return "7z 压缩包头";
        if (StartsWithAscii(head, "{\\rtf"))
            return "RTF 文档头";
        if (StartsWithAscii(head, "8BPS"))
            return "Photoshop PSD 文档头";
        if (StartsWithBytes(head, 0x89, 0x50, 0x4E, 0x47))
            return "PNG 图像头";
        if (StartsWithBytes(head, 0xFF, 0xD8, 0xFF))
            return "JPEG 图像头";
        if (StartsWithAscii(head, "GIF87a") || StartsWithAscii(head, "GIF89a"))
            return "GIF 图像头";
        if (StartsWithAscii(head, "-----BEGIN "))
            return "PEM 证书或私钥头";
        if (StartsWithKdbxMagic(head))
            return "KeePass 密码库头（KDBX）";
        if (StartsWithPkcs12Magic(head))
            return "PKCS#12 证书私钥头";
        if (StartsWithAscii(head, "regf"))
            return "注册表配置单元头";
        return null;
    }

    private static bool StartsWithBytes(byte[] head, params byte[] prefix)
    {
        if (head == null || prefix == null || head.Length < prefix.Length) return false;
        for (int i = 0; i < prefix.Length; i++)
        {
            if (head[i] != prefix[i]) return false;
        }
        return true;
    }

    private static bool StartsWithAscii(byte[] head, string ascii)
    {
        if (head == null || ascii == null || head.Length < ascii.Length) return false;
        for (int i = 0; i < ascii.Length; i++)
        {
            if (head[i] != (byte)ascii[i]) return false;
        }
        return true;
    }

    private static bool IsAllSameByte(byte[] head)
    {
        if (head == null || head.Length == 0) return true;
        byte first = head[0];
        for (int i = 1; i < head.Length; i++)
        {
            if (head[i] != first) return false;
        }
        return true;
    }

    private static bool HasBinaryFraming(byte[] head, int count)
    {
        if (head == null || head.Length == 0) return false;
        int n = Math.Min(head.Length, count);
        for (int i = 0; i < n; i++)
        {
            byte b = head[i];
            if (b < 0x20 && b != (byte)'\t' && b != (byte)'\r' && b != (byte)'\n')
                return true;
        }
        return false;
    }

    private static int SkipUtf8BomAndWhitespace(byte[] head)
    {
        int i = 0;
        if (head.Length >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF) i = 3;
        while (i < head.Length && (head[i] == (byte)' ' || head[i] == (byte)'\t' || head[i] == (byte)'\r' || head[i] == (byte)'\n'))
            i++;
        return i;
    }

    private static bool StartsWithJsonPayload(byte[] head)
    {
        int i = SkipUtf8BomAndWhitespace(head);
        if (i >= head.Length) return false;
        byte lead = head[i];
        if (lead != (byte)'{' && lead != (byte)'[') return false;
        for (int k = i + 1; k < head.Length; k++)
        {
            if (head[k] == (byte)'"' || head[k] == (byte)':' || head[k] == (byte)'}' || head[k] == (byte)']')
                return true;
        }
        return false;
    }

    private static bool StartsWithHtmlIndex(byte[] head)
    {
        int i = SkipUtf8BomAndWhitespace(head);
        if (i + 5 > head.Length || head[i] != (byte)'<') return false;
        string s = Encoding.ASCII.GetString(head, i, Math.Min(16, head.Length - i));
        return s.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
            || s.StartsWith("<html", StringComparison.OrdinalIgnoreCase);
    }

    private static bool StartsWithXmlFeed(byte[] head)
    {
        int i = SkipUtf8BomAndWhitespace(head);
        if (i + 5 > head.Length || head[i] != (byte)'<') return false;
        string s = Encoding.ASCII.GetString(head, i, Math.Min(16, head.Length - i));
        return s.StartsWith("<?xml", StringComparison.OrdinalIgnoreCase)
            || s.StartsWith("<feed", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHex(string s)
    {
        foreach (char c in s)
        {
            bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    private static byte[] ReadHead(string path, int count)
    {
        using (FileStream fs = OpenNoReparseRead(path))
        {
            byte[] b = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = fs.Read(b, read, count - read);
                if (n <= 0) break;
                read += n;
            }
            if (read == count) return b;
            byte[] smaller = new byte[read];
            Array.Copy(b, smaller, read);
            return smaller;
        }
    }
}
