using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Threading.Tasks;

/// <summary>
/// 规则匹配阶段：严格对齐 EvidenceRules 的分层优先级，确保用户文档与配置绝不被缓存规则误吞。
/// </summary>
public enum RuleMatchStage
{
    BeforeUserDoc = 0,     // 仅限限定了专用缓存完整路径的特殊扩展名（如 Explorer 下的 thumbcache_*.db）
    BeforeUserConfig = 1,  // 排在 USER-DOC 之后、USER-CONFIG 之前（限定包缓存子目录路径下的 .dat / .json / .tgz）
    StandardCache = 2,     // 排在 USER-DOC / USER-CONFIG / USER-SCRIPT 全部用户数据规则之后
    AfterNamedReviews = 3  // 排在 REVIEW-* 命名推测规则之后（如满 24h 的 %LOCALAPPDATA%\Temp\*.tmp）
}

/// <summary>一条缓存规则下属的单条路径/文件名匹配声明。</summary>
public sealed class RuleMatchPattern
{
    public RuleMatchStage Stage = RuleMatchStage.StandardCache;
    public string Pattern = "";
    public bool NameOnly = true;
    public string App = "";
    public string Reason = "";
    public string Consequence = "";
    public EvidenceKind Evidence = EvidenceKind.MagicHeader;
    public string Scope = "";
    public string Excludes = "";
    public int MinAgeHours = -1;
}

/// <summary>
/// 单一受控清理缓存规则完整声明（真理源）。
/// 新增或调整受控缓存规则只需在 CacheRuleRegistry 中声明一处，
/// Rules / Safety / ContentEvidence / CleanSelection / ScanText / AnPingExplanation / Bridge 自动同步。
/// </summary>
public sealed class CacheRuleSpec
{
    public string Id = "";
    public int Order;

    public string CategoryId = "";
    public string CategoryName = "";

    public string GroupTitle = "";
    public string GroupCost = "";

    public bool RequiresSeparateConfirm;
    public string ConfirmLabel = "";
    public string SeparateConfirmError = "";

    public string RuleLabel = "";

    public string ExplainType = "";
    public string ExplainPurpose = "";
    public string ExplainRiskText = "";
    public string[] ExplainSteps = new string[0];

    public bool RootBound = true;
    public int MinAgeHours;
    public bool ReportHeaderInDetail;

    public RuleMatchPattern[] MatchPatterns = new RuleMatchPattern[0];
    public Func<CacheRoots.Root[]> DiscoverDefaultRoots;
    public Func<string, HashBudget, Func<bool>, ContentEvidence> VerifyFile;
    public Func<string, Stream, string> VerifyStream;
}

/// <summary>单一声明式受控缓存规则注册表。</summary>
public static class CacheRuleRegistry
{
    private static readonly CacheRuleSpec[] specs = BuildSpecs();
    private static readonly Dictionary<string, CacheRuleSpec> byId = BuildLookup(specs);
    private static List<string> quickScanOverrideForTest;

    private const long ExistingRootsTtlTicks = 5L * TimeSpan.TicksPerSecond;
    private static readonly object rootsCacheGate = new object();
    private static CacheRoots.Root[] cachedExistingRoots;
    private static long cachedExistingAtUtcTicks;
    private static int cachedExistingGeneration = 1;
    private static int refreshEpoch = 1;

    private static readonly object elevationGate = new object();
    private static bool elevationChecked;
    private static bool isElevatedCached;

    /// <summary>当前进程是否以管理员（Administrator）权限运行（带静态缓存）。</summary>
    public static bool IsCurrentProcessElevated()
    {
        if (elevationChecked) return isElevatedCached;
        lock (elevationGate)
        {
            if (elevationChecked) return isElevatedCached;
            bool admin = false;
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    if (id != null)
                    {
                        WindowsPrincipal principal = new WindowsPrincipal(id);
                        admin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                    }
                }
            }
            catch { admin = false; }
            isElevatedCached = admin;
            elevationChecked = true;
            return admin;
        }
    }

    /// <summary>只读检测本机是否存在需要管理员权限才能完整访问的系统级缓存目标（SoftwareDistribution\Download 或 Windows\Temp）。</summary>
    public static bool HasSystemAdminCacheTargets()
    {
        try
        {
            string winDir = PathGuard.Canonical(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            if (winDir.Length == 0) return false;

            string sdDownload = Path.Combine(Path.Combine(winDir, "SoftwareDistribution"), "Download");
            if (Directory.Exists(sdDownload) && !PathGuard.IsReparsePoint(sdDownload))
                return true;

            string winTemp = Path.Combine(winDir, "Temp");
            if (Directory.Exists(winTemp) && !PathGuard.IsReparsePoint(winTemp))
                return true;

            return false;
        }
        catch { return false; }
    }

    /// <summary>按 Order (0..N-1) 固定顺序排列的全部受控缓存规则。</summary>
    public static CacheRuleSpec[] All
    {
        get { return specs; }
    }

    /// <summary>按规则 ID 查找注册表项；未命中返回 null。</summary>
    public static CacheRuleSpec Find(string ruleId)
    {
        if (string.IsNullOrEmpty(ruleId)) return null;
        CacheRuleSpec spec;
        return byId.TryGetValue(ruleId, out spec) ? spec : null;
    }

    /// <summary>该规则 ID 是否为注册在案的受控缓存清理规则。</summary>
    public static bool IsCleanableRule(string ruleId)
    {
        return Find(ruleId) != null;
    }

    /// <summary>将任意规则 ID 映射为主界面柱状图分类 ID（受控缓存规则直接读注册表，其余走固定归类）。</summary>
    public static string MapRuleToCategory(string ruleId)
    {
        if (string.IsNullOrEmpty(ruleId)) return "tmp";
        CacheRuleSpec spec = Find(ruleId);
        if (spec != null && !string.IsNullOrEmpty(spec.CategoryId))
            return spec.CategoryId;

        switch (ruleId)
        {
            case "REVIEW-CHATTEMP": return "wx";
            case "REVIEW-INSTALLERLOG": return "log";
            case "REVIEW-OFFICEDRAFT": return "draft";
            case "REVIEW-PARTIALDL": return "dl";
            case "REVIEW-VSCODEUPD": return "upd";
            case "KEEP-SYSTEM":
            case "KEEP-LOCK":
            case "KEEP-MSICACHE":
            case "KEEP-CHATDB":
            case "USER-DOC":
            case "USER-CONFIG":
            case "USER-SCRIPT":
                return "user";
            default:
                return "tmp";
        }
    }

    /// <summary>
    /// 显式刷新受控缓存根目录、受控临时目录与浏览器缓存池目录内存缓存。
    /// 供新一轮扫描启动前或沙盒测试注入变更时调用，确保扫描期间零重复磁盘探测。
    /// </summary>
    public static void RefreshRootsCache()
    {
        lock (rootsCacheGate)
        {
            cachedExistingRoots = null;
            cachedExistingAtUtcTicks = 0;
            cachedExistingGeneration++;
            refreshEpoch++;
        }
        PathGuard.InvalidateControlledRootsCache();
        CacheRoots.InvalidateCompiledCache();
        ContentVerifier.ClearDirectoryVerifyCache();
    }

    /// <summary>汇总本机当前真实存在、非重解析点的全部受控缓存根目录（带短 TTL 内存缓存，供 CacheRoots.Existing 调用）。</summary>
    public static CacheRoots.Root[] DiscoverExistingRoots()
    {
        int gen;
        CacheRoots.Root[] arr = DiscoverExistingRootsCached(out gen);
        if (arr.Length == 0) return arr;
        CacheRoots.Root[] copy = new CacheRoots.Root[arr.Length];
        Array.Copy(arr, copy, arr.Length);
        return copy;
    }

    internal static CacheRoots.Root[] DiscoverExistingRootsCached(out int generation)
    {
        long nowTicks = DateTime.UtcNow.Ticks;
        int epochSnapshot;
        lock (rootsCacheGate)
        {
            if (cachedExistingRoots != null
                && nowTicks >= cachedExistingAtUtcTicks
                && (nowTicks - cachedExistingAtUtcTicks) < ExistingRootsTtlTicks)
            {
                generation = cachedExistingGeneration;
                return cachedExistingRoots;
            }
            epochSnapshot = refreshEpoch;
        }

        CacheRoots.Root[] probed = ProbeExistingRootsFromDisk();

        lock (rootsCacheGate)
        {
            if (refreshEpoch == epochSnapshot || cachedExistingRoots == null)
            {
                cachedExistingRoots = probed;
                cachedExistingAtUtcTicks = DateTime.UtcNow.Ticks;
                cachedExistingGeneration++;
            }
            generation = cachedExistingGeneration;
            return cachedExistingRoots;
        }
    }

    private static CacheRoots.Root[] ProbeExistingRootsFromDisk()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        for (int i = 0; i < specs.Length; i++)
        {
            CacheRuleSpec s = specs[i];
            if (s.DiscoverDefaultRoots == null) continue;
            try
            {
                CacheRoots.Root[] roots = s.DiscoverDefaultRoots();
                if (roots == null) continue;
                for (int k = 0; k < roots.Length; k++)
                {
                    if (roots[k] != null && !string.IsNullOrEmpty(roots[k].Directory))
                        list.Add(roots[k]);
                }
            }
            catch { }
        }
        return list.ToArray();
    }

    /// <summary>
    /// 获取「快速扫描常见缓存」的目标目录列表：
    /// 汇总所有规则在当前系统真实存在、非重解析点的受控缓存目录，去重并过滤掉父子重叠子目录。
    /// 若测试注入了沙盒覆盖目录或 CacheRoots.InjectForTest，仅返回沙盒目录，绝不触碰真实用户目录。
    /// </summary>
    public static string[] GetQuickScanRoots()
    {
        if (quickScanOverrideForTest != null)
            return NormalizeQuickScanRoots(quickScanOverrideForTest);

        if (CacheRoots.HasInjectedForTest)
            return NormalizeQuickScanRoots(CacheRoots.GetInjectedDirectoriesForTest());

        CacheRoots.Root[] existing = DiscoverExistingRoots();
        List<string> raw = new List<string>(existing.Length);
        for (int i = 0; i < existing.Length; i++)
        {
            raw.Add(existing[i].Directory);
        }
        return NormalizeQuickScanRoots(raw);
    }

    /// <summary>对候选扫描根目录做规范化、存在性与非重解析点核验、大小写不敏感去重及父子重叠过滤。</summary>
    public static string[] NormalizeQuickScanRoots(IEnumerable<string> candidates)
    {
        if (candidates == null) return new string[0];

        List<string> unique = new List<string>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string dir in candidates)
        {
            if (string.IsNullOrEmpty(dir)) continue;
            string canon = PathGuard.Canonical(dir);
            if (canon.Length == 0) continue;
            try
            {
                if (!Directory.Exists(canon)) continue;
                if (PathGuard.IsReparsePoint(canon)) continue;
            }
            catch { continue; }

            if (seen.Add(canon))
                unique.Add(canon);
        }

        List<string> filtered = new List<string>(unique.Count);
        for (int i = 0; i < unique.Count; i++)
        {
            string cur = unique[i];
            bool hasParentInList = false;
            for (int j = 0; j < unique.Count; j++)
            {
                if (i == j) continue;
                string other = unique[j];
                if (!string.Equals(other, cur, StringComparison.OrdinalIgnoreCase)
                    && PathGuard.IsInside(other, cur))
                {
                    hasParentInList = true;
                    break;
                }
            }
            if (!hasParentInList)
                filtered.Add(cur);
        }

        return filtered.ToArray();
    }

    /// <summary>仅供沙盒自动化测试显式指定快速扫描根目录列表（传空数组可测 0 项快扫分支）。</summary>
    public static void SetQuickScanRootsForTest(IEnumerable<string> roots)
    {
        if (roots == null)
        {
            quickScanOverrideForTest = null;
            RefreshRootsCache();
            return;
        }
        quickScanOverrideForTest = new List<string>(roots);
        RefreshRootsCache();
    }

    public static void ClearQuickScanRootsForTest()
    {
        quickScanOverrideForTest = null;
        RefreshRootsCache();
    }

    // ==================== 规则声明表（0..7） ====================

    private static CacheRuleSpec[] BuildSpecs()
    {
        string[] standardSteps = new string[]
        {
            "可以用「清理」永久删除。",
            "正在使用的文件会自动跳过。"
        };
        string[] dumpSteps = new string[]
        {
            "如果正在向软件厂商反馈这次崩溃，先把文件发给他们。",
            "否则可以用「清理」删除。"
        };

        CacheRuleSpec[] raw = new CacheRuleSpec[]
        {
            // [0] 开发包管理器缓存（npm / pip / NuGet / Yarn / pnpm / Go / uv）
            new CacheRuleSpec
            {
                Id = "TMP-PKGCACHE",
                Order = 0,
                CategoryId = "pkg",
                CategoryName = "开发包管理器缓存",
                GroupTitle = "开发包管理器缓存 · npm / pip / NuGet / Yarn / Go / uv",
                GroupCost = "下次安装依赖或编译时会自动重新获取；离线或私有源不可达时无法从本地读取。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "开发包管理器缓存",
                ExplainType = "开发包管理器缓存项",
                ExplainPurpose = "npm、pip、NuGet、Yarn、Go 或 uv 等保存的包与编译缓存。",
                ExplainRiskText = "下次安装或编译时会自动重下重建；离线或私有源不可达时无法本地读取。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 0,
                ReportHeaderInDetail = false,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserDoc,
                        Pattern = @"[\\/](yarn[\\/]cache|yarn-cache|pnpm-cache|pnpm[\\/]cache)[\\/].+\.(tgz|zip)$",
                        NameOnly = false,
                        App = "开发工具（Yarn / pnpm）",
                        Reason = "Yarn 或 pnpm 包缓存归档（GZIP 或 ZIP 包头校验通过）",
                        Consequence = "删除后下次安装依赖时会自动重新下载；离线或私有源不可达时无法从本地读取。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "Yarn\\Cache 或 pnpm-cache 下的压缩缓存包",
                        Excludes = "非缓存根、Office 文档头或损坏包"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserDoc,
                        Pattern = @"[\\/]go-build[\\/]([0-9a-f]{2}[\\/][0-9a-f]{64}-[ad]|trim\.txt|README)$",
                        NameOnly = false,
                        App = "开发工具（Go 编译器）",
                        Reason = "Go 编译缓存项（哈希路径与非文档头结构校验通过）",
                        Consequence = "删除后下次执行 go build 或 go test 时会自动重新编译生成。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\go-build 下的编译产物与动作索引",
                        Excludes = "非缓存根、伪造文档/数据库头或被占用项"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserConfig,
                        Pattern = @"[\\/](nuget[\\/]v3-cache|v3-cache|nuget[-_a-z0-9]*)[\\/].+\.(dat|nupkg)$",
                        NameOnly = false,
                        App = "开发工具（npm / pip / NuGet / Yarn / pnpm）",
                        Reason = "NuGet HTTP 缓存项（包头或缓存响应结构校验通过）",
                        Consequence = "删除后下次还原依赖时会自动重新下载；离线或私有源不可达时将无法从本地缓存读取。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\NuGet\\v3-cache 下的 .dat / .nupkg",
                        Excludes = "非缓存根、伪造空壳、文档头或被占用项"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserConfig,
                        Pattern = @"[\\/](yarn[\\/]cache|yarn-cache|pnpm-cache|pnpm[\\/]cache)[\\/].+\.(tgz|dat|json)$",
                        NameOnly = false,
                        App = "开发工具（Yarn / pnpm）",
                        Reason = "Yarn 或 pnpm 缓存项（压缩流或 JSON 元数据结构校验通过）",
                        Consequence = "删除后下次安装依赖时会自动重新拉取；离线或私有源不可达时将无法本地安装。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\Yarn\\Cache 与 pnpm-cache 缓存项",
                        Excludes = "非缓存根、伪造文本、用户文档头或锁文件"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserConfig,
                        Pattern = @"[\\/]uv[\\/]cache[\\/].+\.(whl|tar\.gz|tgz|msgpack|http)$",
                        NameOnly = false,
                        App = "开发工具（Python uv）",
                        Reason = "Python uv 包与元数据缓存项（压缩包头或缓存结构校验通过）",
                        Consequence = "删除后下次使用 uv 安装或同步环境时会自动重新下载。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\uv\\cache 下的 wheel、归档与元数据缓存",
                        Excludes = "非缓存根、重要文档/数据库/PE 头或被占用项"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"_cacache|npm-cache|yarn-|pnpm-|^[0-9a-fA-F]{124}$|\.(whl|nupkg|tgz)$",
                        NameOnly = true,
                        App = "开发工具（npm / pip / NuGet / Yarn / pnpm）",
                        Reason = "开发包管理器缓存项（内容哈希或压缩包头结构校验通过）",
                        Consequence = "删除后该缓存项需重新下载生成。离线安装、私有源不可达或网络受限时，"
                                    + "对应包将无法从本地缓存取得，需重新联网下载或改用本地镜像。",
                        Evidence = EvidenceKind.ContentAddressedHash,
                        Scope = "npm/pip/NuGet/Yarn/pnpm/uv 受控缓存根内且结构通过",
                        Excludes = "非指定缓存根、哈希或包头不符、超限或被占用项"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/]pip[\\/]cache[\\/](http|http-v2)[\\/].+$",
                        NameOnly = false,
                        App = "开发工具（Python pip）",
                        Reason = "pip HTTP 缓存项（缓存序列化头或包体结构校验通过）",
                        Consequence = "删除后下次使用 pip 安装包时会自动重新联网拉取；离线时无法从本地缓存读取。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\pip\\cache\\http(-v2) 内缓存项",
                        Excludes = "非缓存根、结构不符或被占用文件"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/](pnpm-cache|pnpm[\\/]cache)[\\/].+$",
                        NameOnly = false,
                        App = "开发工具（pnpm）",
                        Reason = "pnpm 缓存数据项（压缩流或元数据结构校验通过）",
                        Consequence = "删除后下次使用 pnpm 安装依赖时会自动重新联网获取。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\pnpm-cache 内受控缓存项",
                        Excludes = "非缓存根、用户文档头、纯文本或被占用项"
                    }
                },
                DiscoverDefaultRoots = DiscoverPkgRoots,
                VerifyFile = ContentVerifier.VerifyPkgCache,
                VerifyStream = ContentVerifier.VerifyPkgCacheStream
            },

            // [1] 浏览器缓存（Edge / Chrome / Firefox / Brave / Vivaldi / Opera）
            new CacheRuleSpec
            {
                Id = "TMP-BROWSERCACHE",
                Order = 1,
                CategoryId = "br",
                CategoryName = "浏览器缓存",
                GroupTitle = "浏览器缓存 · Edge / Chrome / Firefox 等",
                GroupCost = "网页图片与脚本缓存会自动重新加载；不包含 Cookie、密码和浏览记录。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "浏览器缓存",
                ExplainType = "浏览器网页与渲染缓存",
                ExplainPurpose = "Edge、Chrome 或 Firefox 等保存的网页与渲染缓存。",
                ExplainRiskText = "下次打开网页会自动重新加载；不含登录状态、密码与书签。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 0,
                ReportHeaderInDetail = true,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/](microsoft[\\/]edge|edge[\\/]user data|google[\\/]chrome|chrome[\\/]user data|bravesoftware|brave-browser|brave[\\/]user data|vivaldi|opera software|opera stable|opera gx)[\\/].*[\\/](cache[\\/]cache_data|code cache|gpucache|dawncache)[\\/].+$",
                        NameOnly = false,
                        App = "浏览器（Edge / Chrome / Brave / Vivaldi / Opera）",
                        Reason = "浏览器网页或渲染缓存项（Chromium 缓存魔数与结构校验通过）",
                        Consequence = "删除后下次访问网页时会自动重新加载资源；不包含 Cookie、密码、历史记录与书签。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "各浏览器配置下的 Cache_Data、Code Cache、GPUCache、DawnCache 纯缓存子目录",
                        Excludes = "Cookies、Login Data、历史书签、扩展及伪造头"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/]cache2[\\/]entries[\\/][0-9a-f]{40}$",
                        NameOnly = false,
                        App = "Mozilla Firefox 浏览器",
                        Reason = "Firefox 网页响应缓存条目（cache2 哈希分片与安全头校验通过）",
                        Consequence = "删除后下次访问网页时会自动重新加载；不包含 cookies.sqlite、书签与保存的密码。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "Firefox Profiles\\*\\cache2\\entries 下的 40 位十六进制缓存项",
                        Excludes = "cookies.sqlite、places.sqlite、logins.json、key4.db 等个人数据"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/]startupcache[\\/].+\.(little|bin)$",
                        NameOnly = false,
                        App = "Mozilla Firefox 浏览器",
                        Reason = "Firefox 启动字节码与界面缓存（二进制帧头校验通过）",
                        Consequence = "删除后下次启动 Firefox 时会自动重建缓存；不影响登录与书签。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "Firefox Profiles\\*\\startupCache 下的 .little / .bin",
                        Excludes = "文档头、SQLite 数据库头、纯文本或非缓存目录项"
                    }
                },
                DiscoverDefaultRoots = DiscoverBrowserRoots,
                VerifyFile = ContentVerifier.VerifyBrowserCache,
                VerifyStream = ContentVerifier.VerifyBrowserCacheStream
            },

            // [2] 微信 / 企业微信 / QQ 纯缓存（朋友圈媒体、小程序包、内置网页缓存；三重硬排除聊天库与接收文件）
            new CacheRuleSpec
            {
                Id = "TMP-CHATCACHE",
                Order = 2,
                CategoryId = "wx",
                CategoryName = "微信 / 办公聊天缓存",
                GroupTitle = "聊天软件纯缓存 · 朋友圈 / 小程序 / 内置网页",
                GroupCost = "朋友圈看过的图片视频缓存与小程序运行包会按需重新加载；绝不触碰聊天记录与接收文件。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "聊天软件缓存",
                ExplainType = "聊天软件朋友圈与小程序缓存",
                ExplainPurpose = "微信、企业微信或 QQ 自动缓存的朋友圈媒体与小程序包。",
                ExplainRiskText = "再次浏览朋友圈或小程序时会自动重下；不含聊天文件与记录。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 0,
                ReportHeaderInDetail = true,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserConfig,
                        Pattern = @"[\\/](sns[\\/]cache|cache[\\/]sns)[\\/](?!.*\.(?:lock|db|sqlite|exe|dll|sys|ini|cfg|config)$).+$",
                        NameOnly = false,
                        App = "微信或企业微信（朋友圈缓存）",
                        Reason = "朋友圈图片或视频预览缓存（纯缓存子目录与媒体/二进制帧结构校验通过）",
                        Consequence = "删除后再次翻看旧朋友圈时会自动重新加载；绝不触碰聊天记录与聊天接收文件。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "微信/企业微信 Sns\\Cache 纯缓存子目录",
                        Excludes = "Msg 聊天数据库、FileStorage\\File|Video|Image|MsgAttach、文档/压缩包/程序头"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserConfig,
                        Pattern = @"[\\/](applet|wmpfruntime|xplugin|xweb|radium[\\/]web[\\/]cache|cefcache|webkit_cache|nt_qq[\\/]global[\\/]nt_temp|nt_temp)[\\/](?!.*\.(?:lock|db|sqlite|exe|dll|sys|ini|cfg|config)$).+$",
                        NameOnly = false,
                        App = "微信 / 企业微信 / QQ（小程序与内置网页缓存）",
                        Reason = "聊天软件小程序运行包或内置网页缓存（纯缓存子目录与安全头结构校验通过）",
                        Consequence = "删除后下次打开对应小程序或内置网页时会自动重新下载；不含聊天记录与接收原件。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "Applet、WMPFRuntime、XPlugin、xweb、CefCache、webkit_cache、nt_temp 纯缓存子目录",
                        Excludes = "聊天数据库、FileRecv/FileStorage 接收原件、Office/PDF/SQLite/PE 头"
                    }
                },
                DiscoverDefaultRoots = ChatStorageLocator.DiscoverPureChatCacheRoots,
                VerifyFile = ContentVerifier.VerifyChatCache,
                VerifyStream = ContentVerifier.VerifyChatCacheStream
            },

            // [3] 桌面软件与组件缓存（VS Code / Electron / CEF / WebView2 / Steam）
            new CacheRuleSpec
            {
                Id = "TMP-APPCACHE",
                Order = 3,
                CategoryId = "app",
                CategoryName = "桌面软件缓存",
                GroupTitle = "桌面软件与组件缓存 · VS Code / 社交办公 / WebView2",
                GroupCost = "下次打开软件时会自动重建；不含账号登录、聊天记录与个人配置。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "桌面软件缓存",
                ExplainType = "桌面软件与组件缓存",
                ExplainPurpose = "桌面软件或 WebView2 组件保存的网页、脚本与渲染缓存。",
                ExplainRiskText = "下次打开软件时会自动重建；不含账号登录、聊天记录与个人配置。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 0,
                ReportHeaderInDetail = true,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserDoc,
                        Pattern = @"[\\/](code|cursor)[\\/]cachedextensionvsixs[\\/][^\\/]+$",
                        NameOnly = false,
                        App = "桌面开发工具（VS Code / Cursor）",
                        Reason = "编辑器已安装插件的离线安装包缓存（ZIP/VSIX 包头校验通过）",
                        Consequence = "删除后不影响已安装的插件运行；重装同版本插件时会自动重新下载。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%APPDATA%\\Code|Cursor\\CachedExtensionVsiXs 下的插件包缓存",
                        Excludes = "settings.json、workspaceStorage、Office OpenXML 文档头或损坏包"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/](cache[\\/]cache_data|code cache|gpucache|dawncache)[\\/].+$",
                        NameOnly = false,
                        App = "桌面软件或 WebView2 组件",
                        Reason = "桌面软件或 WebView2 网页与渲染缓存（Chromium 缓存结构校验通过）",
                        Consequence = "删除后下次打开对应软件时会自动重新加载缓存；不含登录凭据、聊天记录与个人设置。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "受控桌面软件及 EBWebView 下的 Cache_Data / Code Cache / GPUCache / DawnCache",
                        Excludes = "Cookies、Local Storage、IndexedDB、settings.json、state.vscdb 等用户数据"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/](code|cursor)[\\/]cacheddata[\\/][0-9a-f]{8,64}[\\/].+$",
                        NameOnly = false,
                        App = "桌面开发工具（VS Code / Cursor）",
                        Reason = "编辑器版本编译字节码缓存（V8 CachedData 结构校验通过）",
                        Consequence = "删除后下次启动编辑器时会自动重建字节码缓存；不影响代码与个人配置。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%APPDATA%\\Code|Cursor\\CachedData\\<commit> 下的编译缓存",
                        Excludes = "用户配置、工作区状态、文档/数据库/可执行程序头"
                    }
                },
                DiscoverDefaultRoots = DiscoverAppCacheRoots,
                VerifyFile = ContentVerifier.VerifyAppCache,
                VerifyStream = ContentVerifier.VerifyAppCacheStream
            },

            // [4] 缩略图与图标缓存
            new CacheRuleSpec
            {
                Id = "TMP-THUMBCACHE",
                Order = 4,
                CategoryId = "thumb",
                CategoryName = "缩略图与图标缓存",
                GroupTitle = "缩略图与图标缓存",
                GroupCost = "Windows 会自动重建，下次打开文件夹时预览稍慢。正在使用的文件会跳过。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "缩略图/图标缓存",
                ExplainType = "缩略图与图标缓存",
                ExplainPurpose = "资源管理器保存的图片、视频预览小图。",
                ExplainRiskText = "资源管理器会自动重新生成，下次打开文件夹时预览稍慢。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 0,
                ReportHeaderInDetail = true,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserDoc,
                        Pattern = @"[\\/]microsoft[\\/]windows[\\/]explorer[\\/](thumbcache|iconcache)_[^\\/]*\.db$",
                        NameOnly = false,
                        App = "Windows 资源管理器",
                        Reason = "Windows 缩略图/图标缓存（结构校验通过）",
                        Consequence = "删除后资源管理器会自动重新生成，下次打开文件夹时预览图会稍慢。正被资源管理器占用的文件会自动跳过。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "Explorer 目录下的 thumbcache_*/iconcache_*.db",
                        Excludes = "索引文件(*_idx.db)、结构不符、占用或目录外同名项"
                    }
                },
                DiscoverDefaultRoots = DiscoverThumbRoots,
                VerifyFile = ContentVerifier.VerifyThumbcache,
                VerifyStream = ContentVerifier.VerifyThumbcacheStream
            },

            // [5] 图形与着色器缓存（DirectX / NVIDIA / AMD / Intel）
            new CacheRuleSpec
            {
                Id = "TMP-SHADERCACHE",
                Order = 5,
                CategoryId = "shader",
                CategoryName = "图形与着色器缓存",
                GroupTitle = "图形与着色器缓存 · DirectX / NVIDIA / AMD",
                GroupCost = "游戏或图形程序下次启动时会自动重新编译着色器。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "图形与着色器缓存",
                ExplainType = "图形与着色器缓存",
                ExplainPurpose = "DirectX 或显卡驱动保存的已编译着色器缓存。",
                ExplainRiskText = "游戏或图形软件下次启动时会自动重新编译着色器。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 0,
                ReportHeaderInDetail = true,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"\.(val|idx|dxbc|nvph|parc)$",
                        NameOnly = true,
                        App = "DirectX 或显卡图形驱动",
                        Reason = "图形着色器缓存文件（二进制头与非空定界结构校验通过）",
                        Consequence = "删除后游戏或图形软件下次启动时会自动重新编译着色器，首次加载可能稍慢。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "D3DSCache 与显卡着色器缓存目录下的着色器缓存项",
                        Excludes = "*.lock、纯文本或文档头、非着色器缓存目录"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/](d3dscache|dxcache|dxccache|glcache|nv_cache|vkcache|shadercache)[\\/](?!.*\.lock$).+\.(val|idx|bin|toc|parc|dxbc|nvph)$",
                        NameOnly = false,
                        App = "显卡图形驱动（DirectX / NVIDIA / AMD / Intel）",
                        Reason = "显卡着色器编译缓存（二进制帧头与防文档头校验通过）",
                        Consequence = "删除后游戏或 3D 软件下次运行时会自动重新编译着色器。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "NVIDIA / AMD / Intel / DirectX 受控着色器缓存目录",
                        Excludes = "*.lock、Office/PDF/ZIP/PE/图片头、纯文本或被占用项"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"[\\/](dxcache|dxccache|glcache|nv_cache|vkcache|shadercache)[\\/][0-9a-fA-F_]{6,64}(\.(?!lock$)[a-z0-9]{1,6})?$",
                        NameOnly = false,
                        App = "显卡图形驱动（NVIDIA / AMD / Intel）",
                        Reason = "显卡哈希命名着色器缓存块（二进制结构校验通过）",
                        Consequence = "删除后图形程序下次启动时会自动重建着色器缓存。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "显卡驱动 DXCache / GLCache / VkCache / ShaderCache 目录内哈希块",
                        Excludes = "*.lock、个人文档头、数据库头或空壳文件"
                    }
                },
                DiscoverDefaultRoots = DiscoverShaderRoots,
                VerifyFile = ContentVerifier.VerifyShaderCache,
                VerifyStream = ContentVerifier.VerifyShaderCacheStream
            },

            // [6] 系统与软件临时文件（分级冷却 24h / 48h；管理员模式下额外支持 %WINDIR%\Temp）
            new CacheRuleSpec
            {
                Id = "TMP-SYSTEMP",
                Order = 6,
                CategoryId = "systmp",
                CategoryName = "系统与软件临时文件",
                GroupTitle = "系统与软件临时文件 · 过期残留与临时日志",
                GroupCost = "临时目录中超过冷却期且未占用的临时残留与日志；正在使用的文件会跳过。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "系统与软件临时文件",
                ExplainType = "过期的系统与软件临时文件",
                ExplainPurpose = "用户临时目录中超过冷却期未修改的临时文件与日志。",
                ExplainRiskText = "软件遗留的过期临时残留；近期文件与占用项会自动跳过。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 24,
                ReportHeaderInDetail = false,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserDoc,
                        MinAgeHours = 48,
                        Pattern = @"[\\/]temp[\\/](is-[a-z0-9]+\.tmp|ns[a-z0-9]+\.tmp|squirreltemp|scoped_dir[0-9]+_[0-9]+|msi[0-9a-f]+\.tmp|\{[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}\}|(edge|chrome)_bits_[0-9]+_[0-9]+|(msedge|chrome)_installer[^\\/]*|pip-(unpack|ephem|req-build)-[^\\/]+|npm-[0-9]+-[0-9a-f]+|pyinstaller-[^\\/]+)[\\/](?!.*(?:^|[\\/])(?:\~\$|\~df|\~wr)).+\.(exe|dll|cab|nupkg|zip|7z|tgz|pak|dat|bin|json|xml|js|css|tmp|temp|log|etl)$",
                        NameOnly = false,
                        App = "安装或更新程序临时解包目录",
                        Reason = "用户临时目录内专用安装/更新解包沙盒中超过 48 小时未修改的残留文件",
                        Consequence = "删除后旧安装解包残留不再保留；未满 48 小时或正在运行的安装文件会自动跳过。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\Temp 下专用安装/更新沙盒子目录内满 48 小时的解包残留",
                        Excludes = "7zO*/Rar$* 压缩预览目录、未满 48h、Office/PDF/PSD/SQLite/证书头"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        MinAgeHours = 24,
                        Pattern = @"[\\/]temp[\\/](?:[^\\/]+[\\/])*(?!~\$|~df|~wr)[^\\/]+\.(log|etl)$",
                        NameOnly = false,
                        App = "系统或软件临时诊断日志",
                        Reason = "用户临时目录中超过 24 小时未修改的临时日志或跟踪记录",
                        Consequence = "删除后旧临时日志不再保留；正在写入或未满 24 小时的日志会自动跳过。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "仅限 %LOCALAPPDATA%\\Temp 下满 24 小时的 .log / .etl",
                        Excludes = "非 Temp 目录日志、未满 24h、Office 草稿及文档/程序/压缩包头"
                    },
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.AfterNamedReviews,
                        MinAgeHours = 24,
                        Pattern = @"^(?!~\$|~df|~wr).+\.(tmp|temp)$",
                        NameOnly = true,
                        App = "系统或软件临时文件",
                        Reason = "当前用户临时目录中超过 24 小时未修改的临时文件",
                        Consequence = "删除后旧临时数据不再保留；正在使用或未满 24 小时的文件会自动跳过。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "仅限 %LOCALAPPDATA%\\Temp 下满 24 小时的 .tmp/.temp",
                        Excludes = "系统 Temp、未满 24h、Office 草稿及文档/程序头"
                    }
                },
                DiscoverDefaultRoots = DiscoverSystemTempRoots,
                VerifyFile = ContentVerifier.VerifySystemTemp,
                VerifyStream = ContentVerifier.VerifySystemTempStream
            },

            // [7] Windows 错误报告历史（WER ReportArchive / ReportQueue）
            new CacheRuleSpec
            {
                Id = "TMP-WER",
                Order = 7,
                CategoryId = "dump",
                CategoryName = "系统转储与诊断日志",
                GroupTitle = "Windows 错误报告历史 · WER 归档",
                GroupCost = "清理旧诊断报告记录不影响系统或软件正常运行。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "错误报告历史",
                ExplainType = "Windows 错误报告记录",
                ExplainPurpose = "程序异常或卡死时 Windows 自动生成的历史诊断报告。",
                ExplainRiskText = "清理旧报告记录不影响系统或软件正常运行。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 0,
                ReportHeaderInDetail = true,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserDoc,
                        Pattern = @"[\\/]wer[\\/](reportarchive|reportqueue)[\\/].+\.(wer|cab|dmp|mdmp|hdmp)$",
                        NameOnly = false,
                        App = "Windows 错误报告服务",
                        Reason = "Windows 历史错误报告与诊断归档（WER/MSCF/MDMP 头结构校验通过）",
                        Consequence = "删除后旧错误报告记录不再保留；不影响系统与软件正常运行。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportArchive 与 ReportQueue",
                        Excludes = "非 WER 目录、伪造文档头、内核转储头或被占用文件"
                    }
                },
                DiscoverDefaultRoots = DiscoverWerRoots,
                VerifyFile = ContentVerifier.VerifyWer,
                VerifyStream = ContentVerifier.VerifyWerStream
            },

            // [8] Windows 更新下载缓存（SoftwareDistribution\Download；满 48 小时冷却，严禁挂载 DataStore）
            new CacheRuleSpec
            {
                Id = "TMP-WINUPDATE",
                Order = 8,
                CategoryId = "winupd",
                CategoryName = "Windows 更新缓存",
                GroupTitle = "Windows 更新下载缓存 · SoftwareDistribution",
                GroupCost = "已下载超过 48 小时的系统更新安装包缓存；不影响已安装的系统补丁。",
                RequiresSeparateConfirm = false,
                ConfirmLabel = "",
                RuleLabel = "系统更新缓存",
                ExplainType = "Windows 更新下载缓存",
                ExplainPurpose = "Windows Update 下载的系统更新安装包缓存副本。",
                ExplainRiskText = "清理满 48 小时的旧下载包不影响已安装的系统更新。",
                ExplainSteps = standardSteps,
                RootBound = true,
                MinAgeHours = 48,
                ReportHeaderInDetail = true,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.BeforeUserDoc,
                        MinAgeHours = 48,
                        Pattern = @"[\\/]softwaredistribution[\\/]download[\\/](?!.*(?:^|[\\/])datastore(?:[\\/]|$))(?!.*\.lock$).+$",
                        NameOnly = false,
                        App = "Windows Update 服务",
                        Reason = "Windows Update 下载缓存包（满 48 小时且通过更新包或清单头校验）",
                        Consequence = "删除满 48 小时的旧更新下载副本不影响已安装的系统补丁；未满 48 小时或占用项会自动跳过。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%WINDIR%\\SoftwareDistribution\\Download 下满 48 小时的系统更新下载包",
                        Excludes = "DataStore 目录、未满 48h、Office/PDF/PSD/SQLite/证书头或被占用文件"
                    }
                },
                DiscoverDefaultRoots = DiscoverWinUpdateRoots,
                VerifyFile = ContentVerifier.VerifyWinUpdate,
                VerifyStream = ContentVerifier.VerifyWinUpdateStream
            },

            // [9] 系统转储与诊断日志（崩溃转储）
            new CacheRuleSpec
            {
                Id = "TMP-CRASHDUMP",
                Order = 9,
                CategoryId = "dump",
                CategoryName = "系统转储与诊断日志",
                GroupTitle = "系统转储与诊断日志 · 崩溃转储",
                GroupCost = "删除后无法再把这次崩溃报告发给软件厂商。默认不选。",
                RequiresSeparateConfirm = true,
                ConfirmLabel = "我确认不再需要这份崩溃报告",
                SeparateConfirmError = "请单独确认删除崩溃转储的后果。",
                RuleLabel = "崩溃转储",
                ExplainType = "程序崩溃转储",
                ExplainPurpose = "程序崩溃时保存的内存状态，供开发者查问题。",
                ExplainRiskText = "删除后无法再把这次崩溃报告发给软件厂商。",
                ExplainSteps = dumpSteps,
                RootBound = true,
                MinAgeHours = 0,
                ReportHeaderInDetail = true,
                MatchPatterns = new RuleMatchPattern[]
                {
                    new RuleMatchPattern
                    {
                        Stage = RuleMatchStage.StandardCache,
                        Pattern = @"^crashdumps$|\.dmp$",
                        NameOnly = true,
                        App = "Windows 错误报告",
                        Reason = "程序崩溃时生成的转储文件（MDMP 结构校验通过）",
                        Consequence = "删除后无法再把这次崩溃报告发给软件厂商；不影响程序本身运行。",
                        Evidence = EvidenceKind.MagicHeader,
                        Scope = "%LOCALAPPDATA%\\CrashDumps 下结构合法的 MDMP 转储",
                        Excludes = "结构不符、内核转储头、不在 CrashDumps 内的 .dmp"
                    }
                },
                DiscoverDefaultRoots = DiscoverCrashDumpRoots,
                VerifyFile = ContentVerifier.VerifyCrashDump,
                VerifyStream = ContentVerifier.VerifyCrashDumpStream
            }
        };

        Array.Sort(raw, delegate(CacheRuleSpec a, CacheRuleSpec b) { return a.Order.CompareTo(b.Order); });
        return raw;
    }

    private static Dictionary<string, CacheRuleSpec> BuildLookup(CacheRuleSpec[] list)
    {
        Dictionary<string, CacheRuleSpec> map = new Dictionary<string, CacheRuleSpec>(StringComparer.Ordinal);
        for (int i = 0; i < list.Length; i++)
        {
            map[list[i].Id] = list[i];
        }
        return map;
    }

    // ==================== 各规则默认受控根目录动态探测 ====================

    private static string GetLocalAppData()
    {
        try
        {
            string p = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return PathGuard.Canonical(p);
        }
        catch { return ""; }
    }

    private static string GetRoamingAppData()
    {
        try
        {
            string p = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return PathGuard.Canonical(p);
        }
        catch { return ""; }
    }

    private static void AddIfValid(List<CacheRoots.Root> list, string baseAnchor, string ruleId, string dir, string why)
    {
        try
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
            string canon = PathGuard.Canonical(dir);
            if (canon.Length == 0 || !Directory.Exists(canon)) return;
            if (PathGuard.IsReparsePoint(canon)) return;
            if (!string.IsNullOrEmpty(baseAnchor) && PathGuard.IsInside(baseAnchor, canon)
                && PathGuard.HasReparseAncestor(baseAnchor, canon))
                return;
            list.Add(new CacheRoots.Root { RuleId = ruleId, Directory = canon, Why = why });
        }
        catch { }
    }

    private static bool AddIfValidUnique(
        List<CacheRoots.Root> list,
        HashSet<string> seenDirs,
        string baseAnchor,
        string ruleId,
        string dir,
        string why)
    {
        try
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return false;
            string canon = PathGuard.Canonical(dir);
            if (canon.Length == 0) return false;
            if (seenDirs != null && !seenDirs.Add(canon)) return false;
            if (!Directory.Exists(canon)) return false;
            if (PathGuard.IsReparsePoint(canon)) return false;
            if (!string.IsNullOrEmpty(baseAnchor) && PathGuard.IsInside(baseAnchor, canon)
                && PathGuard.HasReparseAncestor(baseAnchor, canon))
                return false;
            list.Add(new CacheRoots.Root { RuleId = ruleId, Directory = canon, Why = why });
            return true;
        }
        catch { return false; }
    }

    private static CacheRoots.Root[] DiscoverPkgRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        string local = GetLocalAppData();
        if (local.Length == 0) return list.ToArray();

        AddIfValid(list, local, "TMP-PKGCACHE",
            Path.Combine(local, "npm-cache", "_cacache", "content-v2", "sha512"),
            "npm 的 cacache 内容库：路径结构与内容哈希双重校验");
        AddIfValid(list, local, "TMP-PKGCACHE",
            Path.Combine(local, "pip", "cache"),
            "Python pip 包与 HTTP 缓存目录，须校验 ZIP 包头或缓存体结构");
        AddIfValid(list, local, "TMP-PKGCACHE",
            Path.Combine(local, "NuGet", "v3-cache"),
            "NuGet v3 HTTP 缓存目录，须校验包头或响应缓存结构");
        AddIfValid(list, local, "TMP-PKGCACHE",
            Path.Combine(local, "Yarn", "Cache"),
            "Yarn 本地包缓存目录，须校验 GZIP/ZIP 包头或元数据结构");
        AddIfValid(list, local, "TMP-PKGCACHE",
            Path.Combine(local, "pnpm-cache"),
            "pnpm 本地包与元数据缓存目录，须校验压缩流、哈希或 JSON 元数据");
        AddIfValid(list, local, "TMP-PKGCACHE",
            Path.Combine(local, "go-build"),
            "Go 编译缓存目录，须校验哈希分片路径与非文档结构");
        AddIfValid(list, local, "TMP-PKGCACHE",
            Path.Combine(local, "uv", "cache"),
            "Python uv 包与元数据缓存目录，须校验压缩包头或序列化结构");

        return list.ToArray();
    }

    private static CacheRoots.Root[] DiscoverBrowserRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string local = GetLocalAppData();
        string roaming = GetRoamingAppData();

        if (local.Length > 0)
        {
            CollectChromiumProfileCaches(list, seen, local, Path.Combine(local, "Microsoft", "Edge", "User Data"), "Microsoft Edge");
            CollectChromiumProfileCaches(list, seen, local, Path.Combine(local, "Google", "Chrome", "User Data"), "Google Chrome");
            CollectChromiumProfileCaches(list, seen, local, Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"), "Brave 浏览器");
            CollectChromiumProfileCaches(list, seen, local, Path.Combine(local, "Vivaldi", "User Data"), "Vivaldi 浏览器");

            CollectOperaCaches(list, seen, local, Path.Combine(local, "Opera Software", "Opera Stable"), "Opera 浏览器");
            CollectOperaCaches(list, seen, local, Path.Combine(local, "Opera Software", "Opera GX Stable"), "Opera GX 浏览器");

            CollectFirefoxProfileCaches(list, seen, local, Path.Combine(local, "Mozilla", "Firefox", "Profiles"));
        }

        if (roaming.Length > 0)
        {
            CollectOperaCaches(list, seen, roaming, Path.Combine(roaming, "Opera Software", "Opera Stable"), "Opera 浏览器");
            CollectOperaCaches(list, seen, roaming, Path.Combine(roaming, "Opera Software", "Opera GX Stable"), "Opera GX 浏览器");
        }

        return list.ToArray();
    }

    private static void CollectChromiumProfileCaches(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string localAnchor,
        string userDataDir,
        string browserName)
    {
        try
        {
            if (!Directory.Exists(userDataDir)) return;
            string canonUser = PathGuard.Canonical(userDataDir);
            if (canonUser.Length == 0 || !Directory.Exists(canonUser)) return;
            if (PathGuard.IsReparsePoint(canonUser)) return;
            if (localAnchor.Length > 0 && PathGuard.IsInside(localAnchor, canonUser)
                && PathGuard.HasReparseAncestor(localAnchor, canonUser))
                return;

            DirectoryInfo[] profiles = new DirectoryInfo(canonUser).GetDirectories();
            for (int i = 0; i < profiles.Length; i++)
            {
                DirectoryInfo profInfo = profiles[i];
                if ((profInfo.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (!IsBrowserProfileName(profInfo.Name)) continue;

                // 绝不把整个 User Data 或 Profile 当扫描根，仅加入四个具体纯缓存子目录
                DirectoryInfo[] children;
                try { children = profInfo.GetDirectories(); }
                catch { continue; }
                for (int k = 0; k < children.Length; k++)
                {
                    DirectoryInfo ch = children[k];
                    if ((ch.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                    string cn = ch.Name;
                    if (string.Equals(cn, "Cache", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            DirectoryInfo cd = new DirectoryInfo(Path.Combine(ch.FullName, "Cache_Data"));
                            if (cd.Exists)
                                AddVerifiedCleanDir(list, seen, "TMP-BROWSERCACHE", cd, browserName + " 网页缓存子目录（排除凭据与记录）");
                        }
                        catch { }
                    }
                    else if (string.Equals(cn, "Code Cache", StringComparison.OrdinalIgnoreCase))
                    {
                        AddVerifiedCleanDir(list, seen, "TMP-BROWSERCACHE", ch, browserName + " 脚本字节码缓存子目录");
                    }
                    else if (string.Equals(cn, "GPUCache", StringComparison.OrdinalIgnoreCase))
                    {
                        AddVerifiedCleanDir(list, seen, "TMP-BROWSERCACHE", ch, browserName + " GPU 着色器缓存子目录");
                    }
                    else if (string.Equals(cn, "DawnCache", StringComparison.OrdinalIgnoreCase))
                    {
                        AddVerifiedCleanDir(list, seen, "TMP-BROWSERCACHE", ch, browserName + " WebGPU Dawn 缓存子目录");
                    }
                }
            }
        }
        catch { }
    }

    private static void CollectOperaCaches(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string anchor,
        string operaDir,
        string browserName)
    {
        try
        {
            if (!Directory.Exists(operaDir)) return;
            string canonOpera = PathGuard.Canonical(operaDir);
            if (canonOpera.Length == 0 || !Directory.Exists(canonOpera)) return;
            if (PathGuard.IsReparsePoint(canonOpera)) return;
            if (anchor.Length > 0 && PathGuard.IsInside(anchor, canonOpera)
                && PathGuard.HasReparseAncestor(anchor, canonOpera))
                return;

            // 绝不把整个 Opera Stable 当扫描根，仅加入纯缓存子目录
            AddPureChromiumQuad(list, seen, canonOpera, "TMP-BROWSERCACHE", canonOpera, browserName);
            string defDir = Path.Combine(canonOpera, "Default");
            if (Directory.Exists(defDir) && !PathGuard.IsReparsePoint(defDir))
            {
                AddPureChromiumQuad(list, seen, canonOpera, "TMP-BROWSERCACHE", defDir, browserName);
            }
        }
        catch { }
    }

    private static void CollectFirefoxProfileCaches(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string localAnchor,
        string profilesDir)
    {
        try
        {
            if (!Directory.Exists(profilesDir)) return;
            string canonProfiles = PathGuard.Canonical(profilesDir);
            if (canonProfiles.Length == 0 || !Directory.Exists(canonProfiles)) return;
            if (PathGuard.IsReparsePoint(canonProfiles)) return;
            if (localAnchor.Length > 0 && PathGuard.IsInside(localAnchor, canonProfiles)
                && PathGuard.HasReparseAncestor(localAnchor, canonProfiles))
                return;

            DirectoryInfo[] profiles = new DirectoryInfo(canonProfiles).GetDirectories();
            for (int i = 0; i < profiles.Length; i++)
            {
                DirectoryInfo prof = profiles[i];
                if ((prof.Attributes & FileAttributes.ReparsePoint) != 0) continue;

                AddIfValidUnique(list, seen, canonProfiles, "TMP-BROWSERCACHE",
                    Path.Combine(prof.FullName, "cache2", "entries"),
                    "Mozilla Firefox 网页缓存子目录（排除 cookies.sqlite 与书签密码）");
                AddIfValidUnique(list, seen, canonProfiles, "TMP-BROWSERCACHE",
                    Path.Combine(prof.FullName, "startupCache"),
                    "Mozilla Firefox 启动字节码缓存子目录");
            }
        }
        catch { }
    }

    private static bool AddPureChromiumQuad(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string anchor,
        string ruleId,
        string parentDir,
        string label)
    {
        bool any = false;
        if (AddIfValidUnique(list, seen, anchor, ruleId, Path.Combine(parentDir, "Cache", "Cache_Data"),
            label + " 网页缓存子目录（排除凭据与配置）")) any = true;
        if (AddIfValidUnique(list, seen, anchor, ruleId, Path.Combine(parentDir, "Code Cache"),
            label + " 脚本字节码缓存子目录")) any = true;
        if (AddIfValidUnique(list, seen, anchor, ruleId, Path.Combine(parentDir, "GPUCache"),
            label + " GPU 着色器缓存子目录")) any = true;
        if (AddIfValidUnique(list, seen, anchor, ruleId, Path.Combine(parentDir, "DawnCache"),
            label + " WebGPU Dawn 缓存子目录")) any = true;
        return any;
    }

    internal static bool IsBrowserProfileName(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(name, "Guest Profile", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    // ==================== [2] 桌面软件与 WebView2 纯缓存子目录有界毫秒级探测 ====================

    private static CacheRoots.Root[] DiscoverAppCacheRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string local = GetLocalAppData();
        string roaming = GetRoamingAppData();
        string selfDataDir = "";
        string selfWebViewDir = "";
        try
        {
            string baseDir = PathGuard.Canonical(AppDomain.CurrentDomain.BaseDirectory);
            if (baseDir.Length > 0) selfDataDir = Path.Combine(baseDir, "data");
        }
        catch { }
        try
        {
            string envWv = Environment.GetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER");
            if (!string.IsNullOrEmpty(envWv)) selfWebViewDir = PathGuard.Canonical(envWv);
        }
        catch { }

        // 1) %APPDATA%（含 VS Code / Cursor CachedData & CachedExtensionVsiXs 及各桌面软件纯缓存四件套）
        if (roaming.Length > 0 && Directory.Exists(roaming) && !PathGuard.IsReparsePoint(roaming))
        {
            ProbeBoundedAppDataBase(list, seen, roaming, true, selfDataDir, selfWebViewDir);
        }

        // 2) %LOCALAPPDATA%（含 Steam htmlcache 及 Electron / CEF / WebView2 宿主纯缓存四件套）
        if (local.Length > 0 && Directory.Exists(local) && !PathGuard.IsReparsePoint(local))
        {
            string steamHtml = Path.Combine(local, "Steam", "htmlcache");
            if (Directory.Exists(steamHtml) && !PathGuard.IsReparsePoint(steamHtml))
            {
                AddPureChromiumQuad(list, seen, local, "TMP-APPCACHE", steamHtml, "Steam 内置网页");
            }

            ProbeBoundedAppDataBase(list, seen, local, false, selfDataDir, selfWebViewDir);
        }

        CacheRoots.Root[] result = list.ToArray();
        Array.Sort(result, delegate(CacheRoots.Root a, CacheRoots.Root b)
        {
            return StringComparer.OrdinalIgnoreCase.Compare(a.Directory, b.Directory);
        });
        return result;
    }

    private static void AddVerifiedCleanDir(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string ruleId,
        DirectoryInfo dirInfo,
        string why)
    {
        if (dirInfo == null) return;
        try
        {
            FileAttributes attr = dirInfo.Attributes;
            if ((attr & FileAttributes.Directory) == 0 || (attr & FileAttributes.ReparsePoint) != 0)
                return;
            string canon = PathGuard.CanonicalFast(dirInfo.FullName);
            if (canon.Length == 0) return;
            if (seen != null && !seen.Add(canon)) return;
            list.Add(new CacheRoots.Root { RuleId = ruleId, Directory = canon, Why = why });
        }
        catch { }
    }

    private static void ProbeBoundedAppDataBase(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string baseAnchor,
        bool isRoaming,
        string selfDataDir,
        string selfWebViewDir)
    {
        const int MaxTopDirs = 256;
        const int MaxVendorSubDirs = 16;

        DirectoryInfo[] topDirs;
        try { topDirs = new DirectoryInfo(baseAnchor).GetDirectories(); }
        catch { return; }

        int topLimit = Math.Min(topDirs.Length, MaxTopDirs);
        object mergeGate = new object();

        Parallel.For(0, topLimit, delegate(int i)
        {
            DirectoryInfo top = topDirs[i];
            try
            {
                if ((top.Attributes & FileAttributes.ReparsePoint) != 0) return;
                string topName = top.Name;
                if (ShouldSkipAppTopLevelName(topName)) return;
                string topFull = top.FullName;
                if (IsExcludedSelfOrProtectedAppRoot(topFull, topName, selfDataDir, selfWebViewDir)) return;

                DirectoryInfo[] topChildren;
                try { topChildren = top.GetDirectories(); }
                catch { return; }
                if (topChildren.Length == 0) return;

                List<CacheRoots.Root> localHits = new List<CacheRoots.Root>(4);
                bool looksLikeSingleApp;
                bool hitDepth1 = InspectAppDirChildren(
                    localHits, null, topName, topChildren,
                    isRoaming && (string.Equals(topName, "Code", StringComparison.OrdinalIgnoreCase)
                                  || string.Equals(topName, "Cursor", StringComparison.OrdinalIgnoreCase)),
                    selfDataDir, selfWebViewDir, out looksLikeSingleApp);

                if (!hitDepth1 && !looksLikeSingleApp && topChildren.Length <= MaxVendorSubDirs)
                {
                    // 深度 2：<Vendor>\<App> 有界遍历（复用已枚举的 topChildren，零重复枚举）
                    for (int k = 0; k < topChildren.Length; k++)
                    {
                        DirectoryInfo sub = topChildren[k];
                        try
                        {
                            if ((sub.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                            string subName = sub.Name;
                            if (ShouldSkipVendorSubDir(topName, subName)) continue;
                            string subFull = sub.FullName;
                            if (IsExcludedSelfOrProtectedAppRoot(subFull, subName, selfDataDir, selfWebViewDir)) continue;

                            DirectoryInfo[] subChildren;
                            try { subChildren = sub.GetDirectories(); }
                            catch { continue; }
                            if (subChildren.Length == 0) continue;

                            bool subLooksApp;
                            InspectAppDirChildren(
                                localHits, null, subName, subChildren, false,
                                selfDataDir, selfWebViewDir, out subLooksApp);
                        }
                        catch { }
                    }
                }

                if (localHits.Count > 0)
                {
                    lock (mergeGate)
                    {
                        for (int m = 0; m < localHits.Count; m++)
                        {
                            CacheRoots.Root item = localHits[m];
                            if (seen.Add(item.Directory))
                                list.Add(item);
                        }
                    }
                }
            }
            catch { }
        });
    }

    private static bool InspectAppDirChildren(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        string appLabel,
        DirectoryInfo[] children,
        bool checkEditorCaches,
        string selfDataDir,
        string selfWebViewDir,
        out bool looksLikeSingleApp)
    {
        looksLikeSingleApp = false;
        bool found = false;

        for (int i = 0; i < children.Length; i++)
        {
            DirectoryInfo ch = children[i];
            FileAttributes attr;
            try { attr = ch.Attributes; }
            catch { continue; }
            if ((attr & FileAttributes.ReparsePoint) != 0) continue;

            string n = ch.Name;
            if (string.Equals(n, "Cache", StringComparison.OrdinalIgnoreCase))
            {
                looksLikeSingleApp = true;
                if (CheckCacheDataUnderCacheDir(list, seen, ch, appLabel))
                    found = true;
            }
            else if (string.Equals(n, "Code Cache", StringComparison.OrdinalIgnoreCase))
            {
                looksLikeSingleApp = true;
                AddVerifiedCleanDir(list, seen, "TMP-APPCACHE", ch, appLabel + " 脚本字节码缓存子目录");
                found = true;
            }
            else if (string.Equals(n, "GPUCache", StringComparison.OrdinalIgnoreCase))
            {
                looksLikeSingleApp = true;
                AddVerifiedCleanDir(list, seen, "TMP-APPCACHE", ch, appLabel + " GPU 着色器缓存子目录");
                found = true;
            }
            else if (string.Equals(n, "DawnCache", StringComparison.OrdinalIgnoreCase))
            {
                looksLikeSingleApp = true;
                AddVerifiedCleanDir(list, seen, "TMP-APPCACHE", ch, appLabel + " WebGPU Dawn 缓存子目录");
                found = true;
            }
            else if (string.Equals(n, "EBWebView", StringComparison.OrdinalIgnoreCase))
            {
                looksLikeSingleApp = true;
                if (!IsExcludedSelfOrProtectedAppRoot(ch.FullName, n, selfDataDir, selfWebViewDir))
                {
                    if (InspectEbWebViewDir(list, seen, ch, appLabel))
                        found = true;
                }
            }
            else if (checkEditorCaches && string.Equals(n, "CachedData", StringComparison.OrdinalIgnoreCase))
            {
                looksLikeSingleApp = true;
                AddVerifiedCleanDir(list, seen, "TMP-APPCACHE", ch, appLabel + " V8 编译缓存子目录");
                found = true;
            }
            else if (checkEditorCaches && string.Equals(n, "CachedExtensionVsiXs", StringComparison.OrdinalIgnoreCase))
            {
                looksLikeSingleApp = true;
                AddVerifiedCleanDir(list, seen, "TMP-APPCACHE", ch, appLabel + " 插件安装包缓存子目录");
                found = true;
            }
            else if (string.Equals(n, "Local Storage", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "Session Storage", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "IndexedDB", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "blob_storage", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "Crashpad", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "User", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "Dictionaries", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "Service Worker", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "Network", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "logs", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "config", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "plugins", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "bin", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(n, "lib", StringComparison.OrdinalIgnoreCase))
            {
                looksLikeSingleApp = true;
            }
        }

        return found;
    }

    private static bool CheckCacheDataUnderCacheDir(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        DirectoryInfo cacheDir,
        string appLabel)
    {
        try
        {
            DirectoryInfo cd = new DirectoryInfo(Path.Combine(cacheDir.FullName, "Cache_Data"));
            if (!cd.Exists) return false;
            AddVerifiedCleanDir(list, seen, "TMP-APPCACHE", cd, appLabel + " 网页缓存子目录（排除凭据与配置）");
            return true;
        }
        catch { return false; }
    }

    private static bool InspectEbWebViewDir(
        List<CacheRoots.Root> list,
        HashSet<string> seen,
        DirectoryInfo ebWebViewDir,
        string appLabel)
    {
        bool found = false;
        try
        {
            DirectoryInfo[] profiles = ebWebViewDir.GetDirectories();
            int limit = Math.Min(profiles.Length, 16);
            for (int i = 0; i < limit; i++)
            {
                DirectoryInfo wp = profiles[i];
                if ((wp.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                if (!IsBrowserProfileName(wp.Name)) continue;

                DirectoryInfo[] wpChildren;
                try { wpChildren = wp.GetDirectories(); }
                catch { continue; }
                bool dummy;
                if (InspectAppDirChildren(list, seen, appLabel + " WebView2", wpChildren, false, "", "", out dummy))
                    found = true;
            }
        }
        catch { }
        return found;
    }

    private static bool ShouldSkipAppTopLevelName(string name)
    {
        if (string.IsNullOrEmpty(name)) return true;
        if (name[0] == '.' || name[0] == '{') return true;
        switch (name.ToLowerInvariant())
        {
            // 浏览器厂商与已由其他规则接管的顶层目录、系统特殊目录、安装包目录
            case "temp":
            case "tmp":
            case "packages":
            case "programs":
            case "microsoft edge":
            case "bravesoftware":
            case "vivaldi":
            case "opera software":
            case "mozilla":
            case "application data":
            case "history":
            case "temporary internet files":
            case "connecteddevicesplatform":
            case "comms":
            case "publishers":
            case "virtualstore":
            case "d3dscache":
            case "crashdumps":
            case "npm-cache":
            case "pnpm-cache":
            case "go-build":
            case "uv":
            case "pip":
            case "nuget":
            case "yarn":
            case "nvidia":
            case "nvidia corporation":
            case "amd":
            case "intel":
            case "canidelete":
            case "can-i-delete":
            case "anping":
                return true;
            default:
                return false;
        }
    }

    private static bool ShouldSkipVendorSubDir(string vendorName, string subName)
    {
        if (string.IsNullOrEmpty(subName) || subName[0] == '.') return true;
        string v = (vendorName ?? "").ToLowerInvariant();
        string s = subName.ToLowerInvariant();

        if (s == "temp" || s == "tmp" || s == "logs" || s == "crashpad" || s == "crashdumps")
            return true;

        if (v == "google" && (s == "chrome" || s.StartsWith("chrome ", StringComparison.Ordinal)))
            return true;

        if (v == "microsoft")
        {
            if (s == "edge" || s.StartsWith("edge", StringComparison.Ordinal)
                || s == "windows" || s.StartsWith("windows", StringComparison.Ordinal)
                || s == "credentials" || s == "protect" || s == "vault" || s == "crypto"
                || s == "systemcertificates" || s == "tokenbroker" || s == "identitycache"
                || s == "oneauth" || s == "cryptneturlcache" || s == "internet explorer"
                || s.StartsWith("clr_v", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsExcludedSelfOrProtectedAppRoot(
        string fullPath,
        string leafName,
        string selfDataDir,
        string selfWebViewDir)
    {
        if (!string.IsNullOrEmpty(leafName))
        {
            if (leafName.IndexOf("canidelete", StringComparison.OrdinalIgnoreCase) >= 0
                || leafName.IndexOf("can-i-delete", StringComparison.OrdinalIgnoreCase) >= 0
                || string.Equals(leafName, "anping", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (!string.IsNullOrEmpty(fullPath))
        {
            if (fullPath.IndexOf("CanIDelete", StringComparison.OrdinalIgnoreCase) >= 0
                || fullPath.IndexOf("can-i-delete", StringComparison.OrdinalIgnoreCase) >= 0
                || fullPath.IndexOf("\\AnPing\\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
            if (!string.IsNullOrEmpty(selfDataDir)
                && (PathGuard.IsInside(selfDataDir, fullPath) || PathGuard.IsInside(fullPath, selfDataDir)))
            {
                return true;
            }
            if (!string.IsNullOrEmpty(selfWebViewDir)
                && (PathGuard.IsInside(selfWebViewDir, fullPath) || PathGuard.IsInside(fullPath, selfWebViewDir)))
            {
                return true;
            }
        }

        return false;
    }

    private static CacheRoots.Root[] DiscoverThumbRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        string local = GetLocalAppData();
        if (local.Length == 0) return list.ToArray();

        AddIfValid(list, local, "TMP-THUMBCACHE",
            Path.Combine(local, "Microsoft", "Windows", "Explorer"),
            "Windows 缩略图/图标缓存目录，文件头必须是 CMMM");
        return list.ToArray();
    }

    private static CacheRoots.Root[] DiscoverShaderRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string local = GetLocalAppData();
        if (local.Length == 0) return list.ToArray();

        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "D3DSCache"),
            "DirectX 着色器缓存目录，须通过二进制头与定界结构校验");
        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "NVIDIA", "DXCache"),
            "NVIDIA DirectX 着色器缓存目录，须通过二进制帧头校验");
        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "NVIDIA", "GLCache"),
            "NVIDIA OpenGL 着色器缓存目录，须通过二进制帧头校验");
        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "NVIDIA Corporation", "NV_Cache"),
            "NVIDIA 传统着色器缓存目录，须通过二进制帧头校验");
        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "AMD", "DxCache"),
            "AMD DirectX 着色器缓存目录，须通过二进制帧头校验");
        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "AMD", "DxcCache"),
            "AMD DXC 着色器缓存目录，须通过二进制帧头校验");
        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "AMD", "GLCache"),
            "AMD OpenGL 着色器缓存目录，须通过二进制帧头校验");
        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "AMD", "VkCache"),
            "AMD Vulkan 着色器缓存目录，须通过二进制帧头校验");
        AddIfValidUnique(list, seen, local, "TMP-SHADERCACHE",
            Path.Combine(local, "Intel", "ShaderCache"),
            "Intel 图形着色器缓存目录，须通过二进制帧头校验");

        return list.ToArray();
    }

    private static CacheRoots.Root[] DiscoverSystemTempRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string local = GetLocalAppData();
        if (local.Length > 0)
        {
            AddIfValidUnique(list, seen, local, "TMP-SYSTEMP",
                Path.Combine(local, "Temp"),
                "当前用户临时目录（按分级冷却时间与内容防误删规则核验）");
        }

        if (IsCurrentProcessElevated())
        {
            try
            {
                string winDir = PathGuard.Canonical(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
                if (winDir.Length > 0)
                {
                    AddIfValidUnique(list, seen, winDir, "TMP-SYSTEMP",
                        Path.Combine(winDir, "Temp"),
                        "Windows 系统临时目录（管理员模式下按分级冷却时间与内容防误删规则核验）");
                }
            }
            catch { }
        }

        return list.ToArray();
    }

    private static CacheRoots.Root[] DiscoverWinUpdateRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        if (!IsCurrentProcessElevated()) return list.ToArray();

        try
        {
            string winDir = PathGuard.Canonical(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
            if (winDir.Length == 0) return list.ToArray();

            AddIfValid(list, winDir, "TMP-WINUPDATE",
                Path.Combine(Path.Combine(winDir, "SoftwareDistribution"), "Download"),
                "Windows Update 下载缓存目录（管理员模式下仅限满 48 小时的下载包，排除 DataStore）");
        }
        catch { }

        return list.ToArray();
    }

    private static CacheRoots.Root[] DiscoverWerRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        string local = GetLocalAppData();
        if (local.Length == 0) return list.ToArray();

        AddIfValid(list, local, "TMP-WER",
            Path.Combine(local, "Microsoft", "Windows", "WER", "ReportArchive"),
            "Windows 错误报告历史归档目录，须通过 WER/MSCF/MDMP 头结构校验");
        AddIfValid(list, local, "TMP-WER",
            Path.Combine(local, "Microsoft", "Windows", "WER", "ReportQueue"),
            "Windows 错误报告待处理队列目录，须通过 WER/MSCF/MDMP 头结构校验");
        return list.ToArray();
    }

    private static CacheRoots.Root[] DiscoverCrashDumpRoots()
    {
        List<CacheRoots.Root> list = new List<CacheRoots.Root>();
        string local = GetLocalAppData();
        if (local.Length == 0) return list.ToArray();

        AddIfValid(list, local, "TMP-CRASHDUMP",
            Path.Combine(local, "CrashDumps"),
            "Windows 崩溃转储目录，文件头必须是 MDMP 结构");
        return list.ToArray();
    }
}
