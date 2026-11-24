using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

// Display-only interpretation of existing observations. Never feeds Rules, Safety or deletion.
public static class AnPingExplanation
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);
    private const RegexOptions RxOpts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    private static readonly Regex RxBrowserProfileDir = new Regex(
        @"[\\/]((Microsoft[\\/])?Edge|(Google[\\/])?Chrome|(BraveSoftware[\\/])?Brave(-Browser)?|Vivaldi)[\\/]User Data[\\/]"
        + @"|[\\/](Opera Software[\\/])?Opera( GX)?( Stable)?[\\/]"
        + @"|[\\/](Mozilla[\\/])?Firefox[\\/]Profiles[\\/]",
        RxOpts, RegexTimeout);
    private static readonly Regex RxSdDownload = new Regex(@"[\\/]SoftwareDistribution[\\/]Download([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxChrome = new Regex(@"Google[\\/]Chrome|[\\/]Chrome[\\/]User Data", RxOpts, RegexTimeout);
    private static readonly Regex RxEdge = new Regex(@"Microsoft[\\/]Edge|[\\/]Edge[\\/]User Data", RxOpts, RegexTimeout);
    private static readonly Regex RxFirefox = new Regex(@"[\\/](Mozilla[\\/])?Firefox([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxBrave = new Regex(@"Brave-Browser|[\\/]Brave[\\/]User Data", RxOpts, RegexTimeout);
    private static readonly Regex RxVivaldi = new Regex(@"[\\/]Vivaldi([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxOpera = new Regex(@"Opera GX|Opera Stable|[\\/]Opera( Software)?[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxGoBuild = new Regex(@"[\\/]go-build([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxUvCache = new Regex(@"[\\/]uv[\\/]cache([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxNpmCache = new Regex(@"npm-cache|_cacache", RxOpts, RegexTimeout);
    private static readonly Regex RxPip = new Regex(@"[\\/]pip[\\/]|\.whl$", RxOpts, RegexTimeout);
    private static readonly Regex RxNuGet = new Regex(@"nuget|v3-cache|\.nupkg$", RxOpts, RegexTimeout);
    private static readonly Regex RxYarn = new Regex(@"yarn", RxOpts, RegexTimeout);
    private static readonly Regex RxPnpm = new Regex(@"pnpm", RxOpts, RegexTimeout);
    private static readonly Regex RxNvidia = new Regex(@"[\\/]NVIDIA([\\/]| Corporation[\\/])", RxOpts, RegexTimeout);
    private static readonly Regex RxAmd = new Regex(@"[\\/]AMD[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxIntel = new Regex(@"[\\/]Intel[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxTempInstaller = new Regex(@"[\\/]temp[\\/](is-|ns|squirreltemp|scoped_dir|msi|\{|chrome_installer|msedge_installer|(edge|chrome)_bits_|pip-|npm-[0-9]|pyinstaller-)", RxOpts, RegexTimeout);
    private static readonly Regex RxTempDir = new Regex(@"[\\/]temp[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWxWork = new Regex(@"[\\/]WXWork([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxQq = new Regex(@"Tencent[\\/]QQ|[\\/](nt_qq|Tencent Files)([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxSnsCache = new Regex(@"[\\/]Sns[\\/]Cache([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxApplet = new Regex(@"[\\/](Applet|WMPFRuntime)([\\/]|$)|\.wxapkg$", RxOpts, RegexTimeout);
    private static readonly Regex RxWeChatWeb = new Regex(@"[\\/](XPlugin|xweb|radium)([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxCode = new Regex(@"[\\/]Code( - Insiders)?[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxCursor = new Regex(@"[\\/]Cursor[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxLark = new Regex(@"[\\/](LarkShell|Feishu)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxDingTalk = new Regex(@"[\\/]DingTalk[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxCloudMusic = new Regex(@"[\\/]CloudMusic[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxDiscord = new Regex(@"[\\/]Discord[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxSlack = new Regex(@"[\\/]Slack[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxNotion = new Regex(@"[\\/]Notion[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxObsidian = new Regex(@"[\\/]Obsidian[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxPostman = new Regex(@"[\\/]Postman[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxFigma = new Regex(@"[\\/]Figma[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxTeams = new Regex(@"[\\/](Teams|MSTeams)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxSteam = new Regex(@"[\\/]Steam[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxAppQq = new Regex(@"[\\/](QQ|nt_qq)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWeMeet = new Regex(@"[\\/](WeMeet|wemeetapp)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxAppWxWork = new Regex(@"[\\/]WXWork[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxBaiduNetdisk = new Regex(@"[\\/]BaiduNetdisk[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxEbWebView = new Regex(@"[\\/]EBWebView[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxCachedVsix = new Regex(@"[\\/]CachedExtensionVsiXs[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxCachedData = new Regex(@"[\\/]CachedData[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWinCoreDir = new Regex(@"[\\/]Windows[\\/](WinSxS|System32|SysWOW64|System)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWinSxS = new Regex(@"[\\/]WinSxS[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWinSdDownload = new Regex(@"[\\/]Windows[\\/]SoftwareDistribution[\\/]Download([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxWinPrefetch = new Regex(@"[\\/]Windows[\\/]Prefetch([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxWinOld = new Regex(@"^[a-z]:[\\/]Windows\.old[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxArchivePreview = new Regex(@"[\\/]temp[\\/](7z[a-z0-9]+|rar\$[a-z0-9._-]+|wz[0-9a-f]+)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxEditorUserDir = new Regex(@"[\\/](Code( - Insiders)?|Cursor|VSCodium|Windsurf)[\\/]User[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxCursorUserDir = new Regex(@"[\\/]Cursor[\\/]User[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWeChatMsgAttach = new Regex(@"[\\/]WeChat Files[\\/][^\\/]+[\\/]FileStorage[\\/]MsgAttach[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWeChatImgExt = new Regex(@"^\.(jpg|jpeg|png|webp|heic)$", RxOpts, RegexTimeout);
    private static readonly Regex RxChatDataDir = new Regex(@"[\\/](WeChat Files|xwechat_files|WXWork|Tencent Files)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWeChatPureSub = new Regex(@"[\\/](SNS[\\/]Cache|Cache[\\/]Sns|Applet|WMPF|WMPFRuntime|XPlugin|xweb|radium)([\\/]|$)", RxOpts, RegexTimeout);
    private static readonly Regex RxQqRecvDir = new Regex(@"[\\/](FileRecv|MobileFile)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWeChatFileDir = new Regex(@"[\\/]FileStorage[\\/]File[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWxWorkFileSub = new Regex(@"[\\/](File|Cache[\\/]File|msg[\\/]file)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWxWorkCacheFileSub = new Regex(@"[\\/](Cache[\\/]File|msg[\\/]file)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWeChatVideoDir = new Regex(@"[\\/]FileStorage[\\/]Video[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWeChatImageDir = new Regex(@"[\\/]FileStorage[\\/]Image[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxWeChatMsgAttachAny = new Regex(@"[\\/]FileStorage[\\/]MsgAttach[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxChatVideoDir = new Regex(@"[\\/](MsgVideo|Video)[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxChatVideoExt = new Regex(@"^\.(mp4|mov|avi|mkv)$", RxOpts, RegexTimeout);
    private static readonly Regex RxVmDiskExt = new Regex(@"^\.(vhdx|vhd|vmdk|vdi|qcow2)$", RxOpts, RegexTimeout);
    private static readonly Regex RxWslDocker = new Regex(@"wsl|docker|ext4\.vhdx|canonical|distro", RxOpts, RegexTimeout);
    private static readonly Regex RxIsoImgExt = new Regex(@"^\.(iso|img|wim|esd)$", RxOpts, RegexTimeout);
    private static readonly Regex RxExePkgExt = new Regex(@"^\.(exe|msi|msix|appx)$", RxOpts, RegexTimeout);
    private static readonly Regex RxInstalledProgDir = new Regex(@"[\\/](Program Files|Program Files \(x86\)|WindowsApps)[\\/]|[\\/]AppData[\\/]Local[\\/]Programs[\\/]", RxOpts, RegexTimeout);
    private static readonly Regex RxInstallerName = new Regex(@"setup|install|installer|update|patch|_x64|_win64|安装包", RxOpts, RegexTimeout);
    private static readonly Regex RxArchiveExt = new Regex(@"^\.(zip|rar|7z|tar|gz|tgz|bz2|xz)$", RxOpts, RegexTimeout);
    private static readonly Regex RxMediaExt = new Regex(@"^\.(mp4|mkv|mov|avi|wmv|flv|webm|m4v|ts|mp3|flac|wav|m4a|aac|ogg)$", RxOpts, RegexTimeout);
    private static readonly Regex RxAudioExt = new Regex(@"^\.(mp3|flac|wav|m4a|aac|ogg)$", RxOpts, RegexTimeout);
    private static readonly Regex RxDesignExt = new Regex(@"^\.(psd|psb|ai|prproj|aep|blend|sketch|fig|dwg|dxf)$", RxOpts, RegexTimeout);
    private static readonly Regex RxDocExt = new Regex(@"^\.(pdf|docx|doc|xlsx|xls|pptx|ppt|csv|rtf|odt|ods|odp|vsdx|vsd|md|txt|pages|numbers|key)$", RxOpts, RegexTimeout);
    private static readonly Regex RxPhotoExt = new Regex(@"^\.(jpg|jpeg|png|webp|heic|gif|bmp|raw|cr2|nef|arw)$", RxOpts, RegexTimeout);
    private static readonly Regex RxPartialDlExt = new Regex(@"^\.(crdownload|part|download|opdownload)$", RxOpts, RegexTimeout);
    private static readonly Regex RxLogExt = new Regex(@"^\.(log|etl|evtx)$", RxOpts, RegexTimeout);
    private static readonly Regex RxBackupExt = new Regex(@"^\.(bak|old|orig)$", RxOpts, RegexTimeout);
    private static readonly Regex RxDbExt = new Regex(@"^\.(db|sqlite|sqlite3|mdb|accdb|mdf|ldf)$", RxOpts, RegexTimeout);
    private static readonly Regex RxUserDlDesktop = new Regex(@"[\\/](Downloads|Download|Desktop|桌面|下载)[\\/]", RxOpts, RegexTimeout);

    private static bool SafeIsMatch(Regex re, string input)
    {
        if (re == null || string.IsNullOrEmpty(input)) return false;
        try { return re.IsMatch(input); }
        catch { return false; }
    }

    private static string NormalizeExplanationPath(string rawPath)
    {
        if (string.IsNullOrEmpty(rawPath)) return "";
        string canon = PathGuard.Canonical(rawPath);
        if (canon.Length > 0) return canon;
        string s = rawPath.Trim();
        if (s.StartsWith("\\\\?\\", StringComparison.Ordinal) && !s.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            string stripped = s.Substring(4);
            string strippedCanon = PathGuard.Canonical(stripped);
            if (strippedCanon.Length > 0) return strippedCanon;
            return stripped;
        }
        try { return Path.GetFullPath(s); }
        catch { return s; }
    }
    public sealed class Evidence
    {
        public string state, text, strength;
        public Evidence(string s, string t, string w) { state = s; text = t; strength = w; }
    }

    public sealed class Detail
    {
        public string type, purpose, basis;
        public string summary = "";
        public string risk = "无法判断";
        public string riskText = "不知道它属于哪个程序，删除后的影响无法预估。";
        public string confidence = "无法确定";
        public string[] steps = new string[] { "不确定时，保留它。" };
        public List<Evidence> evidence = new List<Evidence>();
        public string source = "", sourceUrl = "";
    }

    public static string Confidence(IEnumerable<Evidence> evidence)
    {
        // Grades concern identification only; unexamined fields cannot raise a grade.
        int strong = 0, medium = 0;
        bool contrary = false;
        foreach (Evidence e in evidence)
        {
            if (e.state == "n") contrary = true;
            if (e.state != "y") continue;
            if (e.strength == "强证据") strong++;
            if (e.strength == "中证据") medium++;
        }
        return contrary ? "无法确定" : (strong >= 2 ? "已确认" : (strong >= 1 || medium >= 2 ? "很可能" : "无法确定"));
    }

    public static Detail For(ListRow r)
    {
        if (r == null) r = new ListRow();

        string rawPath = r.Path ?? "";
        string ext = "";
        try { ext = Path.GetExtension(rawPath).ToLowerInvariant(); }
        catch (ArgumentException) { }

        Detail d = new Detail
        {
            type = "未知文件" + (ext.Length > 0 ? "（" + ext + "）" : ""),
            purpose = "按平无法确定这个文件的用途。",
            basis = string.IsNullOrEmpty(r.RuleId) ? "没有匹配的规则" : "现有规则不能识别用途",
            summary = r.Risk == "保留" ? "系统或程序保留项 · 请勿删除" : "用途未明 · 不确定时建议保留"
        };
        if (ext.Length > 0)
            d.evidence.Add(new Evidence("y", "名称带有 " + ext + " 扩展名；单凭它不能识别用途", "弱证据"));

        string full = NormalizeExplanationPath(rawPath);
        string fileName = !string.IsNullOrEmpty(r.Name) ? r.Name : TryGetFileName(full);
        string dirName = PathGuard.Canonical(TryGetDirName(full));
        bool skipGenericUnknownProcess = false;

        string installerCache = "";
        try { installerCache = PathGuard.Canonical(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Installer")); }
        catch { }

        // 1. Windows Installer 维护缓存（微软官方 KB 2667628）
        if (!r.IsDirectory && full.Length > 0 && installerCache.Length > 0
            && (string.Equals(dirName, installerCache, StringComparison.OrdinalIgnoreCase)
                || PathGuard.IsInside(installerCache, full))
            && (ext == ".msi" || ext == ".msp" || ext == ".mst"))
        {
            d.type = "Windows 安装程序缓存";
            d.purpose = "可能是为软件修复、更新或卸载保留的安装包副本。";
            d.basis = "系统专用位置和安装包扩展名";
            d.summary = "软件修复与卸载必需 · 请保留";
            d.risk = "可能影响软件运行";
            d.riskText = "删除后，对应的软件可能无法更新、修复或正常卸载。";
            d.steps = new string[]
            {
                "保留它；按平已将这类文件归为「建议保留」。",
                "需要卸载软件时，使用设置中的正式卸载入口。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于 Windows 管理的 Installer 默认维护缓存目录", "强证据"));
            d.evidence.Add(new Evidence("y", "扩展名为安装包或补丁（" + ext + "）；未验证实际文件格式", "中证据"));
            d.source = "微软官方 · KB 2667628：缓存用于修复、更新、卸载，不应手动删除";
            d.sourceUrl = "https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/missing-windows-installer-cache";
        }
        // 2. 浏览器受保护凭据与个人数据（Edge / Chrome / Brave / Vivaldi / Opera / Firefox 的 Cookies、密码、书签、历史等）
        else if (!r.IsDirectory && IsProtectedBrowserUserData(full, fileName))
        {
            d.type = "浏览器登录与个人数据";
            d.purpose = "可能是浏览器保存的登录状态、密码、历史或书签。";
            d.basis = "浏览器配置目录位置与数据文件名";
            d.summary = "登录状态与书签密码 · 已排除保护";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后可能退出网站登录，或丢失已存密码与书签。";
            d.steps = new string[]
            {
                "保留它；浏览器缓存清理已硬性排除此类文件。",
                "如需管理凭据或记录，请在浏览器设置中操作。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于浏览器用户数据目录且命中受保护数据名称", "强证据"));
        }
        // 2b. 微信 / 企业微信 / QQ 聊天记录核心数据库硬保护（KEEP-CHATDB 或 Msg / nt_msg 下的数据库与索引）
        else if (!r.IsDirectory && IsProtectedChatDatabase(r, full))
        {
            d.type = "微信/QQ 聊天记录数据库";
            d.purpose = "保存本地全部文字聊天记录与索引的核心数据库。";
            d.basis = "聊天软件核心消息目录与数据库格式";
            d.summary = "本地聊天记录库 · 已强制保护";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后本地聊天记录将永久丢失且无法恢复。";
            d.steps = new string[]
            {
                "保留它；按平已将其强制归为「建议保留」。",
                "如需迁移聊天记录，请使用微信或 QQ 设置中的迁移功能。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于微信、企业微信或 QQ 的核心消息数据库目录（Msg / nt_msg）", "强证据"));
            d.evidence.Add(new Evidence("y", "命中本地聊天记录数据库或索引格式", "强证据"));
        }
        // 3. 受控缓存规则（无论 PolicyEligible 是 true、运行占用还是未满冷却期降级）
        else if (!r.IsDirectory && TryApplyCacheRuleExplanation(r, full, d, out skipGenericUnknownProcess))
        {
            // 已由 TryApplyCacheRuleExplanation 填充清晰一致的缓存状态说明
        }
        // 4. 非受控缓存规则但通过了内容检查的兜底
        else if (r.ContentVerified)
        {
            d.purpose = "内容符合已有格式检查；实际用途仍待核实。";
            d.basis = "已完成的内容检查";
            d.summary = "内容已检查 · 用途仍待核实";
            d.evidence.Add(new Evidence("y", r.EvidenceDetail, "强证据"));
        }
        // 5. 常见文件与系统/软件目录「人话知识库」（纯展示指导，绝不改变删除授权）
        else if (!r.IsDirectory)
        {
            ApplyHumanKnowledgeBase(r, full, fileName, ext, d);
        }

        if (!r.ContentVerified)
            d.evidence.Add(new Evidence("u", "文件内容格式和实际用途", "未检查"));
        if (!skipGenericUnknownProcess)
            d.evidence.Add(new Evidence("u", "具体所属软件、正在占用它的进程", "未读取"));
        else
            d.evidence.Add(new Evidence("u", "关闭对应程序后是否立即解除占用（重扫可确认）", "未检查"));
        d.evidence.Add(new Evidence("u", "是否有其他副本或可重建", "未检查"));
        if (string.IsNullOrEmpty(r.RuleId))
            d.evidence.Add(new Evidence("u", "没有匹配的规则", "未检查"));
        d.confidence = Confidence(d.evidence);
        return d;
    }

    private static bool IsProtectedBrowserUserData(string full, string fileName)
    {
        if (string.IsNullOrEmpty(full) || string.IsNullOrEmpty(fileName)) return false;
        if (!SafeIsMatch(RxBrowserProfileDir, full)) return false;
        return CacheRoots.IsBrowserProtectedPath(fileName, full);
    }

    private static bool IsProtectedChatDatabase(ListRow r, string full)
    {
        if (r != null && string.Equals(r.RuleId, "KEEP-CHATDB", StringComparison.Ordinal))
            return true;
        if (string.IsNullOrEmpty(full))
            return false;
        return ChatStorageLocator.IsChatDatabasePath(full);
    }

    private static bool TryApplyCacheRuleExplanation(ListRow r, string full, Detail d, out bool skipGenericUnknownProcess)
    {
        skipGenericUnknownProcess = false;
        CacheRuleSpec spec = CacheRuleRegistry.Find(r.RuleId);
        if (spec == null) return false;

        string appName, shortApp, activeType, lockedType, customPurpose;
        ResolveCacheAppIdentity(r, spec, full, out appName, out shortApp, out activeType, out lockedType, out customPurpose);

        bool isOccupied = r.LockedCleanableCache
            || ContainsText(r.Reason, "占用")
            || ContainsText(r.DenyReason, "占用");
        bool hasUnder = ContainsText(r.DenyReason, "未满")
            || ContainsText(r.Reason, "未满")
            || ContainsText(r.EvidenceDetail, "未满");
        bool hasHourUnit = ContainsText(r.DenyReason, "小时")
            || ContainsText(r.Reason, "小时")
            || ContainsText(r.EvidenceDetail, "小时")
            || ContainsText(r.DenyReason, "24h")
            || ContainsText(r.Reason, "24h")
            || ContainsText(r.DenyReason, "48h")
            || ContainsText(r.Reason, "48h");
        bool isUnderCooldown = hasUnder && hasHourUnit;
        bool outsideCacheRoot = ContainsText(r.Reason, "不在其中")
            || ContainsText(r.Reason, "不在指定的已知缓存根")
            || ContainsText(r.Reason, "不在任何已知缓存根");

        string effectivePurpose = !string.IsNullOrEmpty(customPurpose) ? customPurpose : spec.ExplainPurpose;

        // 情况 A：符合清理规则（PolicyEligible == true）
        if (r.PolicyEligible)
        {
            d.type = activeType;
            d.purpose = effectivePurpose;
            d.basis = "专用缓存目录与内容结构校验";
            d.summary = "可随主页「清理」一键清理";
            d.risk = "影响很小";
            d.riskText = spec.ExplainRiskText;
            d.steps = spec.ExplainSteps;
            d.evidence.Clear();
            if (!string.IsNullOrEmpty(r.EvidenceDetail))
                d.evidence.Add(new Evidence("y", r.EvidenceDetail, "强证据"));
            d.evidence.Add(new Evidence("y", "位于该类缓存的专用目录内", "强证据"));
            return true;
        }

        // 情况 B：正被运行中的浏览器/软件锁住占用的缓存（彻底根治精神分裂文案）
        if (isOccupied && !outsideCacheRoot)
        {
            skipGenericUnknownProcess = true;
            d.type = lockedType;
            d.purpose = effectivePurpose;
            d.basis = "缓存专用目录与运行占用状态";
            d.summary = "正被运行中的" + shortApp + "占用 · 关闭后重扫可清";
            d.risk = "影响很小";
            d.riskText = "它是可再生的缓存，但所属软件正在运行并占用它。";

            if (r.RuleId == "TMP-BROWSERCACHE")
            {
                string brLabel;
                if (appName == "Google Chrome" || appName == "Microsoft Edge" || appName == "Mozilla Firefox")
                    brLabel = " " + appName + " 浏览器";
                else if (appName == "对应浏览器")
                    brLabel = "对应浏览器";
                else
                    brLabel = " " + appName;

                d.steps = new string[]
                {
                    "关闭" + brLabel + "后点「重新扫描」，即可一并清理。",
                    "浏览器运行期间自动跳过它是正常保护。"
                };
            }
            else if (r.RuleId == "TMP-THUMBCACHE")
            {
                d.steps = new string[]
                {
                    "正被资源管理器使用，自动跳过不影响正常清理。",
                    "无需手动强行删除。"
                };
            }
            else if (r.RuleId == "TMP-WINUPDATE")
            {
                d.summary = "正被系统更新服务使用 · 待更新完成后重扫";
                d.steps = new string[]
                {
                    "系统更新服务正在使用此文件，待更新安装完成后再重新扫描。",
                    "更新运行期间自动跳过它是正常保护。"
                };
            }
            else
            {
                d.steps = new string[]
                {
                    "关闭正在运行的相关程序（" + appName + "）后点「重新扫描」，即可一并清理。",
                    "程序运行期间自动跳过它是正常保护。"
                };
            }

            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于专用缓存目录，当前正被运行中的程序占用", "强证据"));
            if (r.ContentVerified && !string.IsNullOrEmpty(r.EvidenceDetail))
                d.evidence.Add(new Evidence("y", r.EvidenceDetail, "强证据"));
            else
                d.evidence.Add(new Evidence("y", "路径与命名符合" + spec.RuleLabel + "规则", "中证据"));
            return true;
        }

        // 情况 C：未满冷却期（24 小时 / 48 小时）的近期临时文件或系统更新包
        if (isUnderCooldown)
        {
            if (r.RuleId == "TMP-WINUPDATE"
                || SafeIsMatch(RxSdDownload, full))
            {
                d.type = "Windows 更新下载缓存";
                d.purpose = "Windows Update 近期下载、可能正待安装的更新包。";
                d.basis = "系统更新缓存目录与最近修改时间";
                d.summary = "近期下载的系统更新包 · 未满 48 小时暂不清理";
                d.risk = "可能影响软件运行";
                d.riskText = "未满 48 小时的更新包可能正准备重启安装。";
                d.steps = new string[]
                {
                    "近期刚下载的系统更新包会自动跳过保护，避免打断安装。",
                    "更新完成并超过 48 小时后重扫即可自动纳入清理。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于系统更新下载目录，距最后修改未满 48 小时冷却保护期", "强证据"));
                return true;
            }

            d.type = "近期生成的临时文件";
            d.purpose = "软件近期刚写入临时目录的文件，可能仍在使用。";
            d.basis = "临时目录位置与最近修改时间";
            d.summary = "近期生成的临时文件 · 暂不清理";
            d.risk = "可能影响软件运行";
            d.riskText = "刚生成的临时文件可能正在参与安装或运行。";
            d.steps = new string[]
            {
                "刚生成不久的临时文件会自动跳过保护。",
                "过一两天不再使用后重扫即可自动纳入清理。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于用户临时目录，距最后修改时间尚处于冷却保护期内", "强证据"));
            return true;
        }

        // 若仅仅是因为文件名在普通目录撞上了缓存规则名（不在缓存根内），交由通用人话知识库诚实解释
        if (outsideCacheRoot)
        {
            return false;
        }

        // 情况 D：位于缓存目录内，但因检测到文档/程序头或格式未在白名单而被安全拦截
        if (ContainsText(r.Reason, "文档或程序头") || ContainsText(r.EvidenceDetail, "文档或程序头")
            || ContainsText(r.Reason, "个人文档") || ContainsText(r.EvidenceDetail, "个人文档")
            || ContainsText(r.EvidenceDetail, "Office") || ContainsText(r.EvidenceDetail, "PDF"))
        {
            d.type = "疑似文档或程序（位于缓存目录）";
            d.purpose = "虽在缓存或临时目录，但文件头疑似文档或程序。";
            d.basis = "文件头安全复核拦截";
            d.summary = "文件头疑似个人内容 · 已拦截保护";
            d.risk = "可能丢失你的内容";
            d.riskText = "可能是临时打开或下载的内容，直接删除可能丢失数据。";
            d.steps = new string[]
            {
                "在资源管理器中查看是否仍需要此文件。",
                "按平已自动排除它以保护你的内容。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", !string.IsNullOrEmpty(r.EvidenceDetail) ? r.EvidenceDetail : "文件头命中文档或程序保护特征", "强证据"));
            return true;
        }

        d.type = activeType + "（待核实）";
        d.purpose = "位于缓存目录，但文件结构不在自动清理白名单内。";
        d.basis = "缓存目录位置与文件结构复核";
        d.summary = "缓存目录辅助或待核实项 · 建议保留";
        d.risk = "可能影响软件运行";
        d.riskText = "可能是缓存索引或辅助状态文件，自动清理默认跳过。";
        d.steps = new string[]
        {
            "建议保留；常规缓存清理无需删除此文件。",
            "交由所属程序自行管理即可。"
        };
        d.evidence.Clear();
        if (r.ContentVerified && !string.IsNullOrEmpty(r.EvidenceDetail))
            d.evidence.Add(new Evidence("y", r.EvidenceDetail, "强证据"));
        else
            d.evidence.Add(new Evidence("y", "位于缓存目录，但未通过自动清理结构白名单", "中证据"));
        return true;
    }

    private static void ResolveCacheAppIdentity(
        ListRow r,
        CacheRuleSpec spec,
        string full,
        out string appName,
        out string shortApp,
        out string activeType,
        out string lockedType,
        out string customPurpose)
    {
        appName = !string.IsNullOrEmpty(r.App) ? r.App : spec.RuleLabel;
        shortApp = "程序";
        activeType = spec.ExplainType;
        lockedType = spec.ExplainType + "（正在使用）";
        customPurpose = "";

        if (r.RuleId == "TMP-BROWSERCACHE")
        {
            if (SafeIsMatch(RxChrome, full))
            {
                appName = "Google Chrome";
                shortApp = " Chrome ";
                activeType = "Chrome 网页与渲染缓存";
                lockedType = "Chrome 缓存（正在使用）";
            }
            else if (SafeIsMatch(RxEdge, full))
            {
                appName = "Microsoft Edge";
                shortApp = " Edge ";
                activeType = "Edge 网页与渲染缓存";
                lockedType = "Edge 缓存（正在使用）";
            }
            else if (SafeIsMatch(RxFirefox, full))
            {
                appName = "Mozilla Firefox";
                shortApp = " Firefox ";
                activeType = "Firefox 网页缓存";
                lockedType = "Firefox 缓存（正在使用）";
                customPurpose = "Mozilla Firefox 保存的网页资源或启动缓存。";
            }
            else if (SafeIsMatch(RxBrave, full))
            {
                appName = "Brave 浏览器";
                shortApp = " Brave ";
                activeType = "Brave 浏览器缓存";
                lockedType = "Brave 缓存（正在使用）";
                customPurpose = "Brave 浏览器保存的网页资源、脚本或渲染缓存。";
            }
            else if (SafeIsMatch(RxVivaldi, full))
            {
                appName = "Vivaldi 浏览器";
                shortApp = " Vivaldi ";
                activeType = "Vivaldi 浏览器缓存";
                lockedType = "Vivaldi 缓存（正在使用）";
                customPurpose = "Vivaldi 浏览器保存的网页资源、脚本或渲染缓存。";
            }
            else if (SafeIsMatch(RxOpera, full))
            {
                appName = "Opera 浏览器";
                shortApp = " Opera ";
                activeType = "Opera 浏览器缓存";
                lockedType = "Opera 缓存（正在使用）";
                customPurpose = "Opera 浏览器保存的网页资源、脚本或渲染缓存。";
            }
            else
            {
                appName = "对应浏览器";
                shortApp = "浏览器";
            }
        }
        else if (r.RuleId == "TMP-APPCACHE")
        {
            ResolveDesktopAppCacheIdentity(spec, full, out appName, out shortApp, out activeType, out lockedType, out customPurpose);
        }
        else if (r.RuleId == "TMP-THUMBCACHE")
        {
            appName = "Windows 资源管理器";
            shortApp = "资源管理器";
        }
        else if (r.RuleId == "TMP-PKGCACHE")
        {
            if (SafeIsMatch(RxGoBuild, full))
            {
                appName = "Go 工具链";
                shortApp = " Go ";
                activeType = "Go 编译缓存";
                lockedType = "Go 编译缓存（正在使用）";
                customPurpose = "Go 编译器生成的中间构建与增量编译缓存。";
            }
            else if (SafeIsMatch(RxUvCache, full))
            {
                appName = "Python uv";
                shortApp = " uv ";
                activeType = "Python uv 缓存";
                lockedType = "Python uv 缓存（正在使用）";
                customPurpose = "Python uv 包管理器下载的离线轮子与元数据缓存。";
            }
            else if (SafeIsMatch(RxNpmCache, full))
            {
                appName = "npm";
                shortApp = " npm ";
            }
            else if (SafeIsMatch(RxPip, full))
            {
                appName = "Python pip";
                shortApp = " pip ";
            }
            else if (SafeIsMatch(RxNuGet, full))
            {
                appName = "NuGet";
                shortApp = " NuGet ";
            }
            else if (SafeIsMatch(RxYarn, full))
            {
                appName = "Yarn";
                shortApp = " Yarn ";
            }
            else if (SafeIsMatch(RxPnpm, full))
            {
                appName = "pnpm";
                shortApp = " pnpm ";
            }
            else
            {
                appName = "开发工具";
                shortApp = "开发工具";
            }
        }
        else if (r.RuleId == "TMP-SHADERCACHE")
        {
            if (SafeIsMatch(RxNvidia, full))
            {
                appName = "NVIDIA 显卡驱动";
                shortApp = "显卡驱动";
                activeType = "NVIDIA 着色器缓存";
                lockedType = "NVIDIA 着色器缓存（正在使用）";
                customPurpose = "NVIDIA 显卡驱动保存的已编译图形着色器缓存。";
            }
            else if (SafeIsMatch(RxAmd, full))
            {
                appName = "AMD 显卡驱动";
                shortApp = "显卡驱动";
                activeType = "AMD 着色器缓存";
                lockedType = "AMD 着色器缓存（正在使用）";
                customPurpose = "AMD 显卡驱动保存的已编译图形着色器缓存。";
            }
            else if (SafeIsMatch(RxIntel, full))
            {
                appName = "Intel 图形驱动";
                shortApp = "图形驱动";
                activeType = "Intel 着色器缓存";
                lockedType = "Intel 着色器缓存（正在使用）";
                customPurpose = "Intel 图形驱动保存的已编译图形着色器缓存。";
            }
            else
            {
                appName = "DirectX 图形程序";
                shortApp = "图形程序";
            }
        }
        else if (r.RuleId == "TMP-SYSTEMP")
        {
            appName = "后台程序";
            shortApp = "程序";
            lockedType = "系统临时文件（正在使用）";
            if (SafeIsMatch(RxTempInstaller, full))
            {
                activeType = "过期的安装或解压临时残留";
                lockedType = "安装或解压临时文件（正在使用）";
                customPurpose = "软件安装、更新或解包完成后遗留的旧临时文件。";
            }
            else if (SafeIsMatch(RxTempDir, full)
                     && (full.EndsWith(".log", StringComparison.OrdinalIgnoreCase)
                         || full.EndsWith(".etl", StringComparison.OrdinalIgnoreCase)))
            {
                activeType = "过期的临时诊断日志";
                lockedType = "临时诊断日志（正在使用）";
                customPurpose = "临时目录中超过冷却期未再写入的旧运行日志。";
            }
        }
        else if (r.RuleId == "TMP-WER")
        {
            appName = "Windows 错误报告服务";
            shortApp = "错误报告服务";
            lockedType = "Windows 错误报告（正在使用）";
        }
        else if (r.RuleId == "TMP-CHATCACHE")
        {
            if (SafeIsMatch(RxWxWork, full))
            {
                appName = "企业微信";
                shortApp = "企业微信";
                activeType = "企业微信缓存";
                lockedType = "企业微信缓存（正在使用）";
                customPurpose = "企业微信自动生成的动态媒体或内置网页缓存。";
            }
            else if (SafeIsMatch(RxQq, full))
            {
                appName = "QQ";
                shortApp = " QQ ";
                activeType = "QQ 临时与网页缓存";
                lockedType = "QQ 缓存（正在使用）";
                customPurpose = "QQ 运行期间生成的临时缓存与内置网页资源。";
            }
            else if (SafeIsMatch(RxSnsCache, full))
            {
                appName = "微信";
                shortApp = "微信";
                activeType = "微信朋友圈缓存";
                lockedType = "微信朋友圈缓存（正在使用）";
                customPurpose = "浏览微信朋友圈时自动缓存的图片或视频副本。";
            }
            else if (SafeIsMatch(RxApplet, full))
            {
                appName = "微信";
                shortApp = "微信";
                activeType = "微信小程序缓存";
                lockedType = "微信小程序缓存（正在使用）";
                customPurpose = "打开微信小程序时自动下载的运行包与资源缓存。";
            }
            else if (SafeIsMatch(RxWeChatWeb, full))
            {
                appName = "微信";
                shortApp = "微信";
                activeType = "微信内置网页缓存";
                lockedType = "微信网页缓存（正在使用）";
                customPurpose = "微信内置浏览器与组件生成的网页渲染缓存。";
            }
            else
            {
                appName = "聊天软件";
                shortApp = "聊天软件";
            }
        }
        else if (r.RuleId == "TMP-WINUPDATE")
        {
            appName = "Windows Update 服务";
            shortApp = "系统更新服务";
            lockedType = "Windows 更新下载缓存（正在使用）";
        }
        else if (r.RuleId == "TMP-CRASHDUMP")
        {
            appName = "调试或错误报告工具";
            shortApp = "程序";
        }
    }

    private static void ResolveDesktopAppCacheIdentity(
        CacheRuleSpec spec,
        string full,
        out string appName,
        out string shortApp,
        out string activeType,
        out string lockedType,
        out string customPurpose)
    {
        appName = "对应桌面软件";
        shortApp = "桌面软件";
        activeType = spec.ExplainType;
        lockedType = spec.ExplainType + "（正在使用）";
        customPurpose = "";

        string matchedApp = "";
        string matchedShort = "";
        if (SafeIsMatch(RxCode, full))
        {
            matchedApp = "VS Code";
            matchedShort = " VS Code ";
        }
        else if (SafeIsMatch(RxCursor, full))
        {
            matchedApp = "Cursor";
            matchedShort = " Cursor ";
        }
        else if (SafeIsMatch(RxLark, full))
        {
            matchedApp = "飞书";
            matchedShort = "飞书";
        }
        else if (SafeIsMatch(RxDingTalk, full))
        {
            matchedApp = "钉钉";
            matchedShort = "钉钉";
        }
        else if (SafeIsMatch(RxCloudMusic, full))
        {
            matchedApp = "网易云音乐";
            matchedShort = "网易云音乐";
        }
        else if (SafeIsMatch(RxDiscord, full))
        {
            matchedApp = "Discord";
            matchedShort = " Discord ";
        }
        else if (SafeIsMatch(RxSlack, full))
        {
            matchedApp = "Slack";
            matchedShort = " Slack ";
        }
        else if (SafeIsMatch(RxNotion, full))
        {
            matchedApp = "Notion";
            matchedShort = " Notion ";
        }
        else if (SafeIsMatch(RxObsidian, full))
        {
            matchedApp = "Obsidian";
            matchedShort = " Obsidian ";
        }
        else if (SafeIsMatch(RxPostman, full))
        {
            matchedApp = "Postman";
            matchedShort = " Postman ";
        }
        else if (SafeIsMatch(RxFigma, full))
        {
            matchedApp = "Figma";
            matchedShort = " Figma ";
        }
        else if (SafeIsMatch(RxTeams, full))
        {
            matchedApp = "Microsoft Teams";
            matchedShort = " Teams ";
        }
        else if (SafeIsMatch(RxSteam, full))
        {
            matchedApp = "Steam";
            matchedShort = " Steam ";
        }
        else if (SafeIsMatch(RxAppQq, full))
        {
            matchedApp = "QQ";
            matchedShort = " QQ ";
        }
        else if (SafeIsMatch(RxWeMeet, full))
        {
            matchedApp = "腾讯会议";
            matchedShort = "腾讯会议";
        }
        else if (SafeIsMatch(RxAppWxWork, full))
        {
            matchedApp = "企业微信";
            matchedShort = "企业微信";
        }
        else if (SafeIsMatch(RxBaiduNetdisk, full))
        {
            matchedApp = "百度网盘";
            matchedShort = "百度网盘";
        }
        else if (SafeIsMatch(RxEbWebView, full))
        {
            matchedApp = "WebView2 桌面组件";
            matchedShort = "桌面组件";
        }

        if (matchedApp.Length == 0)
        {
            return;
        }

        appName = matchedApp;
        shortApp = matchedShort;
        if (SafeIsMatch(RxCachedVsix, full))
        {
            activeType = matchedApp + " 插件安装包缓存";
            customPurpose = matchedApp + " 下载安装扩展后留存的离线插件包副本。";
        }
        else if (SafeIsMatch(RxCachedData, full))
        {
            activeType = matchedApp + " 编译字节码缓存";
            customPurpose = matchedApp + " 为加速界面启动生成的脚本编译缓存。";
        }
        else if (matchedApp == "WebView2 桌面组件")
        {
            activeType = "WebView2 桌面组件缓存";
            customPurpose = "桌面软件内置 WebView2 组件保存的网页与渲染缓存。";
        }
        else
        {
            activeType = matchedApp + " 缓存";
            customPurpose = matchedApp + " 保存的界面渲染、脚本或内置网页缓存。";
        }
        lockedType = (matchedApp == "WebView2 桌面组件" ? "WebView2 组件缓存" : (matchedApp + " 缓存")) + "（正在使用）";
    }

    private static void ApplyHumanKnowledgeBase(ListRow r, string full, string fileName, string ext, Detail d)
    {
        // A. 系统休眠、虚拟内存、组件库与旧系统升级备份
        if (string.Equals(fileName, "hiberfil.sys", StringComparison.OrdinalIgnoreCase))
        {
            d.type = "Windows 休眠状态文件";
            d.purpose = "系统休眠与快速启动保存内存状态的系统文件。";
            d.basis = "Windows 系统根文件名称";
            d.summary = "系统休眠专用文件 · 不可手动删除";
            d.risk = "可能影响软件运行";
            d.riskText = "系统正在锁定管理它，不可直接手动删除。";
            d.steps = new string[]
            {
                "保留它；Windows 会自动管理其占用。",
                "若完全不用休眠，可在管理员命令行用 powercfg /h off 关闭。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "文件名为 Windows 休眠专用系统文件 hiberfil.sys", "强证据"));
            return;
        }

        if (string.Equals(fileName, "pagefile.sys", StringComparison.OrdinalIgnoreCase)
            || string.Equals(fileName, "swapfile.sys", StringComparison.OrdinalIgnoreCase))
        {
            d.type = "Windows 虚拟内存交换文件";
            d.purpose = "物理内存不足时，系统借用磁盘空间的虚拟内存。";
            d.basis = "Windows 虚拟内存页面文件名";
            d.summary = "系统虚拟内存 · 不可手动删除";
            d.risk = "可能影响软件运行";
            d.riskText = "系统运行期间持续占用，不可手动删除。";
            d.steps = new string[]
            {
                "保留它；强行禁用虚拟内存可能导致大型软件闪退。",
                "如需迁移盘符，请在「高级系统设置 → 虚拟内存」调整。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "文件名为 Windows 虚拟内存交换文件（" + fileName + "）", "强证据"));
            return;
        }

        if (SafeIsMatch(RxWinCoreDir, full))
        {
            bool isWinSxS = SafeIsMatch(RxWinSxS, full);
            d.type = isWinSxS ? "Windows 组件存储库 (WinSxS)" : "Windows 系统核心组件";
            d.purpose = "Windows 运行、更新与驱动依赖的核心系统组件。";
            d.basis = "位于 Windows 受保护核心系统目录";
            d.summary = "Windows 核心组件 · 严禁手动删除";
            d.risk = "可能影响软件运行";
            d.riskText = "手动删除会导致系统功能损坏甚至无法开机。";
            d.steps = new string[]
            {
                "保留它；按平已将系统核心目录硬性保护。",
                "如需精简旧更新备份，请使用系统设置中的「存储感知」。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于 Windows 核心系统组件目录", "强证据"));
            return;
        }

        if (SafeIsMatch(RxWinSdDownload, full))
        {
            d.type = "Windows 更新下载缓存";
            d.purpose = "系统更新下载的安装包缓存副本。";
            d.basis = "位于 Windows 更新下载缓存目录";
            d.summary = "系统更新缓存 · 可由系统存储感知清理";
            d.risk = "影响很小";
            d.riskText = "已安装完的更新缓存可在系统存储感知中清理。";
            d.steps = new string[]
            {
                "不要在系统正在下载或安装更新时手动强删。",
                "可在「Windows 设置 → 系统 → 存储 → 临时文件」中清理。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于 Windows SoftwareDistribution\\Download 更新缓存目录", "强证据"));
            return;
        }

        if (SafeIsMatch(RxWinPrefetch, full))
        {
            d.type = "Windows 启动预读取优化文件";
            d.purpose = "系统记录常用软件启动顺序以加速打开的数据。";
            d.basis = "位于 Windows Prefetch 预读取目录";
            d.summary = "系统启动加速数据 · 建议保留";
            d.risk = "不建议删除";
            d.riskText = "删后不会省多少空间，反而会让软件下次启动变慢。";
            d.steps = new string[]
            {
                "保留它；Windows 会自动维护并限制该目录体积。",
                "手动清空只会让常用软件下次打开变慢。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于 Windows Prefetch 启动预读取专用目录", "强证据"));
            return;
        }

        if (SafeIsMatch(RxWinOld, full))
        {
            d.type = "旧版 Windows 升级备份文件";
            d.purpose = "系统大版本升级后留存的旧系统备份（Windows.old）。";
            d.basis = "位于系统盘 Windows.old 备份目录";
            d.summary = "旧系统升级备份 · 请用系统存储设置清理";
            d.risk = "可能影响软件运行";
            d.riskText = "清理后无法回退旧系统；切勿手动零散删除内部文件。";
            d.steps = new string[]
            {
                "不要手动单删内部文件（易产生权限残留）。",
                "确认新系统稳定后，在「Windows 设置 → 系统 → 存储 → 临时文件」中完整清理。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于 Windows.old 旧系统升级备份目录", "强证据"));
            return;
        }

        if (SafeIsMatch(RxArchivePreview, full))
        {
            d.type = "压缩包临时预览文件" + (ext.Length > 0 ? " (" + ext + ")" : "");
            d.purpose = "在压缩软件内直接打开文件时临时解压出的副本。";
            d.basis = "压缩软件临时预览目录与文件类型";
            d.summary = "压缩包预览副本 · 确认已另存前请保留";
            d.risk = "可能丢失你的内容";
            d.riskText = "若在预览时编辑过但未另存到别处，直接删除会丢失修改。";
            d.steps = new string[]
            {
                "先确认原压缩包仍在，且预览中的修改已另存妥当。",
                "按平已排除压缩软件预览目录，防止误删个人文档。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于 7-Zip / WinRAR 等压缩软件临时预览目录", "强证据"));
            return;
        }

        if (SafeIsMatch(RxEditorUserDir, full) && string.Equals(ext, ".json", StringComparison.OrdinalIgnoreCase))
        {
            bool isCursor = SafeIsMatch(RxCursorUserDir, full);
            string edName = isCursor ? "Cursor" : "VS Code";
            d.type = edName + " 个人配置文件 (.json)";
            d.purpose = edName + " 保存的个人偏好设置、快捷键或状态配置。";
            d.basis = "编辑器用户配置目录与配置文件名";
            d.summary = edName + " 个人配置 · 已排除保护";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后会丢失你的编辑器个性化设置或快捷键。";
            d.steps = new string[]
            {
                "保留它；桌面软件缓存清理已硬性排除 User 配置目录。",
                "如需调整选项，请在编辑器设置界面操作。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于 " + edName + " 用户个人配置目录（User）", "强证据"));
            return;
        }

        // B. 微信 / 企业微信 / QQ 聊天数据目录
        if (SafeIsMatch(RxWeChatMsgAttach, full)
            && SafeIsMatch(RxWeChatImgExt, ext))
        {
            d.type = "微信收到的图片";
            d.purpose = "可能是微信收到的图片；是否原图尚未核实。";
            d.basis = "微信附件专用路径和图片扩展名";
            d.summary = "微信聊天图片 · 删后聊天内无法查看";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后，聊天里的图片可能无法再打开；其他副本尚未核实。";
            d.steps = new string[]
            {
                "先在微信里确认这张图片是否已保存到别处。",
                "没有确认其他副本时，保留它。"
            };
            d.evidence.Add(new Evidence("y", "路径符合微信接收附件目录（WeChat Files / FileStorage / MsgAttach）", "强证据"));
            return;
        }

        if (SafeIsMatch(RxChatDataDir, full)
            || ChatStorageLocator.IsChatReceivedUserFile(full))
        {
            if (SafeIsMatch(RxWeChatPureSub, full))
            {
                bool isSns = SafeIsMatch(RxSnsCache, full);
                d.type = isSns ? "微信朋友圈缓存" : "微信小程序缓存";
                d.purpose = "浏览朋友圈或打开小程序自动生成的缓存，非聊天原件。";
                d.basis = "微信朋友圈或小程序专用缓存目录";
                d.summary = "朋友圈或小程序缓存 · 可在微信设置内清理";
                d.risk = "影响很小";
                d.riskText = "属于朋友圈或小程序缓存（非聊天原件），按需会自动重下。";
                d.steps = new string[]
                {
                    "可在微信「设置 → 存储空间 → 缓存」中安全清理。",
                    "不会删除聊天文字记录或聊天收发的文件原件。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于微信朋友圈（SNS\\Cache）或小程序（Applet / WMPF）缓存目录", "强证据"));
                return;
            }

            if (SafeIsMatch(RxQqRecvDir, full))
            {
                d.type = "QQ 聊天接收文件";
                d.purpose = "QQ 好友、群聊或手机传来的文件原件。";
                d.basis = "QQ 接收文件专用目录（FileRecv / MobileFile）";
                d.summary = "QQ 聊天接收文件 · 无用可移入回收站";
                d.risk = "可能丢失你的内容";
                d.riskText = "若发送方已过期未另存，删除后可能无法重新下载。";
                d.steps = new string[]
                {
                    "先确认重要文件已另存到其他文件夹。",
                    "确认不再需要后，可在下方点「移入回收站」。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于 QQ 聊天接收文件专用目录（FileRecv / MobileFile）", "强证据"));
                return;
            }

            if (SafeIsMatch(RxWeChatFileDir, full))
            {
                d.type = "微信聊天接收文件";
                d.purpose = "好友或群聊发送并下载到本地的文档或压缩包。";
                d.basis = "微信聊天接收文件专用目录";
                d.summary = "微信聊天接收文件 · 无用可移入回收站";
                d.risk = "可能丢失你的内容";
                d.riskText = "若发送方已过期未另存，删除后可能无法重新下载。";
                d.steps = new string[]
                {
                    "先确认重要工作或个人文件已另存到其他文件夹。",
                    "确认不再需要后，可在下方点「移入回收站」。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于微信聊天接收文件专用目录（FileStorage\\File）", "强证据"));
                return;
            }

            if ((SafeIsMatch(RxWxWork, full) && SafeIsMatch(RxWxWorkFileSub, full))
                || SafeIsMatch(RxWxWorkCacheFileSub, full))
            {
                d.type = "企业微信聊天接收文件";
                d.purpose = "企业微信会话中接收下载的工作文档或附件。";
                d.basis = "企业微信接收文件专用目录";
                d.summary = "企业微信接收文件 · 无用可移入回收站";
                d.risk = "可能丢失你的内容";
                d.riskText = "若会话文件已过期未另存，删除后可能无法重新下载。";
                d.steps = new string[]
                {
                    "先确认重要工作文件已另存到其他文件夹。",
                    "确认不再需要后，可在下方点「移入回收站」。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于企业微信接收文件专用目录", "强证据"));
                return;
            }

            if (SafeIsMatch(RxWeChatVideoDir, full))
            {
                d.type = "微信聊天视频";
                d.purpose = "聊天中接收或保存的视频文件。";
                d.basis = "微信聊天视频专用目录";
                d.summary = "微信聊天视频 · 确认无用可移入回收站";
                d.risk = "可能丢失你的内容";
                d.riskText = "删除后对应聊天记录里的视频将无法再次播放。";
                d.steps = new string[]
                {
                    "先确认重要视频是否已导出保存。",
                    "确认无需保留后，可在下方点「移入回收站」。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于微信聊天视频存储目录（FileStorage\\Video）", "强证据"));
                return;
            }

            if (SafeIsMatch(RxWeChatImageDir, full)
                || (SafeIsMatch(RxWeChatMsgAttachAny, full) && ext == ".dat"))
            {
                d.type = "微信聊天加密图片";
                d.purpose = "微信聊天中接收的图片本地加密存储文件。";
                d.basis = "微信聊天加密图片存储目录";
                d.summary = "微信聊天图片数据 · 谨慎处理";
                d.risk = "可能丢失你的内容";
                d.riskText = "删除后聊天记录里的对应图片将无法查看。";
                d.steps = new string[]
                {
                    "不确定是否为重要聊天图片时请保留。",
                    "也可在微信「设置 → 存储空间 → 聊天数据」按会话管理。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于微信聊天加密图片存储目录（FileStorage\\Image）", "强证据"));
                return;
            }

            if (SafeIsMatch(RxChatVideoDir, full)
                || SafeIsMatch(RxChatVideoExt, ext))
            {
                d.type = "微信 / QQ 聊天视频";
                d.purpose = "聊天或群聊中接收播放并保存在本地的视频。";
                d.basis = "聊天软件视频存储目录";
                d.summary = "聊天保存的视频 · 确认无用可移入回收站";
                d.risk = "可能丢失你的内容";
                d.riskText = "删除后对应聊天记录里的视频将无法再次播放。";
                d.steps = new string[]
                {
                    "先确认重要视频是否已导出保存。",
                    "也可在微信/QQ「设置 → 存储空间」按群聊管理。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于聊天软件视频目录且符合视频特征", "强证据"));
                return;
            }

            d.type = "聊天软件本地数据或缓存";
            d.purpose = "聊天软件生成的预览缩略图、语音或本地记录文件。";
            d.basis = "位于微信或 QQ 本地数据目录";
            d.summary = "聊天本地数据 · 建议在软件设置内管理";
            d.risk = "可能丢失你的内容";
            d.riskText = "直接手动删除可能导致聊天记录、表情或附件损坏。";
            d.steps = new string[]
            {
                "优先使用微信或 QQ 内置的「存储空间管理」清理缓存。",
                "不确定用途的聊天目录文件请保留。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "位于微信或 QQ 本地数据目录", "强证据"));
            return;
        }

        // C. 虚拟机与容器磁盘映像（WSL / Docker / Hyper-V / VMware）
        if (SafeIsMatch(RxVmDiskExt, ext))
        {
            bool isWslOrDocker = SafeIsMatch(RxWslDocker, full);
            d.type = isWslOrDocker ? ("WSL / Docker 虚拟磁盘镜像 (" + ext + ")") : ("虚拟机磁盘镜像 (" + ext + ")");
            d.purpose = isWslOrDocker
                ? "WSL Linux 子系统或 Docker 容器的完整虚拟硬盘。"
                : "虚拟机软件使用的整块虚拟硬盘映像文件。";
            d.basis = isWslOrDocker ? "虚拟磁盘扩展名与子系统/容器路径" : "虚拟机磁盘镜像扩展名";
            d.summary = isWslOrDocker ? "子系统/容器虚拟硬盘 · 切勿直接删除" : "虚拟机硬盘镜像 · 切勿随意删除";
            d.risk = "可能丢失你的内容";
            d.riskText = isWslOrDocker
                ? "直接删除会毁掉整个 Linux 子系统或全部容器数据！"
                : "删除后虚拟机内的系统与全部文件将一并丢失。";
            d.steps = isWslOrDocker
                ? new string[]
                {
                    "切勿直接删除文件！请在 Docker 或 wsl 命令中清理无用镜像。",
                    "清理内部数据后可用 Optimize-VHD 或 diskpart 压缩虚拟盘体积。"
                }
                : new string[]
                {
                    "切勿直接删除正在使用的虚拟机磁盘文件。",
                    "仅当整台虚拟机已废弃时，在虚拟机软件中移除。"
                };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为虚拟磁盘镜像格式（" + ext + "）", isWslOrDocker ? "强证据" : "中证据"));
            if (isWslOrDocker)
                d.evidence.Add(new Evidence("y", "路径命中 WSL 或 Docker 容器存储目录", "强证据"));
            return;
        }

        // D. 光盘镜像与安装包（.iso / .img / .exe / .msi）
        if (SafeIsMatch(RxIsoImgExt, ext))
        {
            d.type = ext == ".iso" ? "光盘镜像 (.iso)" : ("系统或磁盘镜像 (" + ext + ")");
            d.purpose = "操作系统、大型软件或游戏的光盘安装镜像文件。";
            d.basis = "光盘或磁盘映像扩展名";
            d.summary = "安装完无需保留时可移入回收站";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除不影响已装好的系统或软件，但重装时需重新下载。";
            d.steps = new string[]
            {
                "若系统或软件已安装完成且无需留作备份，可点「移入回收站」。",
                "若是重要系统恢复盘镜像，建议转移到外部硬盘保存。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为标准光盘或系统映像格式（" + ext + "）", "中证据"));
            if (IsUserDownloadOrDesktop(full))
                d.evidence.Add(new Evidence("y", "位于下载或桌面个人目录", "中证据"));
            return;
        }

        if (SafeIsMatch(RxExePkgExt, ext))
        {
            if (SafeIsMatch(RxInstalledProgDir, full))
            {
                d.type = "已安装软件程序文件 (" + ext + ")";
                d.purpose = "已安装软件的主程序或运行组件。";
                d.basis = "位于软件安装目录与可执行扩展名";
                d.summary = "已安装软件组件 · 请通过系统设置卸载";
                d.risk = "可能影响软件运行";
                d.riskText = "直接单删安装目录内的程序文件会导致该软件无法运行。";
                d.steps = new string[]
                {
                    "不要手动单删软件安装目录里的文件。",
                    "如不再使用该软件，请在「Windows 设置 → 应用」中正式卸载。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "位于标准软件安装目录内", "强证据"));
                return;
            }

            bool looksInstaller = ext == ".msi" || ext == ".msix" || ext == ".appx"
                || IsUserDownloadOrDesktop(full)
                || SafeIsMatch(RxInstallerName, fileName);

            if (looksInstaller)
            {
                d.type = ext == ".msi" ? "软件安装程序包 (.msi)" : ("软件安装包或程序 (" + ext + ")");
                d.purpose = "下载的软件安装程序或独立运行工具。";
                d.basis = "位于下载/桌面目录或命中安装包特征";
                d.summary = "软件装完无需留备份时可移入回收站";
                d.risk = "可能丢失你的内容";
                d.riskText = "普通安装包删后不影响已装软件；免安装绿色软件删后即移除。";
                d.steps = new string[]
                {
                    "确认软件已安装完成（且它不是直接运行的免安装绿色软件）。",
                    "无需留作重装备份时，可在下方点「移入回收站」。"
                };
                d.evidence.Clear();
                d.evidence.Add(new Evidence("y", "符合软件安装包或下载程序位置/命名特征", "中证据"));
                d.evidence.Add(new Evidence("y", "扩展名为可执行或安装包格式（" + ext + "）", "中证据"));
                return;
            }

            d.type = "可执行程序文件 (" + ext + ")";
            d.purpose = "可直接运行的软件程序，或独立安装包。";
            d.basis = "可执行文件扩展名（" + ext + "）";
            d.summary = "可执行程序 · 确认用途后再处理";
            d.risk = "可能影响软件运行";
            d.riskText = "若是软件主程序删后将无法启动；若是旧安装包则影响很小。";
            d.steps = new string[]
            {
                "先点「在资源管理器中显示」查看它属于哪个软件文件夹。",
                "仅在确认它是已装完的无用安装包时再移入回收站。"
            };
            return;
        }

        if (ext == ".dll")
        {
            d.type = "程序动态链接库 (.dll)";
            d.purpose = "软件或插件运行时调用的功能模块文件。";
            d.basis = "动态链接库扩展名 (.dll)";
            d.summary = "软件运行模块 · 不建议单独删除";
            d.risk = "可能影响软件运行";
            d.riskText = "单独删除后，所属软件或插件可能报错无法启动。";
            d.steps = new string[]
            {
                "保留它；不要单独删除软件目录里的 .dll 文件。",
                "如不再使用对应软件，请通过系统卸载入口完整移除。"
            };
            return;
        }

        // E. 压缩包归档（.zip / .rar / .7z / .tar / .gz / .tgz / .bz2 / .xz）
        if (SafeIsMatch(RxArchiveExt, ext))
        {
            d.type = "压缩归档包 (" + ext + ")";
            d.purpose = "打包压缩的文件夹、资料备份或软件分发包。";
            d.basis = "常见压缩归档扩展名";
            d.summary = "确认已解压保存后可移入回收站";
            d.risk = "可能丢失你的内容";
            d.riskText = "若里面是唯一原件且尚未解压保存，删除会丢失内容。";
            d.steps = new string[]
            {
                "先确认压缩包里的文件是否已解压并妥善保存在别处。",
                "若已解压且不再需要原压缩包，可点「移入回收站」。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为常见压缩归档格式（" + ext + "）", "中证据"));
            if (IsUserDownloadOrDesktop(full))
                d.evidence.Add(new Evidence("y", "位于下载或桌面个人目录", "中证据"));
            return;
        }

        // F. 视频 / 音频媒体与设计创作工程文件
        if (SafeIsMatch(RxMediaExt, ext))
        {
            bool isAudio = SafeIsMatch(RxAudioExt, ext);
            d.type = isAudio ? ("个人音频媒体 (" + ext + ")") : ("个人视频或录屏媒体 (" + ext + ")");
            d.purpose = isAudio ? "音乐、录音或音频素材文件。" : "录屏、视频电影或拍摄素材文件。";
            d.basis = "常见音视频媒体扩展名";
            d.summary = "个人音视频素材 · 确认无需保留可移入回收站";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后会失去这段音视频内容（移入回收站后仍可还原）。";
            d.steps = new string[]
            {
                "可在资源管理器中打开确认是否还需要保留。",
                "确认已备份或不再需要后，可点「移入回收站」。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为标准音视频媒体格式（" + ext + "）", "中证据"));
            d.evidence.Add(new Evidence("y", "属于非系统缓存的独立媒体文件", "中证据"));
            return;
        }

        if (SafeIsMatch(RxDesignExt, ext))
        {
            d.type = "设计或剪辑工程源文件 (" + ext + ")";
            d.purpose = "图像设计、视频剪辑或制图软件的可编辑工程原件。";
            d.basis = "专业创作工程扩展名";
            d.summary = "创作工程原件 · 确认有备份前请保留";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后将丢失图层与工程进度，无法从导出成品还原。";
            d.steps = new string[]
            {
                "创作工程源文件通常很重要，建议优先保留或备份。",
                "仅在确认项目彻底完结且已有备份时再移入回收站。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为专业设计或剪辑工程源文件（" + ext + "）", "中证据"));
            d.evidence.Add(new Evidence("y", "属于个人创作工程类文件", "中证据"));
            return;
        }

        // G. Office 临时草稿锁文件与办公文档 / PDF / 个人图片
        if (fileName.StartsWith("~$", StringComparison.Ordinal) || r.RuleId == "REVIEW-OFFICEDRAFT")
        {
            d.type = "Office 临时锁或草稿文件";
            d.purpose = "Word、Excel 或 PPT 打开文档时生成的临时状态文件。";
            d.basis = "Office 临时文件名前缀";
            d.summary = "Office 编辑锁文件 · 先保存关闭文档";
            d.risk = "可能丢失你的内容";
            d.riskText = "若对应文档尚未保存关闭，删除可能导致未存修改丢失。";
            d.steps = new string[]
            {
                "先保存并关闭正在编辑的 Office 文档。",
                "关闭软件后若仍残留旧锁文件，再单独移入回收站。"
            };
            return;
        }

        if (SafeIsMatch(RxDocExt, ext))
        {
            d.type = ext == ".pdf" ? "PDF 文档 (.pdf)" : ("个人办公文档 (" + ext + ")");
            d.purpose = "文档、电子表格、演示文稿或文本阅读资料。";
            d.basis = "常见办公文档扩展名";
            d.summary = "个人文档资料 · 建议保留核实";
            d.risk = "可能丢失你的内容";
            d.riskText = "可能是你的工作或学习资料原件，删除会丢失文档内容。";
            d.steps = new string[]
            {
                "建议保留；常规清理空间无需删除个人文档。",
                "如确认是无用的重复下载件，可在详情页移入回收站。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为常见办公或文本格式（" + ext + "）", "中证据"));
            return;
        }

        if (SafeIsMatch(RxPhotoExt, ext))
        {
            d.type = "个人图片或照片 (" + ext + ")";
            d.purpose = "照片、截图或保存的图像文件。";
            d.basis = "图片文件扩展名";
            d.summary = "个人图片文件 · 确认无需保留可移入回收站";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后会失去这张图片（移入回收站后仍可还原）。";
            d.steps = new string[]
            {
                "先确认不是重要的照片或截图原件。",
                "确认不再需要后可在详情页点「移入回收站」。"
            };
            // 单条中证据保持泛化路径下 confidence 为「无法确定」（不冒充已核实归属）
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为常见图片格式（" + ext + "）", "中证据"));
            return;
        }

        // H. 未完成的下载残留
        if (SafeIsMatch(RxPartialDlExt, ext) || r.RuleId == "REVIEW-PARTIALDL")
        {
            d.type = "未完成的下载残留 (" + (ext.Length > 0 ? ext : "分片") + ")";
            d.purpose = "浏览器或下载工具尚未下载完成的分片文件。";
            d.basis = "下载中断临时文件扩展名";
            d.summary = "未完成下载分片 · 确认已废弃可移入回收站";
            d.risk = "可能丢失你的内容";
            d.riskText = "若下载仍在进行，删除会中断任务；旧中断残留删后无碍。";
            d.steps = new string[]
            {
                "先检查浏览器下载列表是否还有正在进行的下载任务。",
                "确认是早已中断废弃的残留后，可点「移入回收站」。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "命中浏览器或下载器未完成分片后缀", "中证据"));
            return;
        }

        // I. 日志、备份、数据库与非标准目录转储
        if (SafeIsMatch(RxLogExt, ext))
        {
            if (ext == ".evtx")
            {
                d.type = "Windows 事件日志 (.evtx)";
                d.purpose = "Windows 记录系统运行与故障事件的日志文件。";
                d.basis = "事件日志扩展名 (.evtx)";
                d.summary = "Windows 事件日志 · 建议保留";
                d.risk = "可能影响软件运行";
                d.riskText = "系统事件查看器可能正在使用或依赖此记录。";
                d.steps = new string[]
                {
                    "系统目录内的事件日志请保留。",
                    "若是自己导出的旧备份副本，确认无用后可移入回收站。"
                };
            }
            else
            {
                d.type = "运行或诊断日志文件 (" + ext + ")";
                d.purpose = "软件或系统记录运行过程与排查故障的日志。";
                d.basis = "日志文件扩展名（" + ext + "）";
                d.summary = "运行诊断日志 · 无需排障时可移入回收站";
                d.risk = "影响很小";
                d.riskText = "一般只影响历史排障记录；正在运行的软件日志请勿强删。";
                d.steps = new string[]
                {
                    "若近期无需排查对应软件故障，过大的旧日志可移入回收站。",
                    "正在运行软件刚写入的当前日志建议保留。"
                };
            }
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为标准诊断日志格式（" + ext + "）", "中证据"));
            return;
        }

        if (SafeIsMatch(RxBackupExt, ext))
        {
            d.type = "备份副本文件 (" + ext + ")";
            d.purpose = "软件升级或修改数据前自动留存的旧版本备份。";
            d.basis = "备份文件扩展名（" + ext + "）";
            d.summary = "旧版备份副本 · 确认无需回退可移入回收站";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后将无法用这份备份回退到修改前的旧版本。";
            d.steps = new string[]
            {
                "先确认对应的正式文件或软件当前运行完全正常。",
                "确认不再需要回退旧版本后，可单独移入回收站。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为常见备份副本标记（" + ext + "）", "中证据"));
            return;
        }

        if (SafeIsMatch(RxDbExt, ext))
        {
            d.type = "本地软件数据库 (" + ext + ")";
            d.purpose = "软件保存本地记录、索引、历史或配置的数据文件。";
            d.basis = "数据库文件扩展名（" + ext + "）";
            d.summary = "软件本地数据库 · 建议保留勿删";
            d.risk = "可能丢失你的内容";
            d.riskText = "删除后所属软件可能丢失本地记录、历史数据或设置。";
            d.steps = new string[]
            {
                "保留它；大多数软件依赖数据库文件存放核心本地数据。",
                "除非明确确认属于早已卸载的无用软件，否则请勿删除。"
            };
            d.evidence.Clear();
            d.evidence.Add(new Evidence("y", "扩展名为结构化数据库文件（" + ext + "）", "中证据"));
            return;
        }

        if (ext == ".dmp")
        {
            d.type = "内存转储或数据文件 (.dmp)";
            d.purpose = "扩展名为 .dmp，但不在系统标准崩溃转储目录内。";
            d.basis = "扩展名 .dmp（非标准转储目录）";
            d.summary = "非标准目录转储 · 确认非备份再处理";
            d.risk = "可能丢失你的内容";
            d.riskText = "部分数据库导出文件也使用 .dmp 后缀，勿盲目当垃圾删除。";
            d.steps = new string[]
            {
                "先点「在资源管理器中显示」核实它属于哪个项目或程序。",
                "确认只是无用的旧调试转储后，再单独移入回收站。"
            };
            return;
        }
    }

    private static bool IsUserDownloadOrDesktop(string full)
    {
        return SafeIsMatch(RxUserDlDesktop, full);
    }

    private static bool ContainsText(string haystack, string needle)
    {
        return !string.IsNullOrEmpty(haystack)
            && !string.IsNullOrEmpty(needle)
            && haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static string TryGetFileName(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        try { return Path.GetFileName(path) ?? ""; }
        catch { return ""; }
    }

    private static string TryGetDirName(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        try { return Path.GetDirectoryName(path) ?? ""; }
        catch { return ""; }
    }
}
