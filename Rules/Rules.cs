using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

/// <summary>
/// 一条文件的风险判定结论。
///
/// 三个概念必须分开（P0 第三部分要求）：
///   Risk           —— 归类：这个文件「像什么」。工具判断，仅供展示与排序。
///   PolicyEligible —— 删除授权：代码判定的「能不能删」。**只有它决定可删除性**。
///   Checked        —— 用户选择：用户勾没勾。只能在 PolicyEligible 的范围内选择。
///
/// 不变量（由 SafetyPolicy 保证，测试断言）：
///   Risk == "安全"  ⟺  PolicyEligible == true
/// 也就是说「安全」这个标签本身就代表已获授权，不存在「标着安全但不能删」的灰色状态。
/// </summary>
public class Evidence
{
    public string Risk = "需复核";          // 安全 / 需复核 / 保留
    public string App = "未知软件或系统服务"; // 归属软件（推测）
    public string Reason = "";               // 判断依据
    public string Consequence = "";          // 删除后果
    public bool Locked = false;              // 是否正被进程占用
    /// <summary>是否为已识别的受控缓存项，但因当前正被运行中的软件占用而暂不可删。</summary>
    public bool LockedCleanableCache = false;

    /// <summary>删除授权。规则层永远置 false，只有 SafetyPolicy 能置 true。</summary>
    public bool PolicyEligible = false;
    /// <summary>不可删除时的原因（面向用户）。</summary>
    public string DenyReason = "规则层不授予删除授权";
    /// <summary>命中的可追溯规则编号（便于审计与回归）。降级后仍保留。</summary>
    public string RuleId = "";

    /// <summary>该规则在什么范围内成立。</summary>
    public string Scope = "";
    /// <summary>该规则的排除条件（即使命中也不授权的情况）。</summary>
    public string Excludes = "";
    /// <summary>该规则是否必须位于其声明的已知缓存根之内（true = Temp 本身不构成证据）。</summary>
    public bool RootBound = false;
    /// <summary>命中的子模式最小修改冷却小时数（0 表示无冷却期）。</summary>
    public int MinAgeHours = 0;

    /// <summary>内容级证据的种类与结论。</summary>
    public EvidenceKind EvidenceKind = EvidenceKind.None;
    public string EvidenceDetail = "";
    /// <summary>内容级正向证据是否已通过。</summary>
    public bool ContentVerified = false;
}

/// <summary>
/// 证据规则库：由系统禁区/用户数据/复核规则 + CacheRuleRegistry 单一受控缓存规则源组合而成。
/// </summary>
public static class EvidenceRules
{
    public const string RiskSafe = "安全";
    public const string RiskReview = "需复核";
    public const string RiskKeep = "保留";

    private sealed class Rule
    {
        public string Id;
        public string Pattern;
        public Regex Compiled;
        public bool NameOnly;
        public string Risk;
        public string App;
        public string Reason;
        public string Consequence;
        public EvidenceKind Evidence = EvidenceKind.None;
        public bool RootBound;
        public int MinAgeHours;
        public string Scope = "";
        public string Excludes = "";
    }

    private static readonly Regex FlatUserDataRegex =
        new Regex(@"[\\/]user data[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex BrowserSubdirRegex =
        new Regex(@"[\\/](cache[\\/]cache_data|code cache|gpucache|dawncache)[\\/]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FlatBrowserFileNameRegex =
        new Regex(@"^([0-9a-f]{16}_([0-9a-f]+|s)|data_[0-9]+|f_[0-9a-f]{6,8}|index|the-real-index)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FlatFirefoxFileNameRegex =
        new Regex(@"^([0-9a-f]{40}|.+\.(little|bin))$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FlatThumbFileNameRegex =
        new Regex(@"^(thumbcache|iconcache)_[^\\/]*\.db$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FlatShaderFileNameRegex =
        new Regex(@"^(?!.*\.lock$).+\.(val|idx|bin|toc|parc|dxbc|nvph)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FlatWerFileNameRegex =
        new Regex(@"\.(wer|cab|dmp|mdmp|hdmp)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FlatAppVsixFileNameRegex =
        new Regex(@"\.vsix$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FlatChatCacheFileNameRegex =
        new Regex(@"^(?!.*\.(lock|db|sqlite|exe|dll|sys|ini|cfg|config|pdf|docx|doc|xlsx|xls|pptx|ppt|zip|rar|7z|psd|rtf)$)([0-9a-f]{16}_([0-9a-f]+|s)|data_[0-9]+|f_[0-9a-f]{6,8}|index|the-real-index|.+\.(wxapkg|jpg|jpeg|png|gif|webp|mp4|tmp|bin|pak|cache)|[0-9a-fA-F_-]{6,64})$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex FlatWinUpdateFileNameRegex =
        new Regex(@"^(?!.*\.(lock|pdf|docx|doc|xlsx|xls|pptx|ppt|psd|rtf|sqlite|db|edb)$).+\.(cab|esd|wim|psf|msu|cbs|exe|dll|xml|json|bin|dat)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex WinUpdateDataStoreRegex =
        new Regex(@"[\\/]datastore([\\/]|$)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Rule[] All = BuildRules();

    private static Rule[] BuildRules()
    {
        List<Rule> list = new List<Rule>();

        // ---------- 1. 绝对禁区，永远排最前 ----------
        list.Add(new Rule
        {
            Id = "KEEP-SYSTEM",
            Pattern = @"system32|syswow64|winsxs|(^|[\\/])windows[\\/]system",
            NameOnly = false,
            Risk = RiskKeep,
            App = "Windows 操作系统",
            Reason = "系统核心组件目录",
            Consequence = "严禁删除。删除可能导致系统服务损坏、无法开机。",
            Scope = "完整路径命中系统目录",
            Excludes = "无（无条件保留）"
        });

        // 微软 KB2667628：Installer 缓存用于修复/更新/卸载，不应手动删除。只匹配目录直接子文件。
        list.Add(new Rule
        {
            Id = "KEEP-MSICACHE",
            Pattern = @"^[a-z]:[\\/]windows[\\/]installer[\\/][^\\/]+\.(msi|msp)$",
            NameOnly = false,
            Risk = RiskKeep,
            App = "Windows Installer",
            Reason = "Windows Installer 维护缓存（微软 KB2667628）",
            Consequence = "不建议手动删除。缺失后对应软件可能无法修复、更新或卸载。",
            Scope = "%WINDIR%\\Installer 直接子文件，扩展名 .msi / .msp",
            Excludes = "无（无条件保留）"
        });

        list.Add(new Rule
        {
            Id = "KEEP-LOCK",
            Pattern = @"\.(lock)$",
            NameOnly = true,
            Risk = RiskKeep,
            App = "系统或软件互斥锁",
            Reason = "进程运行锁文件",
            Consequence = "严禁删除。它代表某个程序正在运行，删除会引发冲突。",
            Scope = "文件名为 *.lock",
            Excludes = "无（无条件保留）"
        });

        list.Add(new Rule
        {
            Id = "KEEP-CHATDB",
            Pattern = @"(wechat files|xwechat_files|wxwork|tencent files)[\\/].*[\\/](msg|nt_msg|nt_db)[\\/].+\.(db|db-wal|db-shm|idx)$",
            NameOnly = false,
            Risk = RiskKeep,
            App = "微信 / QQ 聊天数据库",
            Reason = "聊天记录核心数据库",
            Consequence = "严禁删除。删除会导致本地聊天记录永久丢失。",
            Scope = "微信、企业微信或 QQ 账号 Msg / nt_msg 目录下的聊天记录核心数据库",
            Excludes = "无（无条件保留）"
        });

        // ---------- 2. 限定专用缓存目录路径的前置缓存规则（如 Explorer 缩略图） ----------
        AppendRegistryStage(list, RuleMatchStage.BeforeUserDoc);

        // ---------- 3. 用户文档与压缩包 ----------
        list.Add(new Rule
        {
            Id = "USER-DOC",
            Pattern = @"\.(docx|doc|xlsx|xls|pptx|ppt|pdf|zip|rar|7z|psd|ai|txt|md|csv|rtf|odt|ods|odp|vsdx|vsd|dwg|sketch|fig|key|numbers|pages)$",
            NameOnly = true,
            Risk = RiskReview,
            App = "用户个人文档或压缩包",
            Reason = "文档或压缩包类型，可能是尚未归档的原件",
            Consequence = "请先确认。它可能是你从聊天或邮件里直接打开、尚未另存的原件。",
            Scope = "扩展名命中文档类",
            Excludes = "任何位置都不授权自动清理"
        });

        // ---------- 4. 限定包缓存路径的 .dat / .json / .tgz（在 USER-CONFIG 之前，非缓存目录仍归 USER-CONFIG） ----------
        AppendRegistryStage(list, RuleMatchStage.BeforeUserConfig);

        // ---------- 5. 用户配置、凭据与可执行脚本 ----------
        list.Add(new Rule
        {
            Id = "USER-CONFIG",
            Pattern = @"\.(xml|json|ini|cfg|config|db|sqlite|dat|key|pem|pfx|crt|cer|p12|env|toml|yaml|yml)$",
            NameOnly = true,
            Risk = RiskReview,
            App = "软件配置或数据文件",
            Reason = "配置或凭据类文件，无法确认是否仍在使用",
            Consequence = "请先确认。删除可能导致某个软件丢失设置或凭据。",
            Scope = "扩展名命中配置/凭据类",
            Excludes = "任何位置都不授权自动清理"
        });

        list.Add(new Rule
        {
            Id = "USER-SCRIPT",
            Pattern = @"\.(ps1|bat|cmd|sh|py|js|rb|pl|vbs|reg|lnk|url|exe|msi|dll)$",
            NameOnly = true,
            Risk = RiskReview,
            App = "可执行文件或脚本",
            Reason = "可执行内容，来源与用途无法从名字确定",
            Consequence = "请先确认。随意运行过的脚本/程序删前需确认其来源。",
            Scope = "扩展名命中可执行/脚本",
            Excludes = "任何位置都不授权自动清理"
        });

        // ---------- 6. 标准受控缓存规则（来自 CacheRuleRegistry） ----------
        AppendRegistryStage(list, RuleMatchStage.StandardCache);

        // ---------- 7. 命名像缓存但无内容证据：降级为需复核，永不授权 ----------
        list.Add(new Rule
        {
            Id = "REVIEW-INSTALLERLOG",
            Pattern = @"installer.*\.log$|^setup.*\.log$",
            NameOnly = true,
            Risk = RiskReview,
            App = "可能有（基于文件名推测）",
            Reason = "名字像安装日志，但日志内容无法证明它由安装程序生成",
            Consequence = "无法证明可删。仅凭名字不足以授权自动清理。",
            Scope = "无（仅命名）",
            Excludes = "命名类规则不参与授权"
        });

        list.Add(new Rule
        {
            Id = "REVIEW-OFFICEDRAFT",
            Pattern = @"^~\$|^~df|^~wr",
            NameOnly = true,
            Risk = RiskReview,
            App = "可能有（基于文件名推测）",
            Reason = "名字像 Office 临时副本，但这类文件内容是程序私有的，无法校验",
            Consequence = "无法证明可删。请先确认对应文档已保存。",
            Scope = "无（仅命名）",
            Excludes = "命名类规则不参与授权"
        });

        list.Add(new Rule
        {
            Id = "REVIEW-CHATTEMP",
            Pattern = @"wechat.*temp|wxwork.*temp|filestorage.*temp|dingtalk",
            NameOnly = true,
            Risk = RiskReview,
            App = "可能有（基于文件名推测）",
            Reason = "名字像聊天软件临时文件，但内容无固定格式可核对",
            Consequence = "无法证明可删。仅凭名字不足以授权自动清理。",
            Scope = "无（仅命名）",
            Excludes = "命名类规则不参与授权"
        });

        list.Add(new Rule
        {
            Id = "REVIEW-PARTIALDL",
            Pattern = @"\.crdownload$|\.part$|\.download$",
            NameOnly = true,
            Risk = RiskReview,
            App = "可能有（基于文件名推测）",
            Reason = "名字像未完成的下载，但残片内容无固定格式可核对",
            Consequence = "无法证明可删。请先确认下载确实已中断。",
            Scope = "无（仅命名）",
            Excludes = "命名类规则不参与授权"
        });

        list.Add(new Rule
        {
            Id = "REVIEW-VSCODEUPD",
            Pattern = @"vscode-update|code.*update",
            NameOnly = true,
            Risk = RiskReview,
            App = "可能是 Visual Studio Code（基于文件名推测）",
            Reason = "名字像编辑器更新包，但无法确认更新是否已完成",
            Consequence = "若已完成更新可手工清理；自动清理不处理它。",
            Scope = "无（仅命名）",
            Excludes = "命名类规则不参与授权"
        });

        // ---------- 8. 后置受控缓存规则（排在全部 USER-* / REVIEW-* 之后，如 TMP-SYSTEMP） ----------
        AppendRegistryStage(list, RuleMatchStage.AfterNamedReviews);

        for (int i = 0; i < list.Count; i++)
        {
            Rule item = list[i];
            if (!string.IsNullOrEmpty(item.Pattern))
            {
                try { item.Compiled = new Regex(item.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant); }
                catch { item.Compiled = null; }
            }
        }

        return list.ToArray();
    }

    private static void AppendRegistryStage(List<Rule> list, RuleMatchStage stage)
    {
        CacheRuleSpec[] specs = CacheRuleRegistry.All;
        for (int i = 0; i < specs.Length; i++)
        {
            CacheRuleSpec s = specs[i];
            if (s.MatchPatterns == null) continue;
            for (int k = 0; k < s.MatchPatterns.Length; k++)
            {
                RuleMatchPattern mp = s.MatchPatterns[k];
                if (mp.Stage != stage) continue;
                list.Add(new Rule
                {
                    Id = s.Id,
                    Pattern = mp.Pattern,
                    NameOnly = mp.NameOnly,
                    Risk = RiskSafe,
                    App = mp.App,
                    Reason = mp.Reason,
                    Consequence = mp.Consequence,
                    Evidence = mp.Evidence,
                    RootBound = s.RootBound,
                    MinAgeHours = mp.MinAgeHours >= 0 ? mp.MinAgeHours : s.MinAgeHours,
                    Scope = mp.Scope,
                    Excludes = mp.Excludes
                });
            }
        }
    }

    /// <summary>
    /// 规则层结论（不含实时状态与授权）。daysUnused = 距最后修改的天数。
    /// 返回对象的 PolicyEligible 恒为 false —— 授权由 SafetyPolicy 决定。
    /// </summary>
    public static Evidence Evaluate(string name, string fullPath, int daysUnused)
    {
        Evidence ev = new Evidence();
        if (name == null) name = "";
        if (fullPath == null) fullPath = "";

        foreach (Rule r in All)
        {
            if (r.Id == "TMP-BROWSERCACHE" && CacheRoots.IsBrowserProtectedPath(name, fullPath))
                continue;
            if (r.Id == "TMP-CHATCACHE" && (ChatStorageLocator.IsChatProtectedUserContent(fullPath) || CacheRoots.IsBrowserProtectedPath(name, fullPath)))
                continue;
            if (r.Id == "TMP-APPCACHE" && CacheRoots.IsAppProtectedPath(name, fullPath))
                continue;
            if (r.Id == "TMP-WINUPDATE" && WinUpdateDataStoreRegex.IsMatch(fullPath))
                continue;

            string target = r.NameOnly ? name : fullPath;
            bool hit;
            try
            {
                hit = r.Compiled != null
                    ? r.Compiled.IsMatch(target)
                    : Regex.IsMatch(target, r.Pattern, RegexOptions.IgnoreCase);
            }
            catch { hit = false; }

            if (!hit && r.Id == "KEEP-CHATDB")
            {
                hit = ChatStorageLocator.IsChatDatabasePath(fullPath);
            }

            // 支持沙盒测试对扁平目录调用 InjectForTest 放入标准缓存文件名（不影响任何缓存根外的同名文件归类）
            if (!hit)
            {
                hit = MatchesFlatInjectedRoot(r, name, fullPath);
            }

            if (!hit) continue;

            // 浏览器、聊天软件与桌面软件共享 Chromium 子目录结构时，若文件明确落在另一条规则的注册根内，交由对应规则处理
            if (r.Id == "TMP-BROWSERCACHE" || r.Id == "TMP-CHATCACHE" || r.Id == "TMP-APPCACHE")
            {
                string ownerRule, ownerWhy;
                if (CacheRoots.Match(fullPath, out ownerRule, out ownerWhy)
                    && (ownerRule == "TMP-BROWSERCACHE" || ownerRule == "TMP-CHATCACHE" || ownerRule == "TMP-APPCACHE")
                    && ownerRule != r.Id)
                {
                    continue;
                }
            }

            ev.RuleId = r.Id;
            ev.Risk = r.Risk;
            ev.App = r.App;
            ev.Reason = r.Reason;
            ev.Consequence = r.Consequence;
            ev.Scope = r.Scope;
            ev.Excludes = r.Excludes;
            ev.EvidenceKind = r.Evidence;
            ev.RootBound = r.RootBound;
            ev.MinAgeHours = r.MinAgeHours;

            // 明确的系统禁区直接返回，不再降级
            if (r.Risk == RiskKeep) return ev;

            // 「安全」不得仅凭名字得出：声明了根绑定的规则，必须真的落在其缓存根内。
            if (r.Risk == RiskSafe)
            {
                string hitRule, hitWhy;
                bool inRoot = CacheRoots.Match(fullPath, out hitRule, out hitWhy);
                int minDays = r.MinAgeHours > 0 ? Math.Max(1, r.MinAgeHours / 24) : 0;

                if (!inRoot)
                    Downgrade(ev, r.RootBound
                        ? "该规则要求位于指定的已知缓存根内，本文件不在其中（临时目录位置不算证据）"
                        : "位置不在受控临时目录，也不在任何已知缓存根内");
                else if (r.RootBound && hitRule != r.Id)
                    Downgrade(ev, "所在缓存根只对规则 " + hitRule + " 生效，本文件命中 " + r.Id);
                else if (minDays > 0 && daysUnused < minDays)
                    Downgrade(ev, "临时文件修改时间未满 " + r.MinAgeHours + " 小时，可能仍在使用中");
            }
            break;
        }

        // 兜底：未能识别归属的文件
        if (ev.Reason.Length == 0)
        {
            ev.Risk = RiskReview;
            ev.RuleId = "FALLBACK-UNKNOWN";
            ev.App = "未能识别的软件";
            ev.Scope = "无（未命中任何规则）";
            ev.Excludes = "未识别文件永不授权自动清理";
            if (daysUnused >= 3)
            {
                ev.Reason = "已 " + daysUnused + " 天无人写入，但无法识别其归属";
                ev.Consequence = "无法确认用途。仅凭「长期未修改」不能证明可删；" +
                                 "请先确认它属于哪个软件、删后能否重建，再决定。";
            }
            else
            {
                ev.Reason = WhenText(daysUnused) + "，可能正被某个程序使用";
                ev.Consequence = "建议先关闭相关软件，或保留观察几天再处理。";
            }
        }

        ev.PolicyEligible = false;
        ev.DenyReason = "规则层不授予删除授权";
        return ev;
    }

    private static bool MatchesFlatInjectedRoot(Rule r, string name, string fullPath)
    {
        if (!CacheRoots.HasInjectedForTest) return false;

        if (r.Id == "TMP-BROWSERCACHE"
            && ((!FlatUserDataRegex.IsMatch(fullPath)
                 && (FlatBrowserFileNameRegex.IsMatch(name) || FlatFirefoxFileNameRegex.IsMatch(name)))
                || BrowserSubdirRegex.IsMatch(fullPath)))
        {
            string mappedRule, mappedWhy;
            return CacheRoots.Match(fullPath, out mappedRule, out mappedWhy) && mappedRule == "TMP-BROWSERCACHE";
        }

        if (r.Id == "TMP-APPCACHE"
            && (FlatBrowserFileNameRegex.IsMatch(name)
                || FlatAppVsixFileNameRegex.IsMatch(name)
                || BrowserSubdirRegex.IsMatch(fullPath)))
        {
            string mappedRule, mappedWhy;
            return CacheRoots.Match(fullPath, out mappedRule, out mappedWhy) && mappedRule == "TMP-APPCACHE";
        }

        if (r.Id == "TMP-THUMBCACHE"
            && FlatThumbFileNameRegex.IsMatch(name))
        {
            string mappedRule, mappedWhy;
            return CacheRoots.Match(fullPath, out mappedRule, out mappedWhy) && mappedRule == "TMP-THUMBCACHE";
        }

        if (r.Id == "TMP-SHADERCACHE"
            && FlatShaderFileNameRegex.IsMatch(name))
        {
            string mappedRule, mappedWhy;
            return CacheRoots.Match(fullPath, out mappedRule, out mappedWhy) && mappedRule == "TMP-SHADERCACHE";
        }

        if (r.Id == "TMP-WER"
            && FlatWerFileNameRegex.IsMatch(name))
        {
            string mappedRule, mappedWhy;
            return CacheRoots.Match(fullPath, out mappedRule, out mappedWhy) && mappedRule == "TMP-WER";
        }

        if (r.Id == "TMP-CHATCACHE"
            && !ChatStorageLocator.IsChatProtectedUserContent(fullPath)
            && !CacheRoots.IsBrowserProtectedPath(name, fullPath)
            && (FlatChatCacheFileNameRegex.IsMatch(name) || BrowserSubdirRegex.IsMatch(fullPath)))
        {
            string mappedRule, mappedWhy;
            return CacheRoots.Match(fullPath, out mappedRule, out mappedWhy) && mappedRule == "TMP-CHATCACHE";
        }

        if (r.Id == "TMP-WINUPDATE"
            && !WinUpdateDataStoreRegex.IsMatch(fullPath)
            && FlatWinUpdateFileNameRegex.IsMatch(name))
        {
            string mappedRule, mappedWhy;
            return CacheRoots.Match(fullPath, out mappedRule, out mappedWhy) && mappedRule == "TMP-WINUPDATE";
        }

        return false;
    }

    /// <summary>把结论降级为「需复核」，并保留原来的规则编号与理由。</summary>
    public static void Downgrade(Evidence ev, string why)
    {
        ev.Risk = RiskReview;
        ev.Reason = why + "（原始判断：" + ev.Reason + "）";
        ev.Consequence = "证据不足，不作为自动清理建议。仅凭位置、名称、扩展名或时间不足以授权删除。";
    }

    private static string WhenText(int days)
    {
        if (days <= 0) return "今天刚被写入";
        if (days == 1) return "昨天被写入";
        return "最近 " + days + " 天内有写入";
    }
}
