using System;

// =====================================================================
// 扫描相关文案（第二批）。纯函数、无 WinForms 依赖，可被测试直接断言。
//
// 铁律（对应验收要求）：
//   1. 未确认枚举完成时，**不得**出现「共 N 项」或任何精确总数；一律用「≥」。
//   2. Remainder=Unknown 与 Remainder=Exists 的措辞必须不同：
//        Unknown = 剩余情况未知（取消 / 超时 / 枚举异常时不去探测）
//        Exists  = 仍有未枚举项（已探测确认，但数量仍未知）
//      v0.5.0 第四批：两个措辞都收紧了长度 —— 底栏只有一行，
//      必须给“删除已禁用”这类安全提示留下可显位置。
//   3. 「显示已就绪的更多结果」不得描述成「继续扫描剩余文件」。
//   4. 不得出现「已验证…」这类确定性承诺 —— 候选 ≠ 授权。
// =====================================================================
public static class ScanText
{
    public const string DeletionDisabled = "真实删除已禁用";
    public const string CandidateOnly = "候选 ≠ 已授权删除";

    /// <summary>是否允许显示精确总数。只有枚举真正结束、且已发现项都已处理才允许。</summary>
    public static bool CanShowExactTotal(ScanProgress p)
    {
        return p != null && p.HasKnownTotal;
    }

    /// <summary>计数：未确认完成时一律加「≥」，表示“至少这么多”。</summary>
    public static string Count(int n, bool exact)
    {
        return exact ? n.ToString("N0") : "≥ " + n.ToString("N0");
    }

    /// <summary>停止原因（短）。</summary>
    public static string StopReason(ScanProgress p)
    {
        if (p == null) return "";
        switch (p.Stop)
        {
            case ScanStopReason.Completed: return "本次枚举结束";
            case ScanStopReason.TopLevelBudget: return "已达条目预算（已发现 " + p.Discovered.ToString("N0") + " 项）";
            case ScanStopReason.AnalysisBudget: return "已达条目预算（已分析 " + p.Analyzed.ToString("N0") + " 项）";
            case ScanStopReason.TimeBudget: return "已达时间预算，已停止";
            case ScanStopReason.Cancelled: return "已被用户取消";
            case ScanStopReason.EnumerationFailed: return "目录枚举中断";
            case ScanStopReason.ParkTimeout: return "暂停已超时，枚举资源已释放；只能重新开始分析";
            case ScanStopReason.FatalError: return "内部错误，扫描中止";
            default: return "分析中";
        }
    }

    /// <summary>剩余部分：三种状态必须用三句话，不得混用。</summary>
    public static string Remainder(ScanProgress p)
    {
        if (p == null) return "";
        switch (p.Remainder)
        {
            case RemainderState.Exists: return "仍有未枚举项（数量未知）";
            case RemainderState.Unknown: return "剩余部分未知";
            default: return "没有剩余项目";
        }
    }

    /// <summary>
    /// 底栏左侧（选择栏）——保持 v0.3.2 的两段式，不改版式。
    /// 只读版必须写明勾选“仅统计”：否则用户会以为勾选后就等着删除。
    /// </summary>
    public static string Selection(int checkedCount, long checkedBytes, bool executionAllowed)
    {
        string s = "已选 " + checkedCount.ToString("N0") + " 项 · " + FormatSize(checkedBytes);
        return executionAllowed ? s : s + "（仅统计，不可执行删除）";
    }

    /// <summary>抽屉：结论强度。内容证据缺失/未通过时不得给出确定性安全结论。</summary>
    public static string EvidenceConclusion(bool contentVerified)
    {
        return contentVerified
            ? "结论强度：内容证据已校验通过。"
            : "结论强度：不足以给出“可以安全清理”的结论（证据缺失或未校验）。";
    }

    /// <summary>抽屉：体积完整性说明（预算受限时必须明确）。</summary>
    public static string SizeNote(bool sizeComplete)
    {
        return sizeComplete
            ? ""
            : "（体积为部分统计：含链接点、超出统计上限或预算受限；列表中以 ≥ 显示，未当作精确值）";
    }

    /// <summary>
    /// 底栏灰色提示：扫描状态 / 结果完整性 / 删除禁用。刻意保持短（设计稿里这一行很窄）。
    /// 铁律：后台异常不得把“结果是否完整、剩余多少已知”顶掉 —— 两者必须同时出现。
    /// </summary>
    public static string Hint(ScanSessionState state, ScanProgress p, int displayed, string error)
    {
        if (state == ScanSessionState.Cancelling)
            return "·  正在停止…等待系统调用返回";

        // 暂停 = 达到单轮预算、可继续。**不是**“正在分析”，更不是“分析完成”。
        if (state == ScanSessionState.Paused || (p != null && p.Resumable))
            return PausedHint(p, displayed);

        if (state == ScanSessionState.Scanning)
            return "·  正在分析…已分析 " + (p == null ? "0" : p.Analyzed.ToString("N0"))
                 + " 项 · 已显示 " + displayed.ToString("N0") + " 行 · 点「取消」可停止";

        // Idle：从未扫描过
        if (p == null || (p.Stop == ScanStopReason.None && String.IsNullOrEmpty(error)))
            return "·  " + DeletionDisabled + "（只读分析版）";

        bool hasError = !String.IsNullOrEmpty(error);

        // 真正穷尽且没有任何异常 / 丢弃
        if (p.IsScanExhaustive && !hasError && p.RowsDropped == 0)
        {
            string done = "·  本次枚举结束 · 已分析 " + p.Analyzed.ToString("N0") + " 项";
            if (p.Failed > 0) done += "，其中 " + p.Failed.ToString("N0") + " 项分析失败";
            if (!p.EvidenceComplete) done += "；" + p.ContentUnverified.ToString("N0") + " 项内容证据未校验";
            done += "（扫描当时状态，目录此后可能已变化）";
            return done + " ·  " + DeletionDisabled;
        }

        string text = p.RowsDropped > 0
            ? "·  结果不完整（已交付 " + p.RowsDelivered.ToString("N0") + " 行，丢弃 " + p.RowsDropped.ToString("N0") + " 行）："
            : "·  结果不完整：";
        text += StopReason(p) + "；" + Remainder(p);
        if (p.Failed > 0) text += "；" + p.Failed.ToString("N0") + " 项分析失败";
        if (!String.IsNullOrEmpty(p.ResumeBlocked)) text += "；" + p.ResumeBlocked;
        if (hasError) text += "；后台异常：" + error;
        return text + " ·  " + DeletionDisabled;
    }

    /// <summary>表格顶部细带的辅助信息：**口径与依据**（筛选口径 / 排序依据 / 累计预算用尽）。</summary>
    public static string AuxNote(params string[] parts)
    {
        string t = "";
        foreach (string raw in parts)
        {
            if (String.IsNullOrEmpty(raw)) continue;
            string s = raw.Trim();
            if (s.StartsWith("·", StringComparison.Ordinal)) s = s.Substring(1).Trim();
            if (s.Length == 0) continue;
            if (t.Length > 0) t += "    ·    ";
            t += s;
        }
        return t;
    }

    /// <summary>累计预算用尽提示。</summary>
    public static string BudgetExhaustedNote(ScanProgress p)
    {
        if (p == null) return "";
        string t = "";
        if (p.HashBudgetExhausted)
            t = "内容证据预算已用尽：部分项的内容校验未完成";
        if (p.FileStatsLimit > 0 && p.FileStats >= p.FileStatsLimit)
            t += (t.Length > 0 ? "；" : "") + "文件属性读取预算已用尽：体积只能是已知下界";
        if (p.DirVisitsLimit > 0 && p.DirVisits >= p.DirVisitsLimit)
            t += (t.Length > 0 ? "；" : "") + "目录访问预算已用尽：目录体积只能是已知下界";
        if (p.SessionRowsLimit > 0 && p.Discovered >= p.SessionRowsLimit)
            t += (t.Length > 0 ? "；" : "") + "全会话结果上限已用尽：无法再继续分析";
        return t;
    }

    /// <summary>暂停态文案。</summary>
    public static string PausedHint(ScanProgress p, int displayed)
    {
        string t = "已达单轮预算·第 " + (p == null ? 1 : p.Rounds) + " 轮";
        if (p != null) t += " · 交付/显示 " + p.RowsDelivered + "/" + displayed;
        t += " · " + Remainder(p) + " · 点「继续分析」（" + (p == null ? 60 : p.ParkSeconds) + " 秒内有效）";
        return t + " · " + DeletionDisabled;
    }

    /// <summary>该状态的文案里是否已经含了关键对账数字。</summary>
    public static bool HintCarriesCounts(ScanSessionState state, ScanProgress p)
    {
        return state == ScanSessionState.Paused || (p != null && p.Resumable);
    }

    /// <summary>五项对账：已发现 / 已分析 / 已交付 / 已显示 / 已丢弃。</summary>
    public static string Accounting(ScanProgress p, int displayed)
    {
        if (p == null) return "";
        if (p.RowsDropped == 0 && p.Rounds <= 1) return "";
        return "对账：发现 " + p.Discovered + "/分析 " + p.Analyzed + "/交付 " + p.RowsDelivered
             + "/显示 " + displayed + "/丢弃 " + p.RowsDropped + "（共 " + p.Rounds + " 轮）";
    }

    /// <summary>统计卡片的数字（未完成时带「≥」）。</summary>
    public static string StatCount(int n, bool exact)
    {
        return Count(n, exact);
    }

    /// <summary>统计卡片的副标题（未完成时体积同样带「≥」）。</summary>
    public static string StatSub(long bytes, bool exact)
    {
        return (exact ? "项 · " : "项 · ≥ ") + FormatSize(bytes);
    }

    /// <summary>分批显示说明：措辞必须是「已就绪 / 已显示」，不得写成「继续扫描」。</summary>
    public static string DisplayedNote(int delivered, int displayed)
    {
        if (delivered == displayed)
            return "·  已显示 " + displayed.ToString("N0") + " 行（均为已就绪结果）";
        return "·  已交付 " + delivered.ToString("N0") + " 行，已显示 " + displayed.ToString("N0") + " 行";
    }

    /// <summary>底栏筛选说明。</summary>
    public static string FilterNote(bool filtering, int displayed, int fetched)
    {
        if (!filtering) return "";
        return "·  当前显示 " + displayed.ToString("N0")
             + " / 已获取 " + fetched.ToString("N0") + " 行";
    }

    /// <summary>底栏排序说明。</summary>
    public static string SortNote(bool sizeSorted, bool desc, bool hasIncomplete)
    {
        if (!sizeSorted) return "";
        string dir = desc ? "大→小" : "小→大";
        return hasIncomplete
            ? "·  按已知大小排序（" + dir + "，不完整项为下界）"
            : "·  按大小排序（" + dir + "）";
    }

    /// <summary>统计卡片下方的说明：明确区分「规则命中」与「真正具备候选资格」。</summary>
    public static string CandidateNote(ScanProgress p)
    {
        if (p != null && !p.EvidenceComplete)
            return CandidateOnly + "（部分项目证据未完成，未计入候选）";
        return CandidateOnly;
    }

    /// <summary>把内部规则编号翻成用户看得懂的说法；受控缓存规则直接读取 CacheRuleRegistry。</summary>
    public static string RuleLabel(string id)
    {
        if (string.IsNullOrEmpty(id)) return "";

        CacheRuleSpec spec = CacheRuleRegistry.Find(id);
        if (spec != null && !string.IsNullOrEmpty(spec.RuleLabel))
            return spec.RuleLabel + "（技术标识 " + id + "）";

        string name;
        switch (id)
        {
            case "KEEP-SYSTEM": name = "系统目录"; break;
            case "KEEP-LOCK": name = "锁定文件"; break;
            case "KEEP-MSICACHE": name = "Windows Installer 维护缓存"; break;
            case "KEEP-CHATDB": name = "微信 / QQ 聊天记录数据库"; break;
            case "USER-DOC": name = "用户文档或压缩包"; break;
            case "USER-CONFIG": name = "用户配置或数据文件"; break;
            case "USER-SCRIPT": name = "可执行脚本或程序"; break;
            case "REVIEW-INSTALLERLOG": name = "安装或升级日志"; break;
            case "REVIEW-OFFICEDRAFT": name = "Office 临时草稿"; break;
            case "REVIEW-CHATTEMP": name = "聊天软件临时文件"; break;
            case "REVIEW-PARTIALDL": name = "未完成的下载"; break;
            case "REVIEW-VSCODEUPD": name = "编辑器更新包"; break;
            case "FALLBACK-UNKNOWN": name = "未匹配已知规则"; break;
            default: return id;
        }
        return name + "（技术标识 " + id + "）";
    }

    /// <summary>体积格式化（自包含，不依赖 WinForms 控件）。</summary>
    public static string FormatSize(long bytes)
    {
        if (bytes <= 0) return "0 B";
        if (bytes >= 10737418L) return (bytes / 1073741824.0).ToString("0.00") + " GB";
        if (bytes >= 1048576L) return (bytes / 1048576.0).ToString("0.#") + " MB";
        if (bytes >= 1024L) return (bytes / 1024.0).ToString("0.#") + " KB";
        return bytes + " B";
    }
}
