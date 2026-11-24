using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

// =====================================================================
// 扫描会话宿主（第二批）：把 ScanEngine 的生命周期收成一个可测的状态机。
//
// 界面只跟这个类打交道，硬规则都收在这里：
//   * 同时只允许一个会话。上一轮**尚未排空**前，Start 直接拒绝 —— 不排队、不覆盖。
//     （注意“排空”= 生产者已退出 **且** 待交付批次已取完；只判断线程退出会丢掉尾批。）
//   * 每轮一个 Generation；交付只从本轮 engine 取，旧会话的回调在结构上
//     无法写进新会话的结果。
//   * 界面只通过 Pump 取结果，且每次有量上限 —— 界面永远不会被无界队列压住。
//   * 消费方提前退出（关窗）时，丢掉的行数由引擎如实累计，最终结果标记为不完整。
// =====================================================================

/// <summary>
/// 一次扫描会话的状态。
/// Paused 是 v0.5.0 第三批新增的：“已达单轮预算、已暂停、可继续”——
/// 既不是“正在跑”，也不是“已结束”。
/// </summary>
public enum ScanSessionState { Idle, Scanning, Cancelling, Paused }

public sealed class ScanSessionHost
{
    private readonly IFileEnumerator enumerator;
    private readonly IEntryAnalyzer analyzer;

    private ScanEngine engine;
    private string root = "";
    private readonly List<string> currentRoots = new List<string>();
    private int generation;
    private int delivered;
    private ScanSessionState state = ScanSessionState.Idle;
    private bool finalized;
    private string lastRefusal = "";

    // ---- 构造 ----

    public ScanSessionHost() : this(null, null) { }

    /// <summary>
    /// 测试 / 验收注入点：传 null 表示用真实枚举器与真实分析器。
    /// 有了它，预算触顶、取消、并发拒绝这些场景都能在内存里确定性复现，不必造大目录。
    /// </summary>
    public ScanSessionHost(IFileEnumerator enumerator, IEntryAnalyzer analyzer)
    {
        this.enumerator = enumerator;
        this.analyzer = analyzer;
    }

    // ---- 对外查询 ----

    public ScanSessionState State { get { return state; } }
    public int Generation { get { return generation; } }
    public string Root { get { return root; } }
    public IList<string> Roots { get { return currentRoots.AsReadOnly(); } }
    public string LastRefusal { get { return lastRefusal; } }
    public int Delivered { get { return delivered; } }
    /// <summary>本次会话是否有过“结果不可信”的情形（取消 / 丢弃 / 异常 / 未枚举完）。</summary>
    public bool HadIncomplete { get; private set; }

    public ScanProgress Progress
    {
        get
        {
            ScanEngine e = engine;
            return e == null ? new ScanProgress() : e.Progress;
        }
    }

    public string LastError
    {
        get
        {
            ScanEngine e = engine;
            return e == null ? "" : e.LastError;
        }
    }

    /// <summary>生产者仍在跑。</summary>
    public bool IsRunning
    {
        get
        {
            ScanEngine e = engine;
            return e != null && !e.HasExited;
        }
    }

    /// <summary>生产者已退出且待交付批次已取完 —— 只有到这一步才算真的“排空”。</summary>
    public bool IsDrained
    {
        get
        {
            ScanEngine e = engine;
            return e == null || (e.HasExited && e.PendingBatches == 0);
        }
    }

    public bool IsBusy { get { return !IsDrained; } }

    /// <summary>
    /// 停在「已达单轮预算、可继续」上。不是正在跑，也不是已结束。
    /// </summary>
    public bool IsPaused
    {
        get
        {
            ScanEngine e = engine;
            return e != null && !e.HasExited && e.IsParked;
        }
    }

    /// <summary>
    /// 界面是否可以显示「继续分析」。必须与 <see cref="TryContinue"/> 实际能否成功一致：
    /// 取消、关窗、游标已释放（超时/异常）、累计硬预算耗尽都不允许显示可执行入口。
    /// </summary>
    public bool CanContinue { get { return IsPaused; } }

    /// <summary>不可续的真实原因（空 = 本就不该续，例如枚举已穷尽）。</summary>
    public string ResumeBlocked
    {
        get
        {
            ScanEngine e = engine;
            return e == null ? "" : e.ResumeBlocked;
        }
    }

    /// <summary>
    /// 本轮是否已“落定”：生产者已退出，或已达单轮预算并暂停（且待交付批次已取完）。
    /// 落定之后界面可以做一次收尾（排序 / 统计 / 文案）；
    /// 但**暂停不是结束** —— 继续分析会把会话重新变成未落定。
    /// </summary>
    public bool IsSettled
    {
        get
        {
            ScanEngine e = engine;
            return e == null || ((e.HasExited || e.IsParked) && e.PendingBatches == 0);
        }
    }

    /// <summary>生产者是后台线程（关窗后不会拖住进程退出）。</summary>
    public bool ProducerIsBackground
    {
        get
        {
            ScanEngine e = engine;
            return e == null || e.ProducerIsBackground;
        }
    }

    // ---- 生命周期 ----

    /// <summary>
    /// 启动单目录扫描（直接委托给 StartTargets，保持 100% 向后兼容）。
    /// </summary>
    public bool Start(string scanRoot, ScanBudget budget, out string why)
    {
        return StartTargets(new string[] { scanRoot }, budget, out why);
    }

    /// <summary>
    /// 启动多根目录连续扫描会话。
    /// 逐一校验每个 root 非空、规范化路径真实存在且不是重解析点；
    /// 在同一次扫描会话中顺序遍历并汇总至同一 ScanProgress 与 Coverage。
    /// </summary>
    public bool StartTargets(IList<string> roots, ScanBudget budget, out string why)
    {
        why = "";
        // 暂停态不是“正在跑”，但它的游标仍占着一个 find 句柄 + 一个线程。
        // 启动新扫描前必须先释放，否则会同时存在两个引擎。
        if (IsPaused && !ReleasePausedCursor())
        {
            why = "暂停中的游标未能及时释放，已拒绝启动新扫描";
            lastRefusal = why;
            return false;
        }
        if (IsBusy)
        {
            why = "上一轮扫描尚未结束（" + state + "），已拒绝启动新扫描";
            lastRefusal = why;
            return false;
        }
        if (roots == null || roots.Count == 0)
        {
            why = "扫描路径为空";
            lastRefusal = why;
            return false;
        }

        List<string> normalized = new List<string>();
        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < roots.Count; i++)
        {
            string raw = roots[i];
            if (String.IsNullOrEmpty(raw) || raw.Trim().Length == 0)
            {
                why = "扫描路径为空";
                lastRefusal = why;
                return false;
            }
            string norm = NormalizeScanRoot(raw);
            if (norm.Length == 0 || !PathGuard.IsLocalDrivePath(norm))
            {
                why = "扫描路径无效（仅支持本地磁盘路径）：" + raw;
                lastRefusal = why;
                return false;
            }
            if (PathGuard.HasAnyReparseComponent(norm))
            {
                why = "扫描根目录或其上级路径不能是符号链接或重解析点：" + raw;
                lastRefusal = why;
                return false;
            }
            if (!Directory.Exists(norm))
            {
                why = "目录不存在或无法访问：" + raw;
                lastRefusal = why;
                return false;
            }
            if (PathGuard.IsReparsePoint(norm))
            {
                why = "扫描根目录不能是符号链接或重解析点：" + raw;
                lastRefusal = why;
                return false;
            }
            if (seen.Add(norm))
            {
                normalized.Add(norm);
            }
        }

        if (normalized.Count == 0)
        {
            why = "扫描路径为空";
            lastRefusal = why;
            return false;
        }

        PathPool.Clear();
        engine = new ScanEngine(normalized, budget, enumerator, analyzer);
        currentRoots.Clear();
        currentRoots.AddRange(normalized);
        root = normalized[0];
        generation++;
        delivered = 0;
        finalized = false;
        HadIncomplete = false;
        state = ScanSessionState.Scanning;
        lastRefusal = "";
        engine.Start();
        return true;
    }

    public static string NormalizeScanRoot(string rawRoot)
    {
        if (String.IsNullOrEmpty(rawRoot)) return "";
        string trimmed = rawRoot.Trim();
        if (trimmed.Length == 0) return "";
        if (trimmed.Length == 2 && trimmed[1] == ':') trimmed += "\\";
        try
        {
            string full = Path.GetFullPath(trimmed);
            string pathRoot = Path.GetPathRoot(full);
            if (!String.IsNullOrEmpty(pathRoot) && String.Equals(full, pathRoot, StringComparison.OrdinalIgnoreCase))
            {
                return pathRoot;
            }
            return full.TrimEnd('\\', '/');
        }
        catch
        {
            return "";
        }
    }

    /// <summary>
    /// 把已就绪的批次搬进 into。每次最多取 maxBatches 批 / maxRows 行 ——
    /// 这是界面侧的硬上限，保证 UI 更新不会无限堆积。
    /// 返回本次搬入的行数。
    /// </summary>
    public int Pump(List<ListRow> into, int maxBatches, int maxRows)
    {
        ScanEngine e = engine;
        if (e == null || into == null) return 0;

        int added = 0, batches = 0;
        ScanBatch b;
        while (batches < maxBatches && added < maxRows && e.TryTakeBatch(out b, 0))
        {
            into.AddRange(b.Rows);
            added += b.Rows.Count;
            batches++;
        }
        delivered += added;
        return added;
    }

    /// <summary>请求取消。幂等；已经退出则什么都没发生。</summary>
    public void RequestCancel()
    {
        ScanEngine e = engine;
        if (e == null || e.HasExited) return;
        state = ScanSessionState.Cancelling;
        e.RequestCancel();
    }

    /// <summary>
    /// 每轮只成功一次：本轮已“落定”（生产者退出，或已达单轮预算并暂停，且队列已排空）时，
    /// 给出进度快照供调用方做一次收尾（排序、统计、文案）。
    /// 注意：暂停也会让 TryFinalize 成功（否则暂停期间界面没有稳定状态），
    /// 但它**不是结束**：继续分析会重置 finalized。
    /// </summary>
    public bool TryFinalize(out ScanProgress final)
    {
        final = null;
        ScanEngine e = engine;
        if (e == null || finalized) return false;
        if (!((e.HasExited || e.IsParked) && e.PendingBatches == 0)) return false;

        finalized = true;
        state = e.HasExited ? ScanSessionState.Idle : ScanSessionState.Paused;
        final = e.Progress;
        HadIncomplete = !final.IsScanExhaustive || final.RowsDropped > 0
                        || final.Failed > 0 || final.ContentUnverified > 0
                        || e.LastError.Length > 0;
        return true;
    }

    /// <summary>
    /// 继续同一会话的分析。
    /// **不新建引擎、不递增 Generation、不清空已交付结果** ——
    /// 行对象身份、勾选状态、筛选与排序因此天然保持。
    /// 只允许在生产者确实处于暂停态时成功；否则返回 false 并给出真实原因，
    /// 调用方必须把原因告知用户，不得假装还在继续。
    /// </summary>
    public bool TryContinue(out string why)
    {
        why = "";
        ScanEngine e = engine;
        if (e == null) { why = "还没有扫描过，没有可继续的内容。"; return false; }
        if (e.HasExited)
        {
            why = e.ResumeBlocked.Length > 0 ? e.ResumeBlocked : "上一轮扫描已经结束，无法继续。";
            return false;
        }
        if (!e.IsParked) { why = "当前不在「可继续」状态。"; return false; }
        if (!e.RequestResume())
        {
            why = e.ResumeBlocked.Length > 0 ? e.ResumeBlocked : "继续分析未被接受（状态已变化）。";
            return false;
        }
        state = ScanSessionState.Scanning;
        finalized = false;                 // 会话重新变回“未落定”
        return true;
    }

    /// <summary>
    /// 释放暂停中的游标（find 句柄 + 生产者线程）。用于：新扫描、Reset、关窗。
    /// 返回生产者是否确实已退出 —— 未退出意味着线程/句柄可能仍存活，
    /// 调用方必须如实告知，不得当成“已释放”。
    /// </summary>
    public bool ReleasePausedCursor()
    {
        ScanEngine e = engine;
        if (e == null || e.HasExited) return true;
        state = ScanSessionState.Cancelling;
        e.RequestCancel();                     // Park 会就此醒来并释放游标
        bool exited = e.WaitForExit(TimeSpan.FromSeconds(3));
        if (!exited)
        {
            e.StopConsuming();                 // 解除背压，让停在入队上的线程也能退出
            exited = e.WaitForExit(TimeSpan.FromSeconds(2));
        }
        if (exited) e.AbandonPending();
        return exited;
    }

    /// <summary>
    /// 关窗 / 退出时调用：先请求取消并给一次优雅退出的机会；
    /// 仍未退出则 StopConsuming 解除背压（丢掉的行数由引擎如实计数），最后再等一小段。
    /// 最后**把队列里剩下的行显式计为丢弃** —— 窗口关了，不会再有人取它们。
    /// 返回后台线程是否已真正退出。
    /// </summary>
    public bool Shutdown(TimeSpan graceful)
    {
        ScanEngine e = engine;
        if (e == null) return true;

        bool exited;
        if (e.HasExited)
        {
            exited = true;
        }
        else
        {
            state = ScanSessionState.Cancelling;
            e.RequestCancel();
            exited = e.WaitForExit(graceful);
            if (!exited)
            {
                e.StopConsuming();
                exited = e.WaitForExit(TimeSpan.FromSeconds(2));
            }
        }

        // 只有确认生产者已经不跑了，排空队列才是安全的（否则它还会继续入队）。
        if (exited) e.AbandonPending();
        return exited;
    }

    /// <summary>恢复成“从未扫描过”的状态（仅用于演示模式等不需要真实扫描的场合）。</summary>
    public void Reset()
    {
        ScanEngine e = engine;
        if (e != null && !e.HasExited)
        {
            state = ScanSessionState.Cancelling;
            e.RequestCancel();
            e.StopConsuming();
            // 暂停态下必须等它醒过来、释放游标再走 —— 否则 Reset 之后
            // 会短暂存在一个已经没人引用的线程 + 打开的 find 句柄。
            e.WaitForExit(TimeSpan.FromSeconds(3));
            if (!e.HasExited)
            {
                // 生产者尚未退出时严禁清空 engine 或复位 Idle，防止同时并发第二个引擎。
                return;
            }
        }
        if (e != null && e.HasExited) e.AbandonPending();
        engine = null;
        currentRoots.Clear();
        root = "";
        state = ScanSessionState.Idle;
        finalized = false;
        delivered = 0;
        HadIncomplete = false;
    }

    // ---- 预算钩子 ----

    private static int ClampInt(double v, int min, int max)
    {
        if (v < (double)min) return min;
        if (v > (double)max) return max;
        return (int)v;
    }

    private static long ClampLong(double v, long min, long max)
    {
        if (v < (double)min) return min;
        if (v > (double)max) return max;
        return (long)v;
    }

    private static double ClampDouble(double v, double min, double max)
    {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }

    /// <summary>
    /// 正式扫描默认高容量预算；若设置了验收钩子
    /// CANIDELETE_SCAN_LIMITS="entries=40;time=5;hash=1;rows=512;batch=8"
    /// 则按键值覆盖对应上限，供小型沙盒确定性复现预算触顶与暂停。
    /// </summary>
    public static ScanBudget BudgetFromEnvironment(string spec)
    {
        ScanBudget b = new ScanBudget();
        b.MaxTopLevelEntries = 5000000;
        b.MaxAnalyzedEntries = 5000000;
        b.MaxSessionRows = 5000000;
        b.MaxFileStats = 5000000;
        b.MaxDirVisits = 2000000;
        b.MaxHashBytes = 2L * 1024 * 1024 * 1024;
        b.MaxDuration = TimeSpan.FromHours(2);
        b.MaxParkedDuration = TimeSpan.FromMinutes(10);
        if (String.IsNullOrEmpty(spec) || spec.Trim().Length == 0) return b;

        string[] parts = spec.Split(new char[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string raw in parts)
        {
            int eq = raw.IndexOf('=');
            if (eq <= 0) continue;
            string k = raw.Substring(0, eq).Trim().ToLowerInvariant();
            string v = raw.Substring(eq + 1).Trim();
            double num;
            if (!double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out num)) continue;
            if (double.IsNaN(num) || double.IsInfinity(num) || num <= 0.0) continue;

            switch (k)
            {
                case "entries": b.MaxTopLevelEntries = ClampInt(num, 1, 5000000); break;
                case "analyzed": b.MaxAnalyzedEntries = ClampInt(num, 1, 5000000); break;
                case "files": b.MaxFileStats = ClampLong(num, 1L, 5000000L); break;
                case "dirs": b.MaxDirVisits = ClampLong(num, 1L, 5000000L); break;
                case "hash": b.MaxHashBytes = ClampLong(num * 1024.0 * 1024.0, 1L, 16L * 1024L * 1024L * 1024L); break;
                case "time": b.MaxDuration = TimeSpan.FromSeconds(ClampDouble(num, 0.1, 86400.0)); break;
                case "rows": b.MaxPendingRows = ClampInt(num, 1, 65536); break;
                case "batch": b.BatchSize = ClampInt(num, 1, 4096); break;
                // v0.5.0 第三批：全会话累计结果上限与暂停保留时长（测试用短值）
                case "sessionrows": b.MaxSessionRows = ClampInt(num, 1, 5000000); break;
                case "park": b.MaxParkedDuration = TimeSpan.FromSeconds(ClampDouble(num, 0.1, 3600.0)); break;
            }
        }
        return b;
    }
}
