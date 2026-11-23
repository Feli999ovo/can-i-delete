using System;
using System.Collections.Generic;
using System.IO;
// 注：不再引用 Microsoft.VisualBasic.FileIO —— 旧回收后端已删除，
// 产品里不允许再出现那两条 FileSystem.Delete* 调用。

// =====================================================================
// 删除执行层（P0）：不信任快照、不信任 UI，逐项独立重算授权与身份。
//
// 设计要点：
//   * 代码级闸门 BuildAllowsRealDeletion（编译期常量）：整改验收通过前，
//     任何删除都会被拒绝，不依赖界面是否隐藏按钮。
//   * 授权在执行层重新计算（SafetyPolicy.Decide），扫描快照里的 PolicyEligible
//     只作为“必须为 true”的前置条件，不作为依据。
//   * 身份用「卷号 + 文件索引」核对，大小/时间/只读位只作辅助。
//   * 回收站通过 IRecycleBin 抽象，便于用 Fake 做自动化测试。
//   * 不提供任何永久删除路径；不做权限提升；不结束占用进程。
// =====================================================================

/// <summary>
/// 单项操作的结果状态（执行契约 v1）。
///
/// 铁律：
///   * 只有 <see cref="RecycledVerified"/> 允许被描述为"已回收"；
///   * 绝不因为"原路径消失"就认定回收；
///   * 绝不因为"路径还在"就认定"什么都没发生"；
///   * 结果不明时必须停下来，后续项目不再派发。
/// </summary>
public enum DeleteStatus
{
    /// <summary>有确凿回收证据（当前=事后三重取证；方案 A 落地后=同步 psiNewlyCreated）。</summary>
    RecycledVerified,
    /// <summary>已永久删除并核实：同一句柄核对身份后删除，事后原路径已不存在。**不可恢复**。</summary>
    DeletedVerified,
    /// <summary>动作尚未派发就被拒绝：授权 / 前置 / 闸门任一未过。**未发生任何操作**。</summary>
    RefusedNotDispatched,
    /// <summary>操作失败，**且已重新核验**原对象仍在原处、文件身份一致。</summary>
    FailedStillPresent,
    /// <summary>结果未知：对象可能已变化、可能已消失，无法证明已回收。**必须报警**。</summary>
    OutcomeUnknown,
    /// <summary>有 intent 无 outcome（崩溃遗留）：待核实。**不得**推断为已删除。</summary>
    PendingReconciliation,
    /// <summary>批次中因上一项结果不明而被停止、未执行的剩余项目。</summary>
    NotExecutedDueToStop
}

/// <summary>
/// 拒绝/异常的具体理由。它与 Status 分开：
/// Status 回答"可不可信、要不要停下"，Kind 回答"为什么"。
/// 前置拒绝矩阵就是靠 Kind 逐条断言的。
/// </summary>
public enum DeleteRefusalKind
{
    None = 0,
    // ---- 派发前拒绝 ----
    GateDisabled,             // 编译期 / 运行期闸门
    NotEligibleAtScan,        // 扫描阶段的授权结论为 false
    OutOfScope,               // 越出扫描根
    ReparseAncestor,          // 祖先链含符号链接 / 目录联接点
    PathNotCanonical,         // 无法规范化
    Vanished,                 // 目标已不存在
    TypeChanged,              // 文件 / 目录类型变了
    ReparseTarget,            // 目标自身是重解析点
    NonEmptyDirectory,        // 非空目录禁止递归删除
    DirectoryRefused,         // 目录一律不授权（策略层硬拒绝）
    IdentityUnreadable,       // 取不到强身份
    IdentityChanged,          // 强身份变化（被替换）
    WeakIdentityChanged,      // 大小 / 修改时间 / 只读位变化
    PolicyRecomputeDenied,    // 执行层重算未通过
    RiskChanged,              // 重算类别与扫描时不一致
    DirSizeIncomplete,        // 目录体积不完整（**新增**：下界不得当上限用）
    VolumeNotSupported,       // 卷不支持回收站（非固定盘 / 无 $Recycle.Bin）
    NukeOnDelete,             // 回收站被配置为直接永久删除
    CapacityUnknown,          // 回收站可用容量未知（**新增**：未知即拒绝）
    CapacityInsufficient,     // 回收站容量不足
    LogUnwritable,            // 审计日志不可写（**新增**：不可信即不动文件）
    SafetyStop                // 上一项结果不明，本项未派发
}

/// <summary>
/// 动作到底有没有被派发过。
///
/// 为什么不能用 bool：intent 是在派发**之前**写的，因此“有 intent”只能推出
/// “_可能_已经派发了”，推不出“已经派发”。把它写成 bool 会把“不确定”
/// 静默归入“是”或“否”其中一个 —— 两种归法都是错误的陈述。
/// </summary>
public enum DispatchState
{
    /// <summary>确定未派发（所有前置拒绝路径，以及因安全原因未执行的尾项）。</summary>
    NotDispatched,
    /// <summary>**无法确定**：意图记录存在但结果丢失（崩溃遗留）。</summary>
    Unknown,
    /// <summary>确定派发过（调用已发生，无论成败）。</summary>
    Dispatched
}

/// <summary>一次删除请求（来自扫描快照 + 安全授权）。</summary>
public sealed class DeleteRequest
{
    public string Path = "";
    public bool WasDirectory;
    public long BytesAtScan;
    public DateTime LastWriteUtcAtScan;
    public bool WasReadOnly;
    public bool PolicyEligible;                 // 扫描阶段的授权结论（必须为 true 才继续）
    public string Risk = "";
    public FileIdentity IdAtScan;          // 扫描阶段抓到的强身份
}

/// <summary>单个目标的执行结果。</summary>
public sealed class DeleteOutcome
{
    public string Path = "";
    public DeleteStatus Status;
    public DeleteRefusalKind Kind = DeleteRefusalKind.None;
    public string Detail = "";
    /// <summary>该次操作的唯一 ID（与日志中的 intent / outcome 一致）。</summary>
    public string OpId = "";

    /// <summary>动作是否真的派发过 —— 三态，不是 bool。</summary>
    public DispatchState Dispatch = DispatchState.NotDispatched;

    /// <summary>是否**确定**派发过。</summary>
    public bool WasDispatched { get { return Dispatch == DispatchState.Dispatched; } }

    /// <summary>派发与否**无法确定**（崩溃遗留：有 intent 无 outcome）。</summary>
    public bool DispatchUncertain { get { return Dispatch == DispatchState.Unknown; } }

    public bool IsSuccess { get { return Status == DeleteStatus.RecycledVerified || Status == DeleteStatus.DeletedVerified; } }

    /// <summary>是否需要用户立即人工核实（存在数据已不可逆丢失的可能）。</summary>
    public bool NeedsUrgentReview
    {
        get { return Status == DeleteStatus.OutcomeUnknown || Status == DeleteStatus.PendingReconciliation; }
    }
}

/// <summary>回收站抽象。真实实现只允许“送入回收站”，不得降级为永久删除。</summary>
public interface IRecycleBin
{
    /// <summary>
    /// 派发前的可用性 / 容量预检。
    /// 注意语义：这是**必要而非充分**条件 —— 通过它**不等于**能成功回收。
    /// <paramref name="sizeComplete"/> = false 时表示调用方给的体积只是下界，
    /// 实现必须拒绝（不得把下界当上限做容量判断）。
    /// </summary>
    bool IsAvailable(string path, long bytes, bool sizeComplete, out string reason, out DeleteRefusalKind kind);

    RecycleEvidence SendFile(string path);
}

/// <summary>删除执行器。</summary>
public static class DeleteEngine
{
    /// <summary>
    /// 闸门自检：任何直接调用真实后端都逃不过这一层。
    /// 看的是**编译期常量**，而不是可被测试改写的运行期字段 ——
    /// 因此本构建里真实回收站永远无法被调用（测试也不行）。
    /// </summary>
    internal static void RequireGate()
    {
        if (!BuildAllowsRealDeletion) throw new InvalidOperationException(DisabledReason);
    }

    /// <summary>
    /// 出厂构建是否允许真实删除。P0 验收通过前必须为 false。
    /// 它是编译期常量，也是 RealDeletionEnabled 的初值。
    /// 要放开删除必须改这一行并重新构建 —— 没有运行期开关能让产品构建放开。
    /// 自动化测试会直接改写 RealDeletionEnabled，以便验证回收站调用逻辑；
    /// 产品代码从不修改它（已由测试断言）。
    /// </summary>
    public const bool BuildAllowsRealDeletion = false;

    /// <summary>
    /// 唯一的运行期闸门。初值取自编译期常量（当前为 false）。
    /// 产品代码不写它；只有 tests/SelfTest.cs 会临时置 true。
    /// </summary>
    public static bool RealDeletionEnabled = BuildAllowsRealDeletion;

    /// <summary>
    /// 【四层权限模型的第四层】当前实际是否允许执行删除。
    ///
    /// 必须与前三层分清：
    ///   Risk             —— 文件分析与风险分类（像什么）
    ///   PolicyEligible   —— 根据证据获得的**候选**清理资格
    ///   Checked          —— 用户是否选择
    ///   ExecutionAllowed —— 当前**实际**是否允许执行（含运行期与编译期闸门）
    ///
    /// 禁止把「规则认为可以清理」等同于「当前可以执行删除」。
    /// PolicyEligible == true 而 ExecutionAllowed == false 是正常且预期的状态。
    /// </summary>
    public static bool ExecutionAllowed { get { return RealDeletionEnabled; } }

    /// <summary>
    /// 永久删除闸门（用户 2026-11 批准）。只放行 PermanentDeleteBin：同一句柄核对身份后删除、
    /// 不承诺可恢复。回收站路径仍由 BuildAllowsRealDeletion=false 锁住（NO-GO 未变）。
    /// </summary>
    public const bool BuildAllowsPermanentDelete = true;

    /// <summary>给定后端当前是否允许执行：永久删除只看其独立闸门，其他后端只看旧闸门。</summary>
    public static bool AllowsBackend(IRecycleBin bin)
    { return bin is PermanentDeleteBin ? BuildAllowsPermanentDelete : ExecutionAllowed; }

    public const string DisabledReason =
        "真实删除已在当前构建中被代码级禁用（P0 安全整改尚未通过验收）。";

    /// <summary>
    /// 批量执行。契约要点：
    ///   * 日志不可写 → **整批拒绝派发**；
    ///   * 逐项独立：一项抛异常不得终止整批，也不得让结果丢失；
    ///   * 出现不明结果（OutcomeUnknown）→ **停止后续危险操作**，
    ///     剩余项标为 NotExecutedDueToStop；
    ///   * 每项都有唯一 opId，intent 与 outcome 都在日志里可对账。
    /// </summary>
    public static List<DeleteOutcome> Execute(IList<DeleteRequest> requests, string scanRoot,
                                              IRecycleBin bin, string logPath)
    { return Execute(requests, scanRoot, bin, logPath, null, null); }

    /// <summary>
    /// 带进度与停止的版本。stopRequested 只在两项之间检查：已开始的那一项总会走完并写完日志，
    /// 剩余项标为「未执行」。
    /// </summary>
    public static List<DeleteOutcome> Execute(IList<DeleteRequest> requests, string scanRoot,
                                              IRecycleBin bin, string logPath,
                                              Action<int, int> progress, Func<bool> stopRequested)
    { return Execute(requests, scanRoot, bin, logPath, progress, null, stopRequested); }

    public static List<DeleteOutcome> Execute(IList<DeleteRequest> requests, string scanRoot,
                                              IRecycleBin bin, string logPath,
                                              Action<int, int> progress,
                                              Action<int, int, DeleteRequest, DeleteOutcome> itemProgress,
                                              Func<bool> stopRequested)
    {
        IList<string> roots = scanRoot == null ? new string[0] : new string[] { scanRoot };
        return Execute(requests, roots, bin, logPath, progress, itemProgress, stopRequested);
    }

    public static List<DeleteOutcome> Execute(IList<DeleteRequest> requests, IList<string> scanRoots,
                                              IRecycleBin bin, string logPath)
    { return Execute(requests, scanRoots, bin, logPath, null, null, null); }

    public static List<DeleteOutcome> Execute(IList<DeleteRequest> requests, IList<string> scanRoots,
                                              IRecycleBin bin, string logPath,
                                              Action<int, int> progress, Func<bool> stopRequested)
    { return Execute(requests, scanRoots, bin, logPath, progress, null, stopRequested); }

    public static List<DeleteOutcome> Execute(IList<DeleteRequest> requests, IList<string> scanRoots,
                                              IRecycleBin bin, string logPath,
                                              Action<int, int> progress,
                                              Action<int, int, DeleteRequest, DeleteOutcome> itemProgress,
                                              Func<bool> stopRequested)
    {
        List<DeleteOutcome> results = new List<DeleteOutcome>();
        if (requests == null) return results;
        string batchId = DeleteLog.NewOpId();

        // ---- 前置：审计日志必须可信，否则不动文件（单次打开会话贯穿整批） ----
        string logErr;
        using (DeleteLog.WriterSession logSession = DeleteLog.OpenSession(logPath, out logErr))
        {
            if (logSession == null)
            {
                foreach (DeleteRequest r in requests)
                {
                    DeleteOutcome q = NoDispatch(r, DeleteRefusalKind.LogUnwritable,
                        "审计日志不可写，已拒绝派发任何删除操作（" + logErr + "）。未执行任何操作。");
                    results.Add(q);
                }
                if (requests.Count <= 64)
                {
                    LogAll(logPath, batchId, results);
                }
                return results;
            }

            bool stopped = false;
            string stopWhy = "";
            int index = 0;
            foreach (DeleteRequest r in requests)
            {
                if (progress != null) progress(index, requests.Count);
                if (!stopped && stopRequested != null && stopRequested())
                {
                    stopped = true;
                    stopWhy = "用户停止";
                }
                if (stopped)
                {
                    index++;
                    DeleteOutcome q = NoDispatch(r, DeleteRefusalKind.SafetyStop,
                        stopWhy == "用户停止" ? "已按要求停止，本项未执行。"
                        : "上一项结果不明，已停止后续危险操作（" + stopWhy + "）。本项未执行。");
                    q.Status = DeleteStatus.NotExecutedDueToStop;
                    results.Add(q);
                    string stopLogWhy;
                    logSession.WriteOutcome(q.OpId, batchId, q, out stopLogWhy);
                    continue;
                }

                if (itemProgress != null) itemProgress(index, requests.Count, r, null);
                index++;

                DeleteOutcome o;
                try
                {
                    o = VerifyAndDelete(r, scanRoots, bin, logPath, batchId, logSession);
                }
                catch (Exception ex)
                {
                    // 逐项隔离：未预期异常也不得让结果丢失或让整批静默中断。
                    // 此时无法确认目标状态 ⇒ 归为“结果未知”，并触发停止。
                    o = new DeleteOutcome();
                    o.Path = r == null ? "" : r.Path;
                    o.OpId = DeleteLog.NewOpId();
                    o.Status = DeleteStatus.OutcomeUnknown;
                    o.Detail = "执行过程中出现未预期异常（" + ex.GetType().Name + "），"
                             + "无法确认目标状态，请立即检查回收站与原位置。";
                }
                results.Add(o);
                string logWhy2;
                if (!logSession.WriteOutcome(o.OpId, batchId, o, out logWhy2))
                {
                    // 结果记不下来：继续删就无法事后核对，停止剩余项目。
                    stopped = true;
                    stopWhy = "审计日志写入失败（" + logWhy2 + "）";
                    if (o.Detail.IndexOf("审计日志", StringComparison.Ordinal) < 0)
                        o.Detail += "（注意：本项结果未能写入审计日志）";
                }

                if (itemProgress != null) itemProgress(index, requests.Count, r, o);

                if (o.NeedsUrgentReview)
                {
                    stopped = true;
                    stopWhy = o.Detail;
                }
            }
        }
        return results;
    }

    /// <summary>
    /// 专供用户在「大文件 / 文件详情」手动点选单个文件确认后调用的受控单文件回收入口。
    /// 保持 BuildAllowsRealDeletion=false 锁死批量自动回收，此处仅允许单次送入 Windows 系统回收站
    /// （强制 IFileOperation + FOFX_RECYCLEONDELETE，绝不降级为永久删除）。
    /// </summary>
    public static DeleteOutcome ExecuteSingleRecycle(
        DeleteRequest req,
        IList<string> allowedScanRoots,
        IRecycleBin customBinOrNull,
        string logPath)
    {
        string batchId = DeleteLog.NewOpId();

        string logWhy;
        if (!DeleteLog.EnsureWritable(logPath, out logWhy))
        {
            DeleteOutcome refusedLog = NoDispatch(req, DeleteRefusalKind.LogUnwritable,
                "审计日志不可写，已拒绝派发单文件移入回收站操作（" + logWhy + "）。未执行任何操作。");
            string ignored;
            DeleteLog.WriteOutcome(logPath, refusedLog.OpId, batchId, refusedLog, out ignored);
            return refusedLog;
        }

        DeleteOutcome o;
        try
        {
            o = VerifyAndSingleRecycle(req, allowedScanRoots, customBinOrNull, logPath, batchId);
        }
        catch (Exception ex)
        {
            o = new DeleteOutcome();
            o.Path = req == null ? "" : req.Path;
            o.OpId = DeleteLog.NewOpId();
            o.Status = DeleteStatus.OutcomeUnknown;
            o.Detail = "单文件移入回收站过程中出现未预期异常（" + ex.GetType().Name + "），"
                     + "无法确认目标状态，请立即检查回收站与原位置。";
        }

        string logWhy2;
        if (!DeleteLog.WriteOutcome(logPath, o.OpId, batchId, o, out logWhy2))
        {
            if (o.Detail.IndexOf("审计日志", StringComparison.Ordinal) < 0)
                o.Detail += "（注意：本项结果未能写入审计日志：" + logWhy2 + "）";
        }
        return o;
    }

    private static DeleteOutcome VerifyAndSingleRecycle(
        DeleteRequest req,
        IList<string> allowedScanRoots,
        IRecycleBin customBinOrNull,
        string logPath,
        string batchId)
    {
        // ---- 1. 请求有效性：拒绝空请求与任何目录 ----
        if (req == null)
            return NoDispatch(null, DeleteRefusalKind.NotEligibleAtScan, "单文件回收请求为空，拒绝处理");
        if (req.WasDirectory)
            return NoDispatch(req, DeleteRefusalKind.DirectoryRefused, "目录不允许移入回收站（仅支持单个普通文件）");

        // ---- 2. 受保护保留类文件硬拒绝 ----
        if (String.Equals(req.Risk, EvidenceRules.RiskKeep, StringComparison.Ordinal))
            return NoDispatch(req, DeleteRefusalKind.NotEligibleAtScan,
                "受保护的系统或关键文件（保留类）不允许移入回收站");

        if (String.IsNullOrEmpty(req.Path))
            return NoDispatch(req, DeleteRefusalKind.PathNotCanonical, "目标路径为空，拒绝处理");

        // ---- 3. 范围守卫与重解析点守卫 ----
        if (allowedScanRoots == null || allowedScanRoots.Count == 0)
            return NoDispatch(req, DeleteRefusalKind.OutOfScope, "未指定有效的扫描根目录范围，拒绝移入回收站");

        string target = PathGuard.Canonical(req.Path);
        if (target.Length == 0 || !Path.IsPathRooted(target))
            return NoDispatch(req, DeleteRefusalKind.PathNotCanonical, "无法规范化目标路径，拒绝处理");

        string targetDriveRoot = Path.GetPathRoot(target);
        if (!String.IsNullOrEmpty(targetDriveRoot)
            && String.Equals(target.TrimEnd('\\', '/') + "\\", targetDriveRoot, StringComparison.OrdinalIgnoreCase))
        {
            return NoDispatch(req, DeleteRefusalKind.DirectoryRefused, "磁盘根目录不允许移入回收站");
        }

        string matchedRoot = FindMatchingScanRoot(allowedScanRoots, target, true);
        if (matchedRoot.Length == 0)
            return NoDispatch(req, DeleteRefusalKind.OutOfScope, "目标位于本次扫描范围之外，拒绝移入回收站");

        if (PathGuard.IsReparsePoint(matchedRoot))
            return NoDispatch(req, DeleteRefusalKind.ReparseAncestor,
                "扫描根目录自身为符号链接或重解析点，拒绝移入回收站");

        if (PathGuard.HasReparseAncestor(matchedRoot, target))
            return NoDispatch(req, DeleteRefusalKind.ReparseAncestor,
                "目标的上级路径中含有符号链接 / 目录联接点 / 卷挂载点，拒绝移入回收站");

        bool existsFile = File.Exists(target);
        bool existsDir = Directory.Exists(target);
        if (!existsFile && !existsDir)
            return NoDispatch(req, DeleteRefusalKind.Vanished, "目标文件已不存在，未执行任何操作");
        if (existsDir || !existsFile)
            return NoDispatch(req, DeleteRefusalKind.TypeChanged, "目标当前不是普通文件，拒绝移入回收站");
        if (PathGuard.IsReparsePoint(target))
            return NoDispatch(req, DeleteRefusalKind.ReparseTarget, "目标是符号链接或重解析点，拒绝移入回收站");

        // ---- 4. 强身份与弱身份复验 + 实时占用探测 + 实时 KEEP-* 规则硬拦截 ----
        FileIdentity nowId = FileIdentityProbe.Capture(target);
        if (!nowId.Ok)
            return NoDispatch(req, DeleteRefusalKind.IdentityUnreadable, "无法取得目标当前的文件标识，拒绝处理");

        if (req.IdAtScan.Ok && !nowId.SameAs(req.IdAtScan))
            return NoDispatch(req, DeleteRefusalKind.IdentityChanged,
                "目标已被替换（文件标识 " + req.IdAtScan + " → " + nowId + "），已中止");

        FileInfo fi;
        try
        {
            fi = new FileInfo(target);
            if (!fi.Exists)
                return NoDispatch(req, DeleteRefusalKind.Vanished, "目标文件已不存在，未执行任何操作");
            if ((fi.Attributes & FileAttributes.Directory) != 0)
                return NoDispatch(req, DeleteRefusalKind.TypeChanged, "目标已变为目录，拒绝移入回收站");
            if ((fi.Attributes & FileAttributes.ReparsePoint) != 0)
                return NoDispatch(req, DeleteRefusalKind.ReparseTarget, "目标是符号链接或重解析点，拒绝移入回收站");
        }
        catch
        {
            return NoDispatch(req, DeleteRefusalKind.WeakIdentityChanged, "无法读取目标文件当前属性，已中止");
        }

        if (req.BytesAtScan < 0 || fi.Length != req.BytesAtScan)
            return NoDispatch(req, DeleteRefusalKind.WeakIdentityChanged,
                "扫描后目标文件大小已发生变化，已中止");

        if (req.LastWriteUtcAtScan == DateTime.MinValue
            || Math.Abs((fi.LastWriteTimeUtc - req.LastWriteUtcAtScan).TotalSeconds) > 2.0)
        {
            return NoDispatch(req, DeleteRefusalKind.WeakIdentityChanged,
                "扫描后目标文件修改时间已发生变化，已中止");
        }

        bool nowReadOnly = (fi.Attributes & FileAttributes.ReadOnly) != 0;
        if (nowReadOnly != req.WasReadOnly)
            return NoDispatch(req, DeleteRefusalKind.WeakIdentityChanged,
                "扫描后目标文件只读属性已发生变化，已中止");

        int liveDays = 0;
        try
        {
            liveDays = (int)(DateTime.Now - fi.LastWriteTime).TotalDays;
            if (liveDays < 0) liveDays = 0;
        }
        catch { liveDays = 0; }

        Evidence liveRule = EvidenceRules.Evaluate(Path.GetFileName(target), target, liveDays);
        if (liveRule != null
            && (String.Equals(liveRule.Risk, EvidenceRules.RiskKeep, StringComparison.Ordinal)
                || (!String.IsNullOrEmpty(liveRule.RuleId)
                    && liveRule.RuleId.StartsWith("KEEP-", StringComparison.OrdinalIgnoreCase))))
        {
            return NoDispatch(req, DeleteRefusalKind.PolicyRecomputeDenied,
                "受保护的系统或关键文件（" + liveRule.RuleId + "：" + liveRule.Reason + "）不允许移入回收站");
        }

        LockState ls = LockProbe.Probe(target);
        if (ls != LockState.Free)
        {
            return NoDispatch(req, DeleteRefusalKind.PolicyRecomputeDenied,
                ls == LockState.Occupied
                    ? "该文件正被其他程序占用，无法移入回收站"
                    : "无法确认该文件是否正被使用，拒绝移入回收站");
        }

        // ---- 5. 回收站后端与可用性预检（绝不降级为永久删除）----
        if (customBinOrNull is PermanentDeleteBin)
            return NoDispatch(req, DeleteRefusalKind.GateDisabled, "单文件回收入口严禁使用永久删除后端");

        IRecycleBin bin = customBinOrNull != null ? customBinOrNull : WindowsRecycleBin.CreateForSingleFile();
        string availWhy;
        DeleteRefusalKind ck;
        if (!bin.IsAvailable(target, fi.Length, true, out availWhy, out ck))
        {
            return NoDispatch(req, ck == DeleteRefusalKind.None ? DeleteRefusalKind.CapacityUnknown : ck,
                "系统回收站预检未通过（为避免直接永久删除已拒绝操作）：" + availWhy);
        }

        // ---- 6. 审计日志 intent 先行 ----
        DeleteOutcome o = new DeleteOutcome();
        o.Path = req.Path;
        o.OpId = DeleteLog.NewOpId();

        DeleteRequest intentReq = new DeleteRequest();
        intentReq.Path = req.Path;
        intentReq.WasDirectory = false;
        intentReq.BytesAtScan = req.BytesAtScan;
        intentReq.LastWriteUtcAtScan = req.LastWriteUtcAtScan;
        intentReq.WasReadOnly = req.WasReadOnly;
        intentReq.PolicyEligible = req.PolicyEligible;
        intentReq.Risk = req.Risk;
        intentReq.IdAtScan = req.IdAtScan.Ok ? req.IdAtScan : nowId;

        string intentWhy;
        if (!DeleteLog.WriteIntent(logPath, o.OpId, batchId, intentReq, target, out intentWhy))
        {
            return NoDispatch(req, DeleteRefusalKind.LogUnwritable,
                "审计日志写入 intent 失败，已拒绝派发操作（" + intentWhy + "）。未执行任何操作。");
        }

        // ---- 7. 派发与事后核验 ----
        o.Dispatch = DispatchState.Dispatched;
        RecycleEvidence rev = null;
        string dispatchError = "";
        try
        {
            rev = bin.SendFile(target);
        }
        catch (Exception ex)
        {
            dispatchError = ex.GetType().Name + "：" + ex.Message;
        }

        bool stillThere = File.Exists(target) || Directory.Exists(target);
        bool identitySame = false;
        if (stillThere)
        {
            FileIdentity after = FileIdentityProbe.Capture(target);
            identitySame = after.Ok && nowId.Ok && after.SameAs(nowId);
        }

        o.Status = WindowsRecycleBin.Classify(rev, stillThere, identitySame);
        o.Detail = WindowsRecycleBin.Describe(rev, stillThere, identitySame);
        if (dispatchError.Length > 0)
            o.Detail = "派发时抛出异常（" + dispatchError + "）。" + o.Detail;
        return o;
    }

    private static string NormalizeRootForScope(string rawRoot)
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
                return pathRoot;
            return full.TrimEnd('\\', '/');
        }
        catch { return ""; }
    }

    private static string FindMatchingScanRoot(IList<string> scanRoots, string targetPath, bool forbidTargetEqualsRoot)
    {
        if (scanRoots == null || scanRoots.Count == 0 || String.IsNullOrEmpty(targetPath)) return "";
        string canonTarget = PathGuard.Canonical(targetPath);
        if (canonTarget.Length == 0) return "";

        string best = "";
        for (int i = 0; i < scanRoots.Count; i++)
        {
            string norm = NormalizeRootForScope(scanRoots[i]);
            if (norm.Length == 0) continue;
            if (!PathGuard.IsInside(norm, targetPath)) continue;
            if (forbidTargetEqualsRoot && String.Equals(PathGuard.Canonical(norm), canonTarget, StringComparison.OrdinalIgnoreCase))
                continue;
            if (norm.Length > best.Length) best = norm;
        }
        return best;
    }

    private static DeleteOutcome VerifyAndDelete(DeleteRequest r, IList<string> scanRoots,
                                                 IRecycleBin bin, string logPath, string batchId,
                                                 DeleteLog.WriterSession logSession)
    {
        DeleteOutcome o = new DeleteOutcome();
        o.Path = r.Path;
        o.OpId = DeleteLog.NewOpId();

        // ---- 0. 运行期闸门：永久删除走独立闸门；回收站走旧闸门（编译期常量仍为 false）----
        if (!AllowsBackend(bin))
            return NoDispatch(r, DeleteRefusalKind.GateDisabled, DisabledReason);

        // ---- 1. 扫描阶段的授权结论必须为 true（前置条件，非依据）----
        if (!r.PolicyEligible)
            return NoDispatch(r, DeleteRefusalKind.NotEligibleAtScan,
                "该项目未通过删除授权（分级：" + r.Risk + "）");

        // ---- 2. 范围：必须在扫描根之内，且祖先链没有重解析点 ----
        string matchedRoot = FindMatchingScanRoot(scanRoots, r.Path, false);
        if (matchedRoot.Length == 0)
            return NoDispatch(r, DeleteRefusalKind.OutOfScope, "目标位于扫描根目录之外");
        if (PathGuard.HasReparseAncestor(matchedRoot, r.Path))
            return NoDispatch(r, DeleteRefusalKind.ReparseAncestor,
                "目标的上级路径中含有符号链接 / 目录联接点 / 卷挂载点");

        // MSDN 事实：pFrom 不是完整路径时，即使设了 FOF_ALLOWUNDO 也不会进回收站
        // （会被静默永久删除）。因此实际调用一律使用规范化后的绝对路径。
        string target = PathGuard.Canonical(r.Path);
        if (target.Length == 0 || !Path.IsPathRooted(target))
            return NoDispatch(r, DeleteRefusalKind.PathNotCanonical, "无法规范化目标路径，拒绝处理");

        // ---- 3. 存在性与类型 ----
        bool existsFile = File.Exists(target);
        bool existsDir = Directory.Exists(target);
        if (!existsFile && !existsDir)
            return NoDispatch(r, DeleteRefusalKind.Vanished, "目标已不存在，未执行任何删除");
        if (existsDir != r.WasDirectory)
            return NoDispatch(r, DeleteRefusalKind.TypeChanged,
                "目标类型已改变（扫描时是" + (r.WasDirectory ? "目录" : "文件") + "）");

        // ---- 4. 目标自身不得是重解析点 ----
        if (PathGuard.IsReparsePoint(target))
            return NoDispatch(r, DeleteRefusalKind.ReparseTarget,
                "目标是符号链接 / 目录联接点，拒绝处理");

        // ---- 5. 非空目录不得递归删除 ----
        if (existsDir && !DirScan.IsEmptyDirectory(target))
            return NoDispatch(r, DeleteRefusalKind.NonEmptyDirectory,
                "非空目录禁止递归删除（当前版本未逐项核验目录内容）");

        // ---- 6. 身份（强）：卷号 + 文件索引 ----
        FileIdentity nowId = FileIdentityProbe.Capture(target);
        if (!nowId.Ok)
            return NoDispatch(r, DeleteRefusalKind.IdentityUnreadable, "无法取得目标的文件标识，拒绝处理");
        if (!r.IdAtScan.Ok)
            return NoDispatch(r, DeleteRefusalKind.IdentityUnreadable, "扫描时未记录目标的文件标识，拒绝处理");
        if (!nowId.SameAs(r.IdAtScan))
            return NoDispatch(r, DeleteRefusalKind.IdentityChanged,
                "目标已被替换（文件标识 " + r.IdAtScan + " → " + nowId + "），已中止");

        // ---- 7. 辅助身份（大小 / 时间 / 只读位）----
        string weak = WeakIdentityChanged(r, target, existsDir, existsFile);
        if (weak.Length > 0)
            return NoDispatch(r, DeleteRefusalKind.WeakIdentityChanged,
                "扫描后目标已发生变化（" + weak + "），已中止");

        // ---- 8. 构造“当下事实”（供重算与容量预检用）----
        ScanItem live = BuildLiveItem(r, target, existsDir, existsFile);

        // ---- 8b. 体积不完整 ⇒ 拒绝（新增）----
        // 下界不得当上限用：路径体积不完整时，配额判断与“已分析体积”都不可信。
        if (!live.SizeComplete)
            return NoDispatch(r, DeleteRefusalKind.DirSizeIncomplete,
                "目标体积不完整（只得到已知下界），无法可靠判断回收站容量，已中止");

        // ---- 9. 执行层独立重算授权（不信任快照，不信任 UI）----
        LockState ls = existsDir ? LockState.Free : LockProbe.Probe(target);
        Evidence fresh = SafetyPolicy.Decide(live, ls);
        if (!fresh.PolicyEligible)
        {
            DeleteRefusalKind k = existsDir ? DeleteRefusalKind.DirectoryRefused : DeleteRefusalKind.PolicyRecomputeDenied;
            return NoDispatch(r, k, "执行层重新判定未通过授权：" + fresh.DenyReason);
        }
        if (fresh.Risk != r.Risk)
            return NoDispatch(r, DeleteRefusalKind.RiskChanged,
                "执行层重新判定的类别与扫描时不一致（" + r.Risk + " → " + fresh.Risk + "），已中止");

        // ---- 10. 回收站可用性 / 容量（**必要非充分**；绝不降级为永久删除）----
        string why;
        DeleteRefusalKind ck;
        if (!bin.IsAvailable(target, live.Bytes, live.SizeComplete, out why, out ck))
            return NoDispatch(r, ck == DeleteRefusalKind.None ? DeleteRefusalKind.CapacityUnknown : ck,
                "回收站预检未通过（容量判断是必要条件，不等于保证能回收）：" + why);

        // ---- 11. intent 先行：写不下去就不许动手 ----
        string intentWhy;
        bool intentOk = logSession != null
            ? logSession.WriteIntent(o.OpId, batchId, r, target, out intentWhy)
            : DeleteLog.WriteIntent(logPath, o.OpId, batchId, r, target, out intentWhy);
        if (!intentOk)
            return NoDispatch(r, DeleteRefusalKind.LogUnwritable,
                "审计日志写入 intent 失败，已拒绝派发操作（" + intentWhy + "）。未执行任何操作。");

        // ---- 12. 派发 ----
        o.Dispatch = DispatchState.Dispatched;
        if (bin is PermanentDeleteBin)
        {
            // 只删文件；目录在前置中已被拒。同一句柄核对身份后删除。
            // 最终核对全部在独占删除句柄上完成：身份、大小、修改时间，以及按同一规则重新校验内容。
            string rule = fresh.RuleId;
            string refused = existsDir ? "目录不做永久删除" : PermanentDeleteBin.DeleteVerified(target, nowId,
                r.BytesAtScan, r.LastWriteUtcAtScan, st => ContentVerifier.VerifyOpenStream(rule, target, st));
            bool gone = !File.Exists(target) && !Directory.Exists(target);
            if (refused == null && gone) { o.Status = DeleteStatus.DeletedVerified; o.Detail = "已永久删除（不可恢复）；删除前已在同一句柄上核对身份、大小、时间与内容"; }
            else if (refused != null && !gone)
            {
                FileIdentity after = FileIdentityProbe.Capture(target);
                bool same = after.Ok && after.SameAs(nowId);
                o.Status = same ? DeleteStatus.FailedStillPresent : DeleteStatus.OutcomeUnknown;
                o.Detail = refused + (same ? "；原文件仍在、未改变" : "；原位置对象身份已变化，请人工核实");
            }
            else { o.Status = DeleteStatus.OutcomeUnknown; o.Detail = "删除结果无法核对（报告=" + (refused ?? "成功") + "，原路径仍在=" + !gone + "），已停止"; }
            return o;
        }
        RecycleEvidence rev = null;
        string dispatchError = "";
        try
        {
            rev = bin.SendFile(target);
        }
        catch (Exception ex)
        {
            dispatchError = ex.GetType().Name + "：" + ex.Message;
        }

        // ---- 13. 分类：只看实测事实 + 源是否仍在 + 身份复验 ----
        // 铁律：
        //   * “HRESULT 成功”不是回收证据；
        //   * “原路径消失”不是回收证据；
        //   * 结果不明 ⇒ 不报成功，且停止后续（o.NeedsUrgentReview 为 true）。
        bool stillThere = File.Exists(target) || Directory.Exists(target);
        bool identitySame = false;
        if (stillThere)
        {
            FileIdentity after = FileIdentityProbe.Capture(target);
            identitySame = after.Ok && nowId.Ok && after.SameAs(nowId);
        }

        o.Status = WindowsRecycleBin.Classify(rev, stillThere, identitySame);
        o.Detail = WindowsRecycleBin.Describe(rev, stillThere, identitySame);
        if (dispatchError.Length > 0)
            o.Detail = "派发时抛出异常（" + dispatchError + "）。" + o.Detail;
        return o;
    }

    /// <summary>构造“未派发就被拒绝”的结果（所有前置拒绝路径都走这里，保证 WasDispatched=false）。</summary>
    private static DeleteOutcome NoDispatch(DeleteRequest r, DeleteRefusalKind kind, string detail)
    {
        DeleteOutcome o = new DeleteOutcome();
        o.Path = r == null ? "" : r.Path;
        o.OpId = DeleteLog.NewOpId();
        o.Status = DeleteStatus.RefusedNotDispatched;
        o.Kind = kind;
        o.Dispatch = DispatchState.NotDispatched;
        o.Detail = detail;
        return o;
    }

    /// <summary>把一批结果写进审计日志（每次只写一项，调用点明确）。</summary>
    private static void LogAll(string logPath, string batchId, IEnumerable<DeleteOutcome> items)
    {
        foreach (DeleteOutcome o in items)
        {
            string why;
            DeleteLog.WriteOutcome(logPath, o.OpId, batchId, o, out why);
        }
    }

    /// <summary>
    /// 把日志里“有 intent 无 outcome”的遗留项转成待核实结果（崩溃恢复用）。
    /// 只报事实：不推断文件还在、不推断已被删除、**绝不重试**。
    /// </summary>
    public static List<DeleteOutcome> Reconcile(string logPath)
    {
        List<DeleteOutcome> list = new List<DeleteOutcome>();
        foreach (KeyValuePair<string, string> kv in DeleteLog.PendingOps(logPath))
        {
            DeleteOutcome o = new DeleteOutcome();
            o.OpId = kv.Key;
            o.Path = kv.Value;
            o.Status = DeleteStatus.PendingReconciliation;
            // 关键：**不确定**，不是“派发过”。intent 在派发之前写，
            // 所以进程可能死在“写 intent”与“真正动手”之间。
            o.Dispatch = DispatchState.Unknown;
            o.Detail = "上次运行留下了未完成记录（有 intent 无 outcome）：**无法确定该操作是否真的派发过**，"
                     + "也无法确定目标是否已被回收站收走 —— 请人工核实。本程序不会自动重试。";
            list.Add(o);
        }
        return list;
    }


    private static ScanItem BuildLiveItem(DeleteRequest r, string target, bool existsDir, bool existsFile)
    {
        ScanItem live = new ScanItem();
        live.Path = target;
        live.Name = Path.GetFileName(target);
        live.IsDirectory = existsDir;
        live.IsReparse = false;               // 已在第 4 步单独确认
        if (existsDir)
        {
            bool complete;
            live.Bytes = DirScan.SizeBounded(target, out complete);
            live.SizeComplete = complete;
            live.HasChildren = !DirScan.IsEmptyDirectory(target);
        }
        else if (existsFile)
        {
            try
            {
                FileInfo fi = new FileInfo(target);
                live.Bytes = fi.Length;
                live.LastWriteUtc = fi.LastWriteTimeUtc;
                live.Days = (int)(DateTime.Now - fi.LastWriteTime).TotalDays;
                if (live.Days < 0) live.Days = 0;
            }
            catch { live.SizeComplete = false; }
        }
        return live;
    }

    /// <summary>辅助身份校验（强身份之外再比一层）。用 target 而不是 r.Path，避免两条路径不一致。</summary>
    private static string WeakIdentityChanged(DeleteRequest r, string target, bool existsDir, bool existsFile)
    {
        try
        {
            if (existsDir)
            {
                DirectoryInfo di = new DirectoryInfo(target);
                if (Math.Abs((di.LastWriteTimeUtc - r.LastWriteUtcAtScan).TotalSeconds) > 2) return "目录修改时间";
                return "";
            }
            if (!existsFile) return "";
            FileInfo fi = new FileInfo(target);
            if (fi.Length != r.BytesAtScan) return "文件大小";
            if (Math.Abs((fi.LastWriteTimeUtc - r.LastWriteUtcAtScan).TotalSeconds) > 2) return "修改时间";
            bool ro = (fi.Attributes & FileAttributes.ReadOnly) != 0;
            if (ro != r.WasReadOnly) return "只读属性";
            return "";
        }
        catch { return "无法读取目标身份"; }
    }

    /// <summary>
    /// 安全移除缓存清理后遗留的空壳子目录（100% Fail-Safe）：
    ///   * 仅处理某个 stopRoot 严格内部（真子目录层级）的已删文件祖先目录，绝不触碰 stopRoot 本身；
    ///   * 绝不删除磁盘根目录、%TEMP%、%LOCALAPPDATA%\Temp、%WINDIR%\Temp、%WINDIR%\SoftwareDistribution\Download 等根；
    ///   * 跳过重解析点与含重解析点祖先的路径；
    ///   * 仅调用非递归 Directory.Delete(dir, false)，只要目录中仍存任意 1 个文件或被进程占用即由 OS 原子拒绝。
    /// </summary>
    public static int PruneEmptyParentDirs(IEnumerable<string> deletedFilePaths, string[] stopRoots)
    {
        if (deletedFilePaths == null || stopRoots == null || stopRoots.Length == 0)
            return 0;

        List<string> cleanStopRoots = new List<string>();
        HashSet<string> seenStopRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < stopRoots.Length; i++)
        {
            string norm = NormalizeRootForScope(stopRoots[i]);
            if (norm.Length == 0) continue;
            if (seenStopRoots.Add(norm))
            {
                cleanStopRoots.Add(norm);
            }
        }
        if (cleanStopRoots.Count == 0)
            return 0;

        HashSet<string> neverPruneDirs = BuildNeverPruneDirSet(cleanStopRoots);
        HashSet<string> candidateSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string rawFile in deletedFilePaths)
        {
            if (String.IsNullOrEmpty(rawFile)) continue;
            string canonFile = NormalizeRootForScope(rawFile);
            if (canonFile.Length == 0 || IsDriveRoot(canonFile)) continue;

            string matchedRoot = FindMatchingScanRoot(cleanStopRoots, canonFile, true);
            if (matchedRoot.Length == 0) continue;

            string curDir = SafeGetParentDir(canonFile);
            while (curDir.Length > 0)
            {
                if (IsDriveRoot(curDir)) break;
                if (neverPruneDirs.Contains(curDir)) break;
                if (String.Equals(curDir, matchedRoot, StringComparison.OrdinalIgnoreCase)) break;
                if (!PathGuard.IsInside(matchedRoot, curDir)) break;
                candidateSet.Add(curDir);
                curDir = SafeGetParentDir(curDir);
            }
        }

        if (candidateSet.Count == 0)
            return 0;

        List<string> candidates = new List<string>(candidateSet);
        candidates.Sort(delegate(string a, string b)
        {
            int cmp = b.Length.CompareTo(a.Length);
            if (cmp != 0) return cmp;
            return String.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        });

        int pruned = 0;
        for (int i = 0; i < candidates.Count; i++)
        {
            string dir = candidates[i];
            if (IsDriveRoot(dir) || neverPruneDirs.Contains(dir)) continue;

            string stopRoot = FindMatchingScanRoot(cleanStopRoots, dir, true);
            if (stopRoot.Length == 0) continue;
            if (!Directory.Exists(dir)) continue;
            if (PathGuard.IsReparsePoint(dir)) continue;
            if (PathGuard.HasReparseAncestor(stopRoot, dir)) continue;

            try
            {
                Directory.Delete(dir, false);
                pruned++;
            }
            catch
            {
                // 目录非空、含受保护/隐藏文件或被占用时，系统原子拒绝删除，静默保留。
            }
        }
        return pruned;
    }

    private static HashSet<string> BuildNeverPruneDirSet(IList<string> stopRoots)
    {
        HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (stopRoots != null)
        {
            for (int i = 0; i < stopRoots.Count; i++)
            {
                AddProtectedDir(set, stopRoots[i]);
            }
        }

        try { AddProtectedDir(set, Path.GetTempPath()); } catch { }
        try
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            AddProtectedDir(set, localAppData);
            if (!String.IsNullOrEmpty(localAppData))
            {
                AddProtectedDir(set, Path.Combine(localAppData, "Temp"));
            }
        }
        catch { }

        try
        {
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            AddProtectedDir(set, winDir);
            if (!String.IsNullOrEmpty(winDir))
            {
                AddProtectedDir(set, Path.Combine(winDir, "Temp"));
                AddProtectedDir(set, Path.Combine(winDir, "SoftwareDistribution"));
                AddProtectedDir(set, Path.Combine(winDir, "SoftwareDistribution", "Download"));
            }
        }
        catch { }

        try { AddProtectedDir(set, Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)); } catch { }
        try { AddProtectedDir(set, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)); } catch { }
        try { AddProtectedDir(set, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)); } catch { }
        try { AddProtectedDir(set, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)); } catch { }
        try { AddProtectedDir(set, Environment.GetFolderPath(Environment.SpecialFolder.Desktop)); } catch { }
        try { AddProtectedDir(set, AppDataPaths.Root); } catch { }
        return set;
    }

    private static void AddProtectedDir(HashSet<string> set, string rawDir)
    {
        string norm = NormalizeRootForScope(rawDir);
        if (norm.Length > 0) set.Add(norm);
    }

    private static bool IsDriveRoot(string normPath)
    {
        if (String.IsNullOrEmpty(normPath)) return true;
        if (normPath.Length <= 3 && normPath.Length >= 2 && normPath[1] == ':') return true;
        try
        {
            string root = Path.GetPathRoot(normPath);
            if (String.IsNullOrEmpty(root)) return true;
            return String.Equals(normPath.TrimEnd('\\', '/') + "\\", root, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return true;
        }
    }

    private static string SafeGetParentDir(string normPath)
    {
        if (String.IsNullOrEmpty(normPath) || IsDriveRoot(normPath)) return "";
        try
        {
            string parent = Path.GetDirectoryName(normPath);
            return NormalizeRootForScope(parent);
        }
        catch
        {
            return "";
        }
    }

    /// <summary>最小操作记录：时间 / 结果 / 路径 / 原因。不记录任何文件内容。</summary>
    public static string DefaultLogPath()
    {
        return AppDataPaths.DeleteLog;
    }

    private static void Log(string logPath, DeleteOutcome o)
    {
        // 写盘统一走 DeleteLog（产品代码中唯一允许写盘点）。
        string why;
        DeleteLog.WriteOutcome(logPath, o.OpId, "", o, out why);
    }
}
