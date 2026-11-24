using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

// =====================================================================
// v0.4.0 只读扫描引擎（第一批：核心数据结构 / 预算 / 取消 / 状态模型）
//
// 硬约束（已批准的设计修正，不得被后续实现悄悄放宽）：
//
//  1) 「已发现项处理完了」≠「目录枚举完成了」。两条轴分开记录：
//       EnumerationOutcome     —— 文件系统枚举是否真正结束
//       Discovered/Analyzed/Failed/NotAnalyzed —— 已发现项的状态分布
//     并由 RemainderUnevaluated 显式回答「尚未枚举部分是否存在」。
//     **未知的剩余数量一律为未知，不得猜测、不得用一个总数糊过去。**
//     因此本文件不提供任何叫 Complete 的单一布尔值 —— 调用方必须自己说明用的是哪条轴。
//
//  2) 只读：不创建 / 修改 / 移动 / 重命名 / 删除任何被扫描对象，
//     也不向被扫描目录写任何文件（包括诊断日志）。本文件无任何写盘调用。
//
//  3) 只做「继续显示」（把已就绪批次交给消费方），**不实现「继续分析」**。
//     达到预算后不支持续扫；要看完剩余部分必须以更高预算重新扫描，
//     那是一次新扫描的完整结果，不是与本轮拼接。详见 docs/v0.4.0-read-only-plan.md。
//
//  4) 统一资源预算：顶层枚举条目、已分析条目、文件 stat 次数、目录访问次数、
//     内容哈希总读取字节、总耗时、待发送批次数与行数（内存上限）。
//
//  5) 取消是协作式的，检查点覆盖：顶层枚举、目录遍历、哈希分块、批次入队等待。
//     对无法立即中断的系统 I/O **不承诺固定取消时间** —— 必须用 HasExited /
//     WaitForExit 判断线程是否真的退出，未退出时只能如实报告「正在停止」。
// =====================================================================

/// <summary>单个已发现项的状态。Discovered 仅存在于生产者线程内部，不作为交付行。</summary>
public enum EntryState { Discovered, Analyzed, Failed, NotAnalyzed }

/// <summary>文件系统枚举的结局。NotStarted/InProgress 都表示「尚未枚举完成」。</summary>
public enum EnumerationOutcome { NotStarted, InProgress, Completed, TruncatedByBudget, Cancelled, Failed }

/// <summary>
/// 剩余部分的状态。**三者必须严格区分，不得用一个 bool 兼表达**：
///   None    —— 已确认枚举完成，没有剩余
///   Exists  —— 已确认**还有**未枚举项（只用一次额外的 MoveNext 探测确认“至少多一个”）
///   Unknown —— 提前停止，剩余情况**未知**（取消 / 超时 / 枚举异常时不会去探测）
/// "Unknown" 绝不能当成 "Exists" 使用，也绝不能写成"共 N 项"。
/// </summary>
public enum RemainderState { Unknown = 0, None, Exists }

/// <summary>扫描停止原因。必须能回答「为什么停」，且必须与「剩余数量未知」配套表达。</summary>
public enum ScanStopReason
{
    None = 0,
    Completed,
    TopLevelBudget,
    AnalysisBudget,
    TimeBudget,
    Cancelled,
    EnumerationFailed,
    /// <summary>暂停等待续扫超时：游标已释放。**不是**枚举完成，也不是用户取消。</summary>
    ParkTimeout,
    FatalError
}

/// <summary>扫描资源预算。所有字段都是上限，触顶一律停止或降级，绝不放宽安全判定。</summary>
public sealed class ScanBudget
{
    // 按平使用逐文件树分析；旧表格界面的顶层目录合同保持默认不变。
    public bool Recursive;
    /// <summary>
    /// **单轮**顶层枚举条目上限。每次「继续分析」重新获得这一份额度。
    /// 全会话累计上限由 <see cref="MaxSessionRows"/> 约束（触顶后不可再续）。
    /// </summary>
    public int MaxTopLevelEntries = 20000;
    /// <summary>**单轮**已分析条目上限。每轮重新获得。</summary>
    public int MaxAnalyzedEntries = 20000;
    /// <summary>
    /// **全会话累计**结果行数上限（跨轮累加，绝不重置）。
    /// 触顶即硬停：不再探测剩余、不再提供「继续分析」。
    /// 这是防“反复继续分析把累计资源吃掉”的最终闸门。
    /// </summary>
    public int MaxSessionRows = 200000;
    /// <summary>
    /// 暂停（达到单轮预算、等待用户继续）时保留枚举游标的最长时间。
    /// 超时自动释放：不允许无限期占用一个 find 句柄 + 一个线程。
    /// </summary>
    public TimeSpan MaxParkedDuration = TimeSpan.FromSeconds(60);
    /// <summary>内容校验的总读取字节上限（触顶只降级证据，不停止扫描）。</summary>
    public long MaxHashBytes = 256L * 1024 * 1024;
    /// <summary>总耗时上限（**单轮**）。每轮一块新的计时钟。</summary>
    public TimeSpan MaxDuration = TimeSpan.FromSeconds(20);
    /// <summary>文件 stat 次数上限（全局，跨所有目录累减）。</summary>
    public long MaxFileStats = 200000;
    /// <summary>目录访问次数上限（全局，跨所有目录累减）。</summary>
    public long MaxDirVisits = 200000;
    /// <summary>待发送批次数上限（背压：达到则生产者阻塞）。</summary>
    public int MaxPendingBatches = 8;
    /// <summary>待发送行数上限（背压：内存上限）。</summary>
    public int MaxPendingRows = 4096;
    /// <summary>单个目录体积统计的文件上限（会按全局剩余量收缩）。</summary>
    public int DirSizeMaxFiles = 5000;
    /// <summary>单个目录体积统计的目录上限（会按全局剩余量收缩）。</summary>
    public int DirSizeMaxDirs = 20000;
    /// <summary>一批交付多少行。</summary>
    public int BatchSize = 64;
}

/// <summary>扫描进度快照（不可变；每次发布都是新对象，读方不会看到半更新状态）。</summary>
public sealed class ScanProgress
{
    public EnumerationOutcome Enumeration = EnumerationOutcome.NotStarted;
    public ScanStopReason Stop = ScanStopReason.None;

    public int Discovered;
    public int Analyzed;
    public int Failed;
    public int NotAnalyzed;

    public long BytesAnalyzed;
    public long HashBytesUsed;
    public long FileStats;
    public long DirVisits;

    public int BatchesProduced;
    public int RowsProduced;
    /// <summary>已经被消费方取走的行数。</summary>
    public int RowsDelivered;
    /// <summary>生产出来但因为消费方退出而丢弃的行数（不变量：RowsProduced == RowsDelivered + RowsDropped）。</summary>
    public int RowsDropped;
    public int BatchesPending;
    public int RowsPending;
    public int BatchesDropped;

    /// <summary>剩余部分的状态。Unknown ≠ Exists，不得混用。</summary>
    public RemainderState Remainder = RemainderState.Unknown;

    // ---- v0.5.0 第三批：同会话续扫 ----

    /// <summary>
    /// 生产者是否**当前正处于**「已达单轮预算、已暂停、可继续」状态。
    /// 只有它为 true 时界面才允许显示「继续分析」。
    /// </summary>
    public bool Resumable;
    /// <summary>已完成的轮次（1 = 只跑过首轮；≥2 表示已经续扫过）。</summary>
    public int Rounds = 1;
    /// <summary>
    /// 不可续的**真实原因**（空 = 本来就不该续，例如枚举已穷尽）。
    /// 用于如实解释「为什么没有继续分析入口」。
    /// </summary>
    public string ResumeBlocked = "";
    /// <summary>累计结果行数上限（用于文案与对账）。</summary>
    public long SessionRowsLimit;

    // ---- v0.5.0 第四批：累计预算用尽的可见性 ----
    /// <summary>文件属性读取的**全会话**上限（0 = 无限）。</summary>
    public long FileStatsLimit;
    /// <summary>目录访问的**全会话**上限（0 = 无限）。</summary>
    public long DirVisitsLimit;
    /// <summary>内容校验字节的**全会话**上限（0 = 无限）。</summary>
    public long HashBytesLimit;
    /// <summary>暂停保留枚举游标的秒数（用于告知“继续分析”的有效期）。</summary>
    public int ParkSeconds;
    /// <summary>
    /// 内容校验字节预算已用尽（剩余不足最小一次校验）—— 此时部分项无法再完整校验。
    /// 不能用“已用 ≥ 上限”代替：余额可能卡在 0 与需求量之间。
    /// </summary>
    public bool HashBudgetExhausted;
    public int FilesDiscovered, DirectoryEntries;
    public string CurrentPath = "";
    public ScanStopReason SliceStop;
    public ScanCoverage Coverage;

    /// <summary>内容证据未完成的行数（预算不足 / 取消 / 读取失败 / 校验期间变化）。</summary>
    public int ContentUnverified;

    /// <summary>文件系统枚举是否真正结束。</summary>
    public bool EnumerationCompleted { get { return Enumeration == EnumerationOutcome.Completed; } }

    /// <summary>是否允许展示精确总数。只有枚举真正结束、且已发现项都已处理才允许。</summary>
    public bool HasKnownTotal { get { return EnumerationCompleted && NotAnalyzed == 0; } }

    /// <summary>剩余是否**有可能**存在（包含“已确认存在”与“未知”）。用于措辞，不得用于断言存在。</summary>
    public bool RemainderPossible { get { return Remainder != RemainderState.None; } }

    /// <summary>所有已发现项都已处理（成功或失败）。</summary>
    public bool AllDiscoveredProcessed { get { return NotAnalyzed == 0; } }

    /// <summary>「已发现项处理完了」**且**「枚举结束了」才算穷尽。</summary>
    public bool IsScanExhaustive
    {
        get
        {
            return EnumerationCompleted && AllDiscoveredProcessed &&
                   (Stop == ScanStopReason.Completed || Stop == ScanStopReason.None);
        }
    }

    public bool EvidenceComplete { get { return ContentUnverified == 0; } }
    public bool HadAnalysisFailures { get { return Failed > 0; } }
}

/// <summary>一批交付给消费方的行。所有权在入队时转交给消费方。</summary>
public sealed class ScanBatch
{
    public int Index;
    public readonly List<ListRow> Rows = new List<ListRow>();
}

/// <summary>顶层条目的只读快照。</summary>
public sealed class FsEntry
{
    public string FullName = "";
    public string Name = "";
    public bool IsDirectory;
    public long Length;
    public DateTime LastWriteUtc;
    public FileAttributes Attributes;
    public string MetadataError = "";

    public bool IsReparse { get { return (Attributes & FileAttributes.ReparsePoint) != 0; } }
}

/// <summary>
/// 顶层枚举的注入点。真实实现走文件系统；测试可注入确定性假实现，
/// 从而在不触碰磁盘、不造大文件的前提下测试预算 / 取消 / 状态模型。
/// 迭代过程中允许抛 IOException / UnauthorizedAccessException；引擎负责捕获并记为失败。
/// </summary>
public interface IFileEnumerator
{
    IEnumerable<FsEntry> Enumerate(string directory);
}

/// <summary>真实枚举：流式，不分配整块数组。</summary>
public sealed class ScanCoverage
{
    public string Root = "", CurrentDirectory = "";
    public int DirectoriesStarted, DirectoriesCompleted, UnreadableDirectories, ReparseSkipped, MetadataFailures, PendingDirectories;
    public bool Closed;
    public string[] PriorityPaths = new string[0];
    public string[] PendingPaths = new string[0], SkippedPaths = new string[0];
}

// 广度优先流式遍历；不跟链接。保留队列/当前目录，暂停不会重新开始或丢失条目。
public sealed class RecursiveFileEnumerator : IFileEnumerator
{
    private const int MaxPendingDirectoriesCap = 200000;

    private sealed class FileIdentityComparer : IEqualityComparer<FileIdentity>
    {
        public bool Equals(FileIdentity x, FileIdentity y)
        {
            return x.SameAs(y);
        }

        public int GetHashCode(FileIdentity obj)
        {
            unchecked
            {
                int h = (int)obj.VolumeSerial;
                h = (h * 397) ^ (int)obj.IndexHigh;
                h = (h * 397) ^ (int)obj.IndexLow;
                return h;
            }
        }
    }

    readonly object gate = new object();
    readonly Queue<string> pending = new Queue<string>();
    readonly List<string> skipped = new List<string>();
    readonly List<string> priorities = new List<string>();
    readonly HashSet<string> scheduled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<FileIdentity> visitedIds = new HashSet<FileIdentity>(new FileIdentityComparer());
    string root = "", active = "";
    int started, completed, denied, links, metadata;
    bool closed;
    void Skip(string path, string reason, bool directory)
    {
        lock (gate) { if (directory) denied++; else metadata++; if (skipped.Count < 64) skipped.Add(path + " · " + reason); }
    }
    public ScanCoverage Snapshot()
    {
        lock (gate)
        {
            List<string> paths = new List<string>();
            if (active.Length > 0) paths.Add(active);
            foreach (string p in pending) { if (paths.Count >= 64) break; paths.Add(p); }
            return new ScanCoverage { Root = root, CurrentDirectory = active, DirectoriesStarted = started, DirectoriesCompleted = completed,
                UnreadableDirectories = denied, ReparseSkipped = links, MetadataFailures = metadata, Closed = closed,
                PendingDirectories = pending.Count + (active.Length > 0 ? 1 : 0), PriorityPaths = priorities.ToArray(), PendingPaths = paths.ToArray(), SkippedPaths = skipped.ToArray() };
        }
    }
    public IEnumerable<FsEntry> Enumerate(string directory)
    {
        return EnumerateMany(new string[] { directory });
    }

    public IEnumerable<FsEntry> EnumerateMany(IList<string> directories)
    {
        List<string> targetRoots = new List<string>();
        HashSet<string> rootSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (directories != null)
        {
            for (int i = 0; i < directories.Count; i++)
            {
                string d = PathGuard.Canonical(directories[i]);
                if (d.Length > 0 && PathGuard.IsLocalDrivePath(d) && rootSet.Add(d)) targetRoots.Add(d);
            }
        }
        bool singleRoot = (targetRoots.Count == 1);
        string singleRootPath = singleRoot ? targetRoots[0] : "";
        lock (gate)
        {
            root = targetRoots.Count == 0
                ? ""
                : (singleRoot ? targetRoots[0] : (targetRoots[0] + " 等 " + targetRoots.Count + " 个位置"));
        }

        // 先覆盖已有规则的缓存根，避免深层缓存排在海量目录之后；全链路拒绝重解析点。
        string[] knownCacheDirs = CacheRoots.ScanDirectories();
        for (int rIdx = 0; rIdx < targetRoots.Count; rIdx++)
        {
            string directory = targetRoots[rIdx];
            foreach (string candidate in knownCacheDirs)
            {
                string canonCandidate = PathGuard.Canonical(candidate);
                if (canonCandidate.Length == 0 || !PathGuard.IsLocalDrivePath(canonCandidate)) continue;
                if (!PathGuard.IsInside(directory, canonCandidate)) continue;
                if (!Directory.Exists(canonCandidate)) continue;
                if (PathGuard.HasAnyReparseComponent(canonCandidate)) continue;
                lock (gate)
                {
                    if (pending.Count < MaxPendingDirectoriesCap && scheduled.Add(canonCandidate))
                    {
                        pending.Enqueue(canonCandidate);
                        priorities.Add(canonCandidate);
                    }
                }
            }
            lock (gate)
            {
                if (pending.Count < MaxPendingDirectoriesCap && scheduled.Add(directory))
                    pending.Enqueue(directory);
            }
        }

        int failedRoots = 0;
        try
        {
            while (true)
            {
                string dir;
                lock (gate) { if (pending.Count == 0) break; dir = pending.Dequeue(); active = dir; started++; }
                bool isTopRoot = rootSet.Contains(dir);

                bool dirExists = false;
                bool dirDirectReparse = false;
                try
                {
                    FileAttributes da = File.GetAttributes(dir);
                    dirExists = true;
                    if ((da & FileAttributes.ReparsePoint) != 0) dirDirectReparse = true;
                }
                catch (FileNotFoundException) { dirExists = false; }
                catch (DirectoryNotFoundException) { dirExists = false; }
                catch { dirExists = true; }

                if (dirDirectReparse || (dirExists && (PathGuard.IsReparsePoint(dir) || PathGuard.HasAnyReparseComponent(dir))))
                {
                    lock (gate)
                    {
                        links++;
                        if (skipped.Count < 64) skipped.Add(dir + " · 重解析点不跟随，其内部内容未覆盖");
                        active = "";
                    }
                    continue;
                }

                if (dirExists)
                {
                    FileIdentity dirId = FileIdentityProbe.Capture(dir);
                    if (dirId.Ok)
                    {
                        bool alreadyVisited;
                        lock (gate) { alreadyVisited = !visitedIds.Add(dirId); }
                        if (alreadyVisited)
                        {
                            lock (gate) { active = ""; }
                            continue;
                        }
                    }
                }

                IEnumerator<FileSystemInfo> entries = null;
                bool complete = false;
                try { entries = new DirectoryInfo(dir).EnumerateFileSystemInfos().GetEnumerator(); }
                catch (Exception ex)
                {
                    Skip(dir, ex.Message, true);
                    if (singleRoot && String.Equals(dir, singleRootPath, StringComparison.OrdinalIgnoreCase)) throw;
                    if (isTopRoot)
                    {
                        failedRoots++;
                        if (failedRoots >= targetRoots.Count && completed == 0 && pending.Count == 0) throw;
                    }
                }
                if (entries != null)
                {
                    try
                    {
                        while (true)
                        {
                            bool moved = false;
                            try { moved = entries.MoveNext(); }
                            catch (Exception ex)
                            {
                                Skip(dir, ex.Message, true);
                                if (singleRoot && String.Equals(dir, singleRootPath, StringComparison.OrdinalIgnoreCase)) throw;
                                break;
                            }
                            if (!moved) { complete = true; break; }
                            FileSystemInfo f = entries.Current;
                            FsEntry e = new FsEntry { FullName = f.FullName, Name = f.Name, IsDirectory = f is DirectoryInfo };
                            try
                            {
                                e.Attributes = f.Attributes;
                                e.IsDirectory = (e.Attributes & FileAttributes.Directory) != 0;
                                e.LastWriteUtc = f.LastWriteTimeUtc;
                                if (!e.IsDirectory && !e.IsReparse) e.Length = ((FileInfo)f).Length;
                            }
                            catch (Exception ex) { e.MetadataError = "属性读取失败：" + ex.Message; Skip(e.FullName, e.MetadataError, false); }
                            if (e.IsReparse)
                            {
                                lock (gate) { links++; if (skipped.Count < 64) skipped.Add(e.FullName + " · 重解析点不跟随，其内部内容未覆盖"); }
                            }
                            else if (e.IsDirectory && e.MetadataError.Length == 0)
                            {
                                lock (gate)
                                {
                                    if (pending.Count < MaxPendingDirectoriesCap)
                                    {
                                        if (scheduled.Add(e.FullName)) pending.Enqueue(e.FullName);
                                    }
                                    else
                                    {
                                        denied++;
                                        if (skipped.Count < 64) skipped.Add(e.FullName + " · 待扫描目录队列达到上限，已跳过");
                                    }
                                }
                            }
                            yield return e;
                        }
                    }
                    finally { entries.Dispose(); }
                }
                lock (gate) { if (complete) completed++; active = ""; }
            }
        }
        finally { lock (gate) closed = true; }
    }
}

public sealed class RealFileEnumerator : IFileEnumerator
{
    public IEnumerable<FsEntry> Enumerate(string directory)
    {
        string canon = PathGuard.Canonical(directory);
        if (canon.Length == 0 || !PathGuard.IsLocalDrivePath(canon))
            throw new IOException("扫描根目录路径无效");
        if (PathGuard.IsReparsePoint(canon) || PathGuard.HasAnyReparseComponent(canon))
            throw new IOException("扫描根目录或其上级包含符号链接或重解析点");

        DirectoryInfo di = new DirectoryInfo(canon);
        // EnumerateFileSystemInfos 返回的实例已带上 FindFirstFile/FindNextFile 的快照
        // （属性 / 长度 / 时间），因此取这些字段不会再产生额外系统调用。
        foreach (FileSystemInfo fsi in di.EnumerateFileSystemInfos())
        {
            FsEntry e = new FsEntry();
            e.FullName = fsi.FullName;
            e.Name = fsi.Name;
            e.IsDirectory = fsi is DirectoryInfo;
            try
            {
                e.Attributes = fsi.Attributes;
                e.IsDirectory = (e.Attributes & FileAttributes.Directory) != 0;
                e.LastWriteUtc = fsi.LastWriteTimeUtc;
                if (!e.IsDirectory && !e.IsReparse)
                {
                    FileInfo fi = fsi as FileInfo;
                    if (fi != null) e.Length = fi.Length;
                }
            }
            catch (Exception ex)
            {
                e.MetadataError = "属性读取失败：" + ex.Message;
            }
            yield return e;
        }
    }
}

/// <summary>分析一项时可用的共享资源状态。只在生产者线程上读写。</summary>
public sealed class AnalysisBudgetState
{
    public readonly ScanBudget Budget;
    public readonly HashBudget Hash;

    public long FileStats;
    public long DirVisits;

    /// <summary>由引擎注入的取消查询。</summary>
    public Func<bool> Cancelled;

    public AnalysisBudgetState(ScanBudget budget)
    {
        Budget = budget;
        Hash = new HashBudget(budget.MaxHashBytes);
    }

    public bool IsCancelled() { return Cancelled != null && Cancelled(); }
    public long FileStatsRemaining { get { long r = Budget.MaxFileStats - FileStats; return r < 0 ? 0 : r; } }
    public long DirVisitsRemaining { get { long r = Budget.MaxDirVisits - DirVisits; return r < 0 ? 0 : r; } }
}

/// <summary>单项分析结果。</summary>
public sealed class AnalysisResult
{
    public EntryState State = EntryState.Analyzed;
    /// <summary>分析成功时的行；失败 / 未分析时为 null，由引擎补占位行（不静默丢弃）。</summary>
    public ListRow Row;
    public string Reason = "";
    /// <summary>该行的内容证据未完成（预算不足 / 取消 / 读取失败 / 校验期间变化）。</summary>
    public bool ContentUnverified;

    public static AnalysisResult Of(ListRow row)
    {
        AnalysisResult r = new AnalysisResult();
        r.State = EntryState.Analyzed;
        r.Row = row;
        return r;
    }

    public static AnalysisResult Fail(string reason)
    {
        AnalysisResult r = new AnalysisResult();
        r.State = EntryState.Failed;
        r.Reason = reason;
        return r;
    }

    public static AnalysisResult NotAnalyzed(string reason)
    {
        AnalysisResult r = new AnalysisResult();
        r.State = EntryState.NotAnalyzed;
        r.Reason = reason;
        return r;
    }
}

/// <summary>
/// 单项分析的注入点。契约：
///   * 不得抛出（引擎也会兜住异常并记为 Failed）；
///   * 不得写盘、不得改动被分析对象；
///   * 取消时应尽快返回，并把结果标为 Analyzed(ContentUnverified) 或 NotAnalyzed，
///     不得把未完成的内容校验写成“已通过”。
/// </summary>
public interface IEntryAnalyzer
{
    AnalysisResult Analyze(FsEntry entry, string scanRoot, AnalysisBudgetState res);
}

/// <summary>
/// 真实分析器：与 v0.3.2 的扫描逐项分析口径一致
/// （占用探测 → 安全策略与内容证据 → 强身份），另加预算与取消透传。
/// </summary>
public sealed class RealEntryAnalyzer : IEntryAnalyzer
{
    public AnalysisResult Analyze(FsEntry e, string scanRoot, AnalysisBudgetState res)
    {
        if (res.IsCancelled()) return AnalysisResult.NotAnalyzed("扫描已取消，本项目未分析");
        if (!string.IsNullOrEmpty(e.MetadataError)) return AnalysisResult.Fail(e.MetadataError);

        ScanItem item = new ScanItem();
        item.Path = e.FullName;
        item.Name = e.Name;
        item.IsDirectory = e.IsDirectory;
        item.LastWriteUtc = e.LastWriteUtc;
        item.IsReparse = e.IsReparse;

        SizeScanResult size = null;
        if (!e.IsDirectory)
        {
            item.Bytes = e.Length;
        }
        else if (res.Budget.Recursive)
        {
            // 目录是遍历容器，不把它的汇总大小再计入文件容量；目录授权合同不变。
            item.Bytes = 0;
            item.SizeComplete = false;
            item.HasChildren = true;
        }
        else
        {
            // 全局预算：每目录上限取 min(全局剩余, 单目录上限)，避免“每个目录各自有上限”的叠加放大
            SizeLimits lim = new SizeLimits(
                (int)Math.Min(res.FileStatsRemaining, res.Budget.DirSizeMaxFiles),
                (int)Math.Min(res.DirVisitsRemaining, res.Budget.DirSizeMaxDirs));
            item.Bytes = DirScan.SizeBounded(e.FullName, out size, lim, res.Cancelled);
            res.FileStats += size.FileStats;
            res.DirVisits += size.DirVisits;
            item.SizeComplete = size.Complete;
            item.HasChildren = size.HasChildren;
        }

        DateTime now = DateTime.UtcNow;
        int days = (int)(now - e.LastWriteUtc).TotalDays;
        if (days < 0) days = 0;
        item.Days = days;

        // 热路径单次评估与单句柄合并优化：
        // 1) 规则层只评估一次并透传给 SafetyPolicy.Decide，消除重复正则与缓存根匹配；
        // 2) 仅对初判 RiskSafe 的候选文件打开一次句柄同时完成占用探测 + 强身份捕获 + 前 64 字节预读；
        // 3) 若被运行中进程占用（Occupied）或未获授权（!PolicyEligible），不再额外调用 FileIdentityProbe.Capture。
        Evidence pre = null;
        bool candidateSafe = false;
        FileIdentity prefetchedId = default(FileIdentity);
        byte[] prefetchedHead = null;
        long prefetchedLen = 0;

        if (!e.IsDirectory && !e.IsReparse)
        {
            pre = EvidenceRules.Evaluate(item.Name, item.Path, item.Days);
            candidateSafe = (pre.Risk == EvidenceRules.RiskSafe);
        }

        LockState ls;
        if (e.IsDirectory)
        {
            ls = LockState.Free;
        }
        else if (e.IsReparse && res.Budget.Recursive)
        {
            ls = LockState.Unknown;
        }
        else if (candidateSafe)
        {
            ls = FileIdentityProbe.ProbeLockAndPrefetch(e.FullName, e.Attributes,
                out prefetchedId, out prefetchedHead, out prefetchedLen);
        }
        else
        {
            ls = LockState.Free;
        }

        Evidence ev = SafetyPolicy.DecideWithPrefetch(item, ls, res.Hash, res.Cancelled,
            pre, prefetchedHead, prefetchedLen);

        ListRow r = new ListRow();
        r.Name = item.Name;
        r.Path = item.Path;
        r.IsDirectory = e.IsDirectory;
        r.Bytes = item.Bytes;
        r.Days = days;
        r.Risk = ev.Risk;
        r.App = ev.App;
        r.Reason = ev.Reason;
        r.Consequence = ev.Consequence;
        r.PolicyEligible = ev.PolicyEligible;
        r.LockedCleanableCache = ev.LockedCleanableCache;
        r.DenyReason = ev.DenyReason;
        r.RuleId = ev.RuleId;
        r.Scope = ev.Scope;
        r.Excludes = ev.Excludes;
        r.EvidenceDetail = ev.ContentVerified
            ? ("已通过：" + ev.EvidenceDetail)
            : (ev.EvidenceDetail.Length > 0 ? ("未通过：" + ev.EvidenceDetail) : "无内容级证据");
        r.SizeComplete = item.SizeComplete;
        r.SizeReason = (size == null || size.Complete) ? "" : size.Explain();
        r.ContentVerified = ev.ContentVerified;
        r.LastWriteUtc = item.LastWriteUtc;
        r.WasReadOnly = !e.IsDirectory && (e.Attributes & FileAttributes.ReadOnly) != 0;
        r.Id = (ls == LockState.Free && ev.PolicyEligible && !(e.IsReparse && res.Budget.Recursive))
            ? (prefetchedId.Ok ? prefetchedId : FileIdentityProbe.Capture(item.Path))
            : default(FileIdentity);
        r.Checked = false;                       // 候选 ≠ 已授权，默认不预选任何项
        r.State = EntryState.Analyzed;

        AnalysisResult ar = AnalysisResult.Of(r);
        // “该规则声明了内容证据，但没有校验通过” —— 与“该规则不需要内容证据”严格区分
        ar.ContentUnverified = (ev.EvidenceKind != EvidenceKind.None) && !ev.ContentVerified;
        return ar;
    }
}

/// <summary>
/// 只读扫描引擎：生产者线程 + 有界队列（背压）。消费方用 TryTakeBatch 拉取。
/// </summary>
public sealed class ScanEngine
{
    /// <summary>背压等待的轮询上限：即使没人 Pulse，取消也能在这个时间内被看到。</summary>
    public const int BackpressureWaitMs = 50;

    private readonly string root;
    private readonly string[] roots;
    private readonly ScanBudget budget;
    private readonly IFileEnumerator enumerator;
    private readonly IEntryAnalyzer analyzer;

    private readonly Queue<ScanBatch> ready = new Queue<ScanBatch>();
    private readonly object gate = new object();
    private readonly Stopwatch clock = new Stopwatch();

    private volatile bool cancel;
    private volatile bool consumerGone;
    private volatile ScanProgress progress = new ScanProgress();
    private volatile bool exited;
    private string lastError = "";

    // ---- v0.5.0 第三批：暂停 / 续扫 ----
    /// <summary>生产者正停在「单轮预算触顶、等继续」上。只有它为 true 才允许续扫。</summary>
    private volatile bool parked;
    /// <summary>单轮预算的**片计数**（每轮重置）。累计计数在 Counters 里，跨轮累加。</summary>
    private int sliceDiscovered, sliceAnalyzed;
    /// <summary>已完成的轮次（1 = 只跑过首轮）。</summary>
    private int rounds = 1;
    /// <summary>不可续的真实原因（空 = 本来就不该续）。</summary>
    private string resumeBlocked = "";
    /// <summary>续扫请求；由 Park 在 gate 上等待。只在 gate 锁内读写。</summary>
    private bool resumeRequested;

    private bool producerDone;
    private int pendingRows;
    private int batchesProduced, rowsProduced, rowsDelivered, rowsDropped, droppedBatches;
    private Thread thread;
    /// <summary>生产者创建的资源状态；Publish 用它报出哈希预算已用量。</summary>
    private AnalysisBudgetState resState;
    /// <summary>最近一次发布的计数器。TryTakeBatch 用它刷新已交付数。</summary>
    private Counters lastCounters;

    public ScanEngine(string root, ScanBudget budget)
        : this(root, budget, new RealFileEnumerator(), new RealEntryAnalyzer()) { }

    public ScanEngine(string root, ScanBudget budget, IFileEnumerator enumerator, IEntryAnalyzer analyzer)
        : this(new string[] { root }, budget, enumerator, analyzer) { }

    public ScanEngine(IList<string> roots, ScanBudget budget)
        : this(roots, budget, null, null) { }

    public ScanEngine(IList<string> roots, ScanBudget budget, IFileEnumerator enumerator, IEntryAnalyzer analyzer)
    {
        if (roots == null || roots.Count == 0)
        {
            this.roots = new string[] { "" };
            this.root = "";
        }
        else
        {
            this.roots = new string[roots.Count];
            for (int i = 0; i < roots.Count; i++) this.roots[i] = roots[i] ?? "";
            this.root = this.roots[0];
        }
        this.budget = budget == null ? new ScanBudget() : budget;
        this.enumerator = enumerator == null ? (this.budget.Recursive ? (IFileEnumerator)new RecursiveFileEnumerator() : new RealFileEnumerator()) : enumerator;
        this.analyzer = analyzer == null ? new RealEntryAnalyzer() : analyzer;
    }

    public ScanProgress Progress { get { return progress; } }
    public bool CancelRequested { get { return cancel; } }
    public bool HasExited { get { return exited; } }
    public string LastError { get { return lastError; } }
    public ScanBudget Budget { get { return budget; } }
    public string Root { get { return root; } }
    public IList<string> Roots { get { return roots; } }

    /// <summary>生产者是否已经把最后一批发完并结束。</summary>
    public bool IsProducerDone { get { lock (gate) { return producerDone; } } }

    /// <summary>队列里还有多少批没被取走。用于判断“是否真的排空”。</summary>
    public int PendingBatches { get { lock (gate) { return ready.Count; } } }

    public void Start()
    {
        Thread t = new Thread(ProducerLoop);
        t.IsBackground = true;
        t.Name = "can-i-delete-scan";
        thread = t;
        t.Start();
    }

    /// <summary>请求取消。幂等、可从任意线程调用；会立刻唤醒正在背压等待的生产者。</summary>
    public void RequestCancel()
    {
        lock (gate) { cancel = true; Monitor.PulseAll(gate); }
    }

    /// <summary>
    /// 消费方不再需要结果（例如窗口已关闭）。按取消处理 —— 绝不“继续扫但把结果丢掉”，
    /// 那会变成未告知的漏项。
    /// </summary>
    public void StopConsuming()
    {
        lock (gate) { consumerGone = true; cancel = true; Monitor.PulseAll(gate); }
    }

    /// <summary>生产者线程是否后台线程。后台线程 ⇒ 进程退出时不会被它拖住。</summary>
    public bool ProducerIsBackground
    {
        get
        {
            Thread t = thread;
            return t == null || t.IsBackground;
        }
    }

    /// <summary>
    /// 等待生产者线程真正退出。返回 false 表示仍卡在某个无法中断的系统调用里 ——
    /// 此时只能如实报告「正在停止」，不得声称已取消完成。
    /// </summary>
    public bool WaitForExit(TimeSpan timeout)
    {
        Thread t = thread;
        if (t == null) return true;
        return t.Join(timeout);
    }

    /// <summary>
    /// 消费方确定不再取结果（关窗 / 退出）时调用：把队列里剩下的行**显式计为丢弃**。
    /// 不这样做的话，它们会永远停在 pending，看起来像“还在路上”，而实际上永远不会有人取。
    /// 返回本次丢弃的行数。
    /// </summary>
    public int AbandonPending()
    {
        int n = 0;
        lock (gate)
        {
            while (ready.Count > 0)
            {
                ScanBatch b = ready.Dequeue();
                pendingRows -= b.Rows.Count;
                rowsDropped += b.Rows.Count;
                droppedBatches++;
                n += b.Rows.Count;
            }
            Monitor.PulseAll(gate);
            if (lastCounters != null) Publish(lastCounters);
        }
        return n;
    }

    /// <summary>拉取一批已就绪的结果（有界队列的消费端）。</summary>
    public bool TryTakeBatch(out ScanBatch batch, int timeoutMs)
    {
        lock (gate)
        {
            while (ready.Count == 0 && !producerDone)
            {
                if (!Monitor.Wait(gate, timeoutMs)) { batch = null; return false; }
            }
            if (ready.Count == 0) { batch = null; return false; }
            batch = ready.Dequeue();
            pendingRows -= batch.Rows.Count;
            rowsDelivered += batch.Rows.Count;
            Monitor.PulseAll(gate);
            // 交完立刻刷新一份进度快照，否则界面读到的 RowsDelivered 会是上一次发布时的旧值
            if (lastCounters != null) Publish(lastCounters);
            return true;
        }
    }

    // ==================================================================
    // 生产者
    // ==================================================================
    private sealed class Counters
    {
        public EnumerationOutcome Enumeration = EnumerationOutcome.NotStarted;
        public RemainderState Remainder = RemainderState.Unknown;
        public ScanStopReason Stop = ScanStopReason.None;
        public int Discovered, Analyzed, Failed, NotAnalyzed, ContentUnverified;
        public long BytesAnalyzed, FileStats, DirVisits;
        public int FilesDiscovered, DirectoryEntries;
        public string CurrentPath = "";
        public ScanStopReason SliceStop;
    }

    private void ProducerLoop()
    {
        Counters c = new Counters();
        try
        {
            RunProducer(c);
        }
        catch (Exception ex)
        {
            lastError = ex.GetType().Name + ": " + ex.Message;
            c.Stop = ScanStopReason.FatalError;
            if (c.Enumeration == EnumerationOutcome.InProgress)
                c.Enumeration = EnumerationOutcome.Failed;
        }
        finally
        {
            Publish(c);
            lock (gate) { producerDone = true; Monitor.PulseAll(gate); }
            exited = true;
            clock.Stop();
        }
    }

    /// <summary>
    /// 生产者主循环。**整个过程固定在这一个线程上**，枚举游标从不跨线程。
    ///
    /// v0.5.0 第三批的关键约束：单轮预算触顶时**不结束线程**，而是原地暂停（Park），
    /// 游标留在本线程；「继续分析」只是让本线程再跑一片新的单轮预算。
    /// 因此不存在“把一个活跃的 IEnumerator 交给另一个线程”这种未经验证的做法。
    ///
    /// 两级预算的分工：
    ///   * 单轮：片计数（sliceDiscovered / sliceAnalyzed）+ 时间钟（clock），每轮重置；
    ///   * 全会话累计：res（AnalysisBudgetState，含 HashBudget、FileStats、DirVisits）
    ///     与队列上限在整段会话里**只创建一次**，续扫绝不重建、绝不重授。
    /// </summary>
    private void RunProducer(Counters c)
    {
        // 全会话唯一一份累计资源状态。放在轮次循环**之外**是“累计预算不可重授”的结构保证。
        AnalysisBudgetState res = new AnalysisBudgetState(budget);
        res.Cancelled = delegate { return cancel; };
        resState = res;

        List<ListRow> buffer = new List<ListRow>();
        IEnumerator<FsEntry> it = null;
        ScanStopReason sessionStop = ScanStopReason.None;
        // 探测（MoveNext）会**消费掉**一个条目。暂停续扫时绝不能丢掉它，
        // 否则就是“静默遗漏一项”。所以把它留到下一轮当第一项处理。
        FsEntry peeked = null;

        try
        {
            try
            {
                it = OpenEnumerator();
            }
            catch (Exception ex)
            {
                lastError = "无法开始枚举： " + ex.Message;
                c.Enumeration = EnumerationOutcome.Failed;
                sessionStop = ScanStopReason.EnumerationFailed;
                resumeBlocked = "无法开始枚举，游标不可用";
            }

            // ================= 轮次循环 =================
            while (sessionStop == ScanStopReason.None)
            {
                // ---- 单轮预算：只重置这一处。累计预算一律继承。 ----
                sliceDiscovered = 0;
                sliceAnalyzed = 0;
                clock.Restart();
                c.Stop = ScanStopReason.None;
                c.SliceStop = ScanStopReason.None;
                c.Enumeration = EnumerationOutcome.InProgress;
                Publish(c);

                ScanStopReason sliceStop = ScanStopReason.None;
                bool sliceProbes = false;

                // ---- 单轮内部循环 ----
                while (sliceStop == ScanStopReason.None)
                {
                    // 预算与取消：都在「取出下一项之前」检查，这样 NotAnalyzed 恒为 0
                    if (cancel)
                    {
                        sliceStop = ScanStopReason.Cancelled;
                        c.Enumeration = EnumerationOutcome.Cancelled;
                        c.Remainder = RemainderState.Unknown;   // 取消不做余量判定
                        break;
                    }
                    // 全会话累计硬上限：硬停，不探测、不提供继续入口
                    if (c.Discovered >= budget.MaxSessionRows)
                    {
                        sliceStop = ScanStopReason.AnalysisBudget;
                        c.Enumeration = EnumerationOutcome.TruncatedByBudget;
                        resumeBlocked = "全会话累计结果上限（" + budget.MaxSessionRows.ToString("N0") + " 项）已耗尽";
                        sessionStop = sliceStop;
                        break;
                    }
                    if (budget.Recursive && (res.FileStats >= budget.MaxFileStats || res.DirVisits >= budget.MaxDirVisits))
                    {
                        sliceStop = ScanStopReason.AnalysisBudget;
                        c.Enumeration = EnumerationOutcome.TruncatedByBudget;
                        resumeBlocked = "全会话属性读取或目录访问预算已耗尽，请选择未扫位置分段分析";
                        sessionStop = sliceStop;
                        break;
                    }
                    if (sliceDiscovered >= budget.MaxTopLevelEntries)
                    {
                        sliceStop = ScanStopReason.TopLevelBudget;
                        c.Enumeration = EnumerationOutcome.TruncatedByBudget;
                        sliceProbes = true;
                        break;
                    }
                    if (sliceAnalyzed >= budget.MaxAnalyzedEntries)
                    {
                        sliceStop = ScanStopReason.AnalysisBudget;
                        c.Enumeration = EnumerationOutcome.TruncatedByBudget;
                        sliceProbes = true;
                        break;
                    }
                    if (clock.Elapsed >= budget.MaxDuration)
                    {
                        // 超时不做探测：那是对用户的明确承诺（不再超预算）
                        sliceStop = ScanStopReason.TimeBudget;
                        c.Enumeration = EnumerationOutcome.TruncatedByBudget;
                        break;
                    }

                    FsEntry e;
                    if (peeked != null)
                    {
                        e = peeked;              // 上一轮探测到的那个，先处理它
                        peeked = null;
                    }
                    else
                    {
                        bool moved;
                        try { moved = it.MoveNext(); }
                        catch (Exception ex)
                        {
                            lastError = "枚举中断： " + ex.Message;
                            c.Enumeration = EnumerationOutcome.Failed;
                            sessionStop = ScanStopReason.EnumerationFailed;
                            resumeBlocked = "枚举中断，游标已释放";
                            break;
                        }
                        if (!moved)
                        {
                            c.Enumeration = EnumerationOutcome.Completed;
                            sessionStop = ScanStopReason.Completed;
                            break;
                        }
                        e = it.Current;
                    }
                    c.Discovered++;
                    sliceDiscovered++;
                    if (e.IsDirectory) c.DirectoryEntries++; else c.FilesDiscovered++;
                    if (budget.Recursive) { if (e.IsDirectory) res.DirVisits++; else res.FileStats++; }
                    c.CurrentPath = e.FullName;
                    Publish(c);

                    AnalysisResult ar;
                    try { ar = analyzer.Analyze(e, ResolveScanRoot(e.FullName), res); }
                    catch (Exception ex) { ar = AnalysisResult.Fail("分析异常：" + ex.GetType().Name); }
                    if (ar == null) ar = AnalysisResult.Fail("分析器未返回结果");

                    // 取消发生在分析过程中：如实记为“已发现但未分析”，并把结果交付出去
                    if (cancel && ar.State == EntryState.NotAnalyzed)
                    {
                        c.NotAnalyzed++;
                        buffer.Add(Placeholder(e, EntryState.NotAnalyzed, SafeReason(ar.Reason, "扫描已取消")));
                        sliceStop = ScanStopReason.Cancelled;
                        c.Enumeration = EnumerationOutcome.Cancelled;
                        c.Remainder = RemainderState.Unknown;
                        break;
                    }

                    if (ar.State == EntryState.Failed)
                    {
                        c.Failed++;
                        buffer.Add(Placeholder(e, EntryState.Failed, SafeReason(ar.Reason, "分析失败")));
                    }
                    else if (ar.State == EntryState.NotAnalyzed)
                    {
                        c.NotAnalyzed++;
                        buffer.Add(Placeholder(e, EntryState.NotAnalyzed, SafeReason(ar.Reason, "未分析")));
                    }
                    else
                    {
                        c.Analyzed++;
                        sliceAnalyzed++;
                        if (ar.Row != null)
                        {
                            ar.Row.State = EntryState.Analyzed;
                            c.BytesAnalyzed += ar.Row.Bytes;
                            buffer.Add(ar.Row);
                        }
                        else
                        {
                            buffer.Add(Placeholder(e, EntryState.Analyzed, "分析器未返回行"));
                        }
                        if (ar.ContentUnverified) c.ContentUnverified++;
                    }

                    c.FileStats = res.FileStats;
                    c.DirVisits = res.DirVisits;

                    if (buffer.Count >= budget.BatchSize)
                    {
                        Enqueue(buffer, false);
                        buffer = new List<ListRow>();
                    }
                    Publish(c);
                }

                c.SliceStop = sliceStop;
                if (sessionStop != ScanStopReason.None) break;   // 会话级终止，不再暂停

                // ---- 余量三态判定（必须在 dispose 之前）----
                if (sliceProbes && it != null)
                {
                    bool completedByProbe = false;
                    peeked = ProbePeek(it, out completedByProbe);
                    if (completedByProbe)
                    {
                        // 恰好达到预算且枚举已结束：如实降为 Completed + 穷尽（total 可精确）
                        c.Enumeration = EnumerationOutcome.Completed;
                        c.Remainder = RemainderState.None;
                        sessionStop = ScanStopReason.Completed;
                        break;
                    }
                    if (peeked == null)
                    {
                        // 探测抛错：游标状态已经不可信，fail-closed，不暂停、不给继续入口
                        c.Remainder = RemainderState.Unknown;
                        resumeBlocked = "探测剩余时枚举出错，游标已释放";
                        sessionStop = sliceStop;
                        break;
                    }
                    c.Remainder = RemainderState.Exists;
                }
                else
                {
                    c.Remainder = RemainderState.Unknown;
                }

                // 落定本轮：把已分析结果全部交付（绕过背压），
                // 否则暂停期间界面上“已分析 / 已显示”对不上账。
                if (buffer.Count > 0) { Enqueue(buffer, true); buffer = new List<ListRow>(); }
                Publish(c);

                // ---- 暂停：线程与游标都留在原地等「继续分析」 ----
                ScanStopReason parkWhy;
                if (!Park(c, out parkWhy)) { sessionStop = parkWhy; break; }
            }
        }
        finally
        {
            if (it != null) { try { it.Dispose(); } catch { } }
            // 尾批绕过背压上限（最多 BatchSize 行，内存有界）：
            // 否则消费方若在等 IsProducerDone 再排空，就会与生产者互相等待。
            if (buffer.Count > 0)
            {
                Enqueue(buffer, true);
                buffer = new List<ListRow>();
            }
            if (sessionStop == ScanStopReason.Completed) c.Remainder = RemainderState.None;
            // 取消 = 对“立即停”的承诺：不再对剩余部分做任何判定，一律 Unknown。
            // （Unknown 永远不会被当成“完整”，所以这样不会虚报；
            //   而保留暂停前那个 Exists 会与“取消后剩余情况未知”的文案自相矛盾。）
            if (sessionStop == ScanStopReason.Cancelled) c.Remainder = RemainderState.Unknown;
            if (c.Remainder == RemainderState.None && c.Enumeration != EnumerationOutcome.Completed)
                c.Enumeration = EnumerationOutcome.TruncatedByBudget;   // 不得自称完成
            c.Stop = sessionStop;
            lock (gate) { parked = false; }
            Publish(c);
        }
    }

    /// <summary>
    /// 暂停：**生产者留在本线程**等待继续。这是本批次最重要的不变量 ——
    /// 枚举游标永远不离开创建它的线程，因此不需要假定 IEnumerator 可以跨线程传递。
    ///
    /// 返回 true = 已收到继续请求，可以开新一轮（单轮预算重置，累计预算不动）。
    /// 返回 false = 不再继续，why 说明原因（取消 / 消费方消失 / 暂停超时）。
    /// </summary>
    private bool Park(Counters c, out ScanStopReason why)
    {
        lock (gate)
        {
            parked = true;
            Publish(c);                       // 让界面立刻看到「可继续」
            long limitMs = (long)budget.MaxParkedDuration.TotalMilliseconds;
            Stopwatch parkClock = Stopwatch.StartNew();
            while (true)
            {
                if (cancel)
                {
                    parked = false;
                    why = ScanStopReason.Cancelled;
                    return false;
                }
                if (resumeRequested)
                {
                    resumeRequested = false;
                    parked = false;
                    rounds++;
                    resumeBlocked = "";           // 新一轮：清掉上一次的阻塞说明
                    why = ScanStopReason.None;
                    return true;
                }
                long remain = limitMs - parkClock.ElapsedMilliseconds;
                if (remain <= 0)
                {
                    // 过期释放：不允许无限期占着一个 find 句柄 + 一个线程
                    parked = false;
                    long ms = (long)budget.MaxParkedDuration.TotalMilliseconds;
                    resumeBlocked = "暂停等待已超过 " + (ms >= 1000 ? (ms / 1000) + " 秒" : ms + " 毫秒")
                                  + "，游标已释放";
                    why = ScanStopReason.ParkTimeout;
                    return false;
                }
                Monitor.Wait(gate, (int)Math.Min(200, remain));
            }
        }
    }

    /// <summary>
    /// 请求继续分析。只有生产者**确实处于暂停态**且未取消/未退出时才接受。
    /// 返回 false 表示这次点击无处可施（已超时释放 / 已取消 / 已结束），
    /// 调用方必须把真实原因告知用户，不得假装还在继续。
    /// </summary>
    public bool RequestResume()
    {
        lock (gate)
        {
            if (!parked || producerDone || cancel || consumerGone) return false;
            resumeRequested = true;
            Monitor.PulseAll(gate);
            return true;
        }
    }

    /// <summary>生产者是否正停在「已达单轮预算、等待继续」上。</summary>
    public bool IsParked { get { lock (gate) { return parked; } } }

    /// <summary>不可续的真实原因（空 = 本来就不该续，例如枚举已穷尽）。</summary>
    public string ResumeBlocked { get { return resumeBlocked; } }

    /// <summary>已完成的轮次（1 = 只跑过首轮）。</summary>
    public int Rounds { get { lock (gate) { return rounds; } } }

    private static string SafeReason(string reason, string fallback)
    {
        return (reason == null || reason.Length == 0) ? fallback : reason;
    }

    /// <summary>
    /// 提前停止后，用**一次**额外的 MoveNext 判断剩余是否存在。
    /// 这不是“枚举剩余部分”，只回答“至少还多一个吗”。
    /// 探测失败一律 Unknown：不知道就说不知道。
    /// </summary>
    private static RemainderState ProbeRemainder(IEnumerator<FsEntry> it, out bool enumerationCompleted)
    {
        bool completed;
        FsEntry peeked = ProbePeek(it, out completed);
        enumerationCompleted = completed;
        if (completed) return RemainderState.None;
        return peeked == null ? RemainderState.Unknown : RemainderState.Exists;
    }

    /// <summary>
    /// 单步探测“是否还有下一项”，并把探到的那一项**返回给调用方保管**。
    /// 这一点至关重要：MoveNext 已经让游标前进了一项，
    /// 若不把它交给下一轮去处理，续扫就会**静默漏掉这一项**。
    /// 返回 null + completed=false 表示探测本身抛错（游标状态不可信）。
    /// </summary>
    private static FsEntry ProbePeek(IEnumerator<FsEntry> it, out bool completed)
    {
        completed = false;
        try
        {
            if (it.MoveNext()) return it.Current;
            completed = true;
            return null;
        }
        catch { return null; }
    }

    private IEnumerator<FsEntry> OpenEnumerator()
    {
        if (roots.Length <= 1)
        {
            return enumerator.Enumerate(root).GetEnumerator();
        }
        RecursiveFileEnumerator tree = enumerator as RecursiveFileEnumerator;
        if (tree != null)
        {
            return tree.EnumerateMany(roots).GetEnumerator();
        }
        return EnumerateSequential().GetEnumerator();
    }

    private IEnumerable<FsEntry> EnumerateSequential()
    {
        for (int i = 0; i < roots.Length; i++)
        {
            foreach (FsEntry entry in enumerator.Enumerate(roots[i]))
            {
                yield return entry;
            }
        }
    }

    private string ResolveScanRoot(string fullPath)
    {
        if (roots.Length <= 1) return root;
        string best = "";
        for (int i = 0; i < roots.Length; i++)
        {
            string candidate = roots[i];
            if (string.IsNullOrEmpty(candidate)) continue;
            if (PathGuard.IsInside(candidate, fullPath) && candidate.Length > best.Length)
            {
                best = candidate;
            }
        }
        return best.Length > 0 ? best : root;
    }

    /// <summary>失败 / 未分析项也要出现在结果里 —— 不得静默丢弃。</summary>
    private static ListRow Placeholder(FsEntry e, EntryState st, string reason)
    {
        ListRow r = new ListRow();
        r.Name = e.Name;
        r.Path = e.FullName;
        r.IsDirectory = e.IsDirectory;
        r.Bytes = e.IsDirectory ? 0 : e.Length;
        r.Risk = "需复核";
        r.App = "未分析";
        r.Reason = (st == EntryState.Failed ? "分析失败" : "未分析") + "：" + reason;
        r.Consequence = "本项目没有被分析，结果中不含任何关于它的结论；不要据此判断它可以删除。";
        r.PolicyEligible = false;
        r.DenyReason = reason;
        r.RuleId = "";
        r.EvidenceDetail = "未分析（引擎未对该项产出结论）";
        r.SizeComplete = false;
        r.SizeReason = st == EntryState.Failed ? "分析失败，未统计" : "未分析，未统计";
        r.Checked = false;
        r.State = st;
        return r;
    }

    /// <summary>有界队列入队；队满则阻塞（背压）。取消 / 消费方退出时立即返回 false。</summary>
    /// <remarks>bypassLimits 仅用于尾批（≤ BatchSize 行），用于避开与消费方的互相等待。</remarks>
    private bool Enqueue(List<ListRow> rows, bool bypassLimits)
    {
        if (rows.Count == 0) return true;
        ScanBatch b = new ScanBatch();
        b.Rows.AddRange(rows);

        lock (gate)
        {
            // 生产量在“入队前”计数，这样不变量成立：
            //   已生产 == 已交付 + 已丢弃 + 待交付
            rowsProduced += rows.Count;

            // 严格上限：先算“再加这一批会不会超”，而不是先加再看。
            // pendingRows > 0 的保护：单个批次本身就大于上限时不得死等（BatchSize > MaxPendingRows）。
            while (!bypassLimits && !cancel && !consumerGone &&
                   (ready.Count >= budget.MaxPendingBatches ||
                    (pendingRows > 0 && pendingRows + b.Rows.Count > budget.MaxPendingRows)))
            {
                Monitor.Wait(gate, BackpressureWaitMs);
            }
            // 尾批（bypassLimits）即使在取消后也要交付：里面是已经分析出来的结论，
            // 丢掉它就等于把“已发现但未分析 / 已分析”变成未告知的缺失。
            // 只有消费方已经不在了才无法交付（由 BatchesDropped 如实计数）。
            if (consumerGone || (cancel && !bypassLimits))
            {
                droppedBatches++;
                rowsDropped += rows.Count;
                return false;
            }

            b.Index = batchesProduced + 1;
            ready.Enqueue(b);
            pendingRows += b.Rows.Count;
            batchesProduced++;
            Monitor.PulseAll(gate);
            return true;
        }
    }
    /// <summary>发布一份新的进度快照（每次都是新对象，读方不会看到半更新状态）。</summary>
    private void Publish(Counters c)
    {
        ScanProgress p = new ScanProgress();
        p.Enumeration = c.Enumeration;
        p.Stop = c.Stop;
        p.Remainder = c.Remainder;
        p.Discovered = c.Discovered;
        p.Analyzed = c.Analyzed;
        p.Failed = c.Failed;
        p.NotAnalyzed = c.NotAnalyzed;
        p.BytesAnalyzed = c.BytesAnalyzed;
        p.FileStats = c.FileStats;
        p.DirVisits = c.DirVisits;
        p.ContentUnverified = c.ContentUnverified;
        lock (gate)
        {
            lastCounters = c;
            p.BatchesProduced = batchesProduced;
            p.RowsProduced = rowsProduced;
            p.RowsDelivered = rowsDelivered;
            p.RowsDropped = rowsDropped;
            p.BatchesPending = ready.Count;
            p.RowsPending = pendingRows;
            p.BatchesDropped = droppedBatches;
        }
        p.HashBytesUsed = HashBytesUsed();
        lock (gate)
        {
            p.Resumable = parked;
            p.Rounds = rounds;
        }
        p.ResumeBlocked = resumeBlocked;
        p.SessionRowsLimit = budget.MaxSessionRows;
        p.FileStatsLimit = budget.MaxFileStats;
        p.DirVisitsLimit = budget.MaxDirVisits;        p.HashBytesLimit = budget.MaxHashBytes;
        p.ParkSeconds = (int)budget.MaxParkedDuration.TotalSeconds;
        AnalysisBudgetState rs = resState;
        p.HashBudgetExhausted = rs != null && rs.Hash != null && (rs.Hash.Denied || rs.Hash.Exhausted);
        p.FilesDiscovered = c.FilesDiscovered;
        p.DirectoryEntries = c.DirectoryEntries;
        p.CurrentPath = c.CurrentPath;
        p.SliceStop = c.SliceStop;
        RecursiveFileEnumerator tree = enumerator as RecursiveFileEnumerator;
        p.Coverage = tree == null ? null : tree.Snapshot();
        progress = p;
    }

    private long HashBytesUsed()
    {
        AnalysisBudgetState s = resState;
        if (s == null || s.Hash.IsUnlimited) return 0;
        long used = s.Hash.Total - s.Hash.Remaining;
        return used < 0 ? 0 : used;
    }
}
