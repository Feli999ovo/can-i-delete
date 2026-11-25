using System;
using System.Collections.Generic;
using System.IO;

/// <summary>
/// 线程安全的目录前缀字符串驻留池。
/// 百万文件扫描场景下，同一目录通常包含成百上千个文件；对父目录路径做驻留后，
/// 所有同目录 ListRow 共享同一个 DirectoryPath 字符串实例，大幅降低托管堆内存占用。
/// </summary>
public static class PathPool
{
    public const int MaxEntries = 200000;

    private static readonly object gate = new object();
    private static readonly Dictionary<string, string> pool =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public static string InternDir(string dir)
    {
        if (string.IsNullOrEmpty(dir)) return "";
        lock (gate)
        {
            string cached;
            if (pool.TryGetValue(dir, out cached)) return cached;
            if (pool.Count < MaxEntries)
            {
                pool[dir] = dir;
            }
            return dir;
        }
    }

    public static int Count
    {
        get { lock (gate) { return pool.Count; } }
    }

    public static void Clear()
    {
        lock (gate) { pool.Clear(); }
    }
}

/// <summary>扫描结果中的单行数据模型（零 WinForms 依赖，支持目录前缀驻留瘦身）。</summary>
public class ListRow
{
    private string dir = "";
    private string leaf = "";
    private bool rawFallback;

    /// <summary>
    /// 完整路径属性：写入时自动拆分为驻留目录前缀 + 叶子名，读取时按需拼接还原；
    /// 对根目录、末尾带分隔符或含正斜杠等无法无损拆分的路径保留原值兜底，确保读写语义 100% 兼容。
    /// </summary>
    public string Path
    {
        get { return GetPath(); }
        set { SetPath(value); }
    }

    /// <summary>驻留后的父目录路径（零分配直接读取，供目录聚合与桥接层高频访问）。</summary>
    public string DirectoryPath
    {
        get { return dir; }
    }

    public string Name = "";
    public long Bytes;
    public bool IsDirectory;
    public int Days;
    public string Risk = "";
    public string App = "";
    public string Reason = "";
    public string Consequence = "";
    /// <summary>是否获准删除。由 SafetyPolicy 决定，与 Risk 展示分级分离。</summary>
    public bool PolicyEligible;
    /// <summary>是否为已识别的受控缓存项，但因当前正被运行中的程序占用而本轮跳过。</summary>
    public bool LockedCleanableCache;
    /// <summary>未获授权时的原因。</summary>
    public string DenyReason = "";
    /// <summary>命中的可追溯规则编号。</summary>
    public string RuleId = "";
    /// <summary>该规则的适用范围 / 排除条件（用于审计展示）。</summary>
    public string Scope = "";
    public string Excludes = "";
    /// <summary>内容级证据的结论（决定能否授权）。</summary>
    public string EvidenceDetail = "";
    /// <summary>体积是否完整统计（目录超限/含链接时为 false）。</summary>
    public bool SizeComplete = true;
    /// <summary>是否完成了内容级证据校验。</summary>
    public bool ContentVerified;
    /// <summary>体积不完整的原因（为空表示完整）。</summary>
    public string SizeReason = "";
    /// <summary>该项的分析状态（Analyzed/Failed/NotAnalyzed）。</summary>
    public EntryState State = EntryState.Analyzed;
    /// <summary>删除前身份校验用的扫描快照。</summary>
    public DateTime LastWriteUtc;
    public bool WasReadOnly;
    /// <summary>扫描时抓到的强身份（卷号 + 文件索引）。</summary>
    public FileIdentity Id;
    public bool Checked;

    private string GetPath()
    {
        if (rawFallback) return leaf;
        if (dir.Length == 0) return leaf;
        if (dir[dir.Length - 1] == '\\') return dir + leaf;
        return dir + "\\" + leaf;
    }

    private void SetPath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath))
        {
            dir = "";
            leaf = "";
            rawFallback = false;
            return;
        }

        int len = fullPath.Length;
        if (fullPath.IndexOf('/') >= 0
            || fullPath[len - 1] == '\\'
            || (len == 2 && fullPath[1] == ':'))
        {
            dir = PathPool.InternDir(TryGetDirectoryNameSafe(fullPath));
            leaf = fullPath;
            rawFallback = true;
            return;
        }

        int sep = fullPath.LastIndexOf('\\');
        if (sep < 0)
        {
            dir = "";
            leaf = ReuseOrSliceLeaf(fullPath, 0);
            rawFallback = false;
            if (string.IsNullOrEmpty(Name) && leaf.Length > 0) Name = leaf;
            return;
        }

        // UNC 共享根（如 \\server\share）无上级目录，保留原值兜底
        if (len >= 2 && fullPath[0] == '\\' && fullPath[1] == '\\')
        {
            int thirdSlash = fullPath.IndexOf('\\', 2);
            if (thirdSlash < 0 || thirdSlash == sep)
            {
                dir = "";
                leaf = fullPath;
                rawFallback = true;
                return;
            }
        }

        // 连续反斜杠（非规范路径）保留原值兜底，确保读出字符串与写入逐字符一致
        if (sep > 1 && fullPath[sep - 1] == '\\')
        {
            dir = PathPool.InternDir(TryGetDirectoryNameSafe(fullPath));
            leaf = fullPath;
            rawFallback = true;
            return;
        }

        string dirPart;
        if (sep == 0)
        {
            dirPart = "\\";
        }
        else if (sep == 2 && len > 3 && fullPath[1] == ':')
        {
            dirPart = fullPath.Substring(0, 3);
        }
        else
        {
            dirPart = fullPath.Substring(0, sep);
        }

        dir = PathPool.InternDir(dirPart);
        leaf = ReuseOrSliceLeaf(fullPath, sep + 1);
        rawFallback = false;
        if (string.IsNullOrEmpty(Name) && leaf.Length > 0) Name = leaf;
    }

    private string ReuseOrSliceLeaf(string fullPath, int startIndex)
    {
        if (startIndex <= 0) return fullPath;
        int leafLen = fullPath.Length - startIndex;
        if (Name != null && Name.Length == leafLen
            && string.CompareOrdinal(fullPath, startIndex, Name, 0, leafLen) == 0)
        {
            return Name;
        }
        return fullPath.Substring(startIndex);
    }

    private static string TryGetDirectoryNameSafe(string fullPath)
    {
        try
        {
            return System.IO.Path.GetDirectoryName(fullPath) ?? "";
        }
        catch
        {
            return "";
        }
    }
}

/// <summary>结果筛选档位。</summary>
public enum RowFilter { All = 0, Candidate = 1, Review = 2, Keep = 3 }

/// <summary>结果排序键。</summary>
public enum RowSortKey { Default = 0, Size = 1 }

/// <summary>行分类的唯一口径。</summary>
public static class RowClass
{
    /// <summary>该行是否属于某一筛选档。</summary>
    public static bool Matches(ListRow r, RowFilter f)
    {
        if (r == null) return false;
        switch (f)
        {
            case RowFilter.Candidate: return r.PolicyEligible;
            case RowFilter.Review: return !r.PolicyEligible && r.Risk != "保留";
            case RowFilter.Keep: return r.Risk == "保留";
            default: return true;
        }
    }

    /// <summary>该行落在哪一档（四档互斥且覆盖全部行）。</summary>
    public static RowFilter Of(ListRow r)
    {
        if (r == null) return RowFilter.Review;
        if (r.PolicyEligible) return RowFilter.Candidate;
        return r.Risk == "保留" ? RowFilter.Keep : RowFilter.Review;
    }
}

/// <summary>纯文本体积格式化辅助（保留静态方法兼容 ScanText.FormatSize，无任何 WinForms 依赖）。</summary>
public static class RowList
{
    public static string FormatSize(long bytes)
    {
        if (bytes >= 1073741824L) return (bytes / 1073741824.0).ToString("0.##") + " GB";
        if (bytes >= 1048576L) return (bytes / 1048576.0).ToString("0.#") + " MB";
        if (bytes >= 1024L) return (bytes / 1024.0).ToString("0.#") + " KB";
        return bytes + " B";
    }
}
