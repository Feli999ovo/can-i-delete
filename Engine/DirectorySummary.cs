using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

// Counts only analyzed files, never directory container sizes; no filesystem traversal.
// Supports both single-root scans and multi-root quick scans cleanly.
public class DirectorySummary
{
    private readonly bool multiRoot;
    private readonly string displayRoot;
    private readonly List<string> scanRoots = new List<string>();
    private readonly Dictionary<string, Node> nodes = new Dictionary<string, Node>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, Node> ids = new Dictionary<int, Node>();
    private readonly Dictionary<string, ListRow> files = new Dictionary<string, ListRow>(StringComparer.OrdinalIgnoreCase);
    private long session;
    private int nextId;
    private bool partial;

    private class Node
    {
        public int Id;
        public string Path;
        public string DisplayName;
        public Node Parent;
        public long Bytes, EligibleBytes, ReviewBytes, KeepBytes;
        public int Count, Eligible, Review, Keep, Unknown;
        public readonly List<Node> Children = new List<Node>();
        public readonly Dictionary<string, ListRow> Files = new Dictionary<string, ListRow>(StringComparer.OrdinalIgnoreCase);
    }

    public DirectorySummary(string root)
    {
        multiRoot = false;
        string norm = TryNormalize(root);
        if (norm.Length > 0)
        {
            displayRoot = norm;
            scanRoots.Add(norm);
        }
        else
        {
            displayRoot = "";
        }
    }

    public DirectorySummary(IList<string> roots, string displayRootName)
    {
        if (roots != null && roots.Count == 1)
        {
            multiRoot = false;
            string norm = TryNormalize(roots[0]);
            if (norm.Length > 0)
            {
                displayRoot = norm;
                scanRoots.Add(norm);
            }
            else
            {
                displayRoot = "";
            }
            return;
        }

        multiRoot = true;
        displayRoot = string.IsNullOrEmpty(displayRootName) ? "常见缓存位置" : displayRootName;
        if (roots != null)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < roots.Count; i++)
            {
                if (string.IsNullOrEmpty(roots[i])) continue;
                string norm = TryNormalize(roots[i]);
                if (norm.Length > 0 && seen.Add(norm)) scanRoots.Add(norm);
            }
        }
    }

    private static string TryNormalize(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        try { return Normalize(path); }
        catch { return ""; }
    }

    private static string Normalize(string path)
    {
        string canon = PathGuard.Canonical(path);
        if (canon.Length == 0) canon = Path.GetFullPath(path);
        return canon.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
    }

    private static string DeriveDirKey(string canonicalFilePath)
    {
        if (string.IsNullOrEmpty(canonicalFilePath)) return "";
        try
        {
            string parent = Path.GetDirectoryName(canonicalFilePath);
            if (string.IsNullOrEmpty(parent)) return "";
            string canonDir = PathGuard.Canonical(parent);
            if (canonDir.Length == 0) return "";
            return canonDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        }
        catch { return ""; }
    }

    public void StartScan(long sessionId)
    {
        session = sessionId;
        nextId = 1;
        partial = false;
        nodes.Clear();
        ids.Clear();
        files.Clear();

        if (!multiRoot)
        {
            if (scanRoots.Count > 0)
            {
                Node root = new Node { Id = 0, Path = scanRoots[0], DisplayName = Name(scanRoots[0]) };
                nodes.Add(scanRoots[0], root);
                ids.Add(0, root);
            }
            else
            {
                Node emptyRoot = new Node { Id = 0, Path = displayRoot, DisplayName = displayRoot };
                ids.Add(0, emptyRoot);
            }
        }
        else
        {
            Node vRoot = new Node { Id = 0, Path = displayRoot, DisplayName = displayRoot };
            ids.Add(0, vRoot);
            for (int i = 0; i < scanRoots.Count; i++)
            {
                string sr = scanRoots[i];
                Node child = new Node
                {
                    Id = nextId++,
                    Path = sr,
                    DisplayName = FriendlyRootLabel(sr, scanRoots),
                    Parent = vRoot
                };
                nodes[sr] = child;
                ids[child.Id] = child;
                vRoot.Children.Add(child);
            }
        }
    }

    private static string FriendlyRootLabel(string normalizedRoot, List<string> allRoots)
    {
        string trimmed = normalizedRoot.TrimEnd(Path.DirectorySeparatorChar);
        string leaf = Name(normalizedRoot);
        int dupCount = 0;
        for (int i = 0; i < allRoots.Count; i++)
        {
            if (string.Equals(Name(allRoots[i]), leaf, StringComparison.OrdinalIgnoreCase))
                dupCount++;
        }
        if (dupCount <= 1) return leaf;
        string[] parts = trimmed.Split(Path.DirectorySeparatorChar);
        if (parts.Length >= 3)
        {
            return parts[parts.Length - 3] + "\\" + parts[parts.Length - 2] + "\\" + parts[parts.Length - 1];
        }
        return trimmed;
    }

    public void SetPartial(bool value) { partial = value; }

    private string FindMatchingRoot(string normalizedDir)
    {
        string best = null;
        for (int i = 0; i < scanRoots.Count; i++)
        {
            string sr = scanRoots[i];
            if (normalizedDir.StartsWith(sr, StringComparison.OrdinalIgnoreCase))
            {
                if (best == null || sr.Length > best.Length)
                    best = sr;
            }
        }
        return best;
    }

    public void UpdateFromRows(List<ListRow> rows, int start)
    {
        if (rows == null || scanRoots.Count == 0 || start < 0) return;
        for (int i = start; i < rows.Count; i++)
        {
            ListRow row = rows[i];
            if (row == null || row.IsDirectory) continue;

            string path = PathGuard.Canonical(row.Path);
            if (path.Length == 0) continue;
            string dir = DeriveDirKey(path);
            if (dir.Length == 0) continue;

            string matchedRoot = FindMatchingRoot(dir);
            if (matchedRoot == null || files.ContainsKey(path)) continue;

            Node node = EnsureNode(dir, matchedRoot);
            if (node == null) continue;
            files.Add(path, row);
            node.Files.Add(path, row);
            Adjust(node, row, 1);
        }
    }

    private Node EnsureNode(string dir, string stopRoot)
    {
        Node existing;
        if (nodes.TryGetValue(dir, out existing)) return existing;

        Stack<string> missing = new Stack<string>();
        string cur = dir;
        Node anchor = null;

        while (true)
        {
            if (nodes.TryGetValue(cur, out anchor)) break;
            if (string.Equals(cur, stopRoot, StringComparison.OrdinalIgnoreCase))
            {
                if (!nodes.TryGetValue(stopRoot, out anchor)) return null;
                break;
            }

            missing.Push(cur);
            string trimmed = cur.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string parentRaw = null;
            try { parentRaw = Path.GetDirectoryName(trimmed); }
            catch { parentRaw = null; }

            if (string.IsNullOrEmpty(parentRaw))
            {
                nodes.TryGetValue(stopRoot, out anchor);
                break;
            }

            string parentDir = TryNormalize(parentRaw);
            if (parentDir.Length == 0
                || string.Equals(parentDir, cur, StringComparison.OrdinalIgnoreCase))
            {
                nodes.TryGetValue(stopRoot, out anchor);
                break;
            }

            cur = parentDir;
        }

        if (anchor == null) return null;
        Node parent = anchor;
        while (missing.Count > 0)
        {
            string nextDir = missing.Pop();
            Node node;
            if (!nodes.TryGetValue(nextDir, out node))
            {
                node = new Node { Id = nextId++, Path = nextDir, DisplayName = Name(nextDir), Parent = parent };
                nodes.Add(nextDir, node);
                ids.Add(node.Id, node);
                parent.Children.Add(node);
            }
            parent = node;
        }
        return parent;
    }

    private static void Adjust(Node node, ListRow row, int delta)
    {
        long b = Math.Max(0, row.Bytes) * delta;
        for (; node != null; node = node.Parent)
        {
            node.Bytes += b;
            node.Count += delta;
            if (row.PolicyEligible) { node.Eligible += delta; node.EligibleBytes += b; }
            else if (row.Risk == EvidenceRules.RiskReview) { node.Review += delta; node.ReviewBytes += b; }
            else { node.Keep += delta; node.KeepBytes += b; }
            if (!row.SizeComplete) node.Unknown += delta;
        }
    }

    public void RemoveRows(List<ListRow> removed)
    {
        if (removed == null) return;
        foreach (ListRow row in removed)
        {
            if (row == null) continue;
            string path = PathGuard.Canonical(row.Path);
            if (path.Length == 0) continue;
            ListRow original;
            if (!files.TryGetValue(path, out original)) continue;
            string dir = DeriveDirKey(path);
            if (dir.Length == 0) continue;
            Node node;
            if (!nodes.TryGetValue(dir, out node)) continue;
            files.Remove(path);
            node.Files.Remove(path);
            Adjust(node, original, -1);
        }
    }

    private static string Name(string path)
    {
        string name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
        return string.IsNullOrEmpty(name) ? path : name;
    }

    private static string NodeLabel(Node n)
    {
        return !string.IsNullOrEmpty(n.DisplayName) ? n.DisplayName : Name(n.Path);
    }

    public DirectoryPage Query(long sessionId, int directoryId, int offset)
    {
        Node node;
        if (sessionId != session || directoryId < 0 || offset < 0 || !ids.TryGetValue(directoryId, out node)) return null;
        var children = node.Children.Where(delegate(Node n) { return n.Count > 0; }).Select(delegate(Node n)
        {
            return new DirectoryRow
            {
                DirectoryId = n.Id,
                IsDirectory = true,
                Name = NodeLabel(n),
                Path = n.Path,
                Bytes = n.Bytes,
                FileCount = n.Count,
                EligibleCount = n.Eligible,
                ReviewCount = n.Review,
                KeepCount = n.Keep,
                EligibleBytes = n.EligibleBytes,
                ReviewBytes = n.ReviewBytes,
                KeepBytes = n.KeepBytes,
                SizeComplete = n.Unknown == 0,
                IsPartial = partial || n.Unknown > 0
            };
        }).Concat(node.Files.Values.Select(delegate(ListRow r)
        {
            long rb = Math.Max(0, r.Bytes);
            bool el = r.PolicyEligible;
            bool rv = !el && r.Risk == EvidenceRules.RiskReview;
            return new DirectoryRow
            {
                DirectoryId = -1,
                IsDirectory = false,
                File = r,
                Name = r.Name,
                Path = r.Path,
                Bytes = rb,
                FileCount = 1,
                EligibleCount = el ? 1 : 0,
                ReviewCount = rv ? 1 : 0,
                KeepCount = (!el && !rv) ? 1 : 0,
                EligibleBytes = el ? rb : 0,
                ReviewBytes = rv ? rb : 0,
                KeepBytes = (!el && !rv) ? rb : 0,
                SizeComplete = r.SizeComplete,
                IsPartial = !r.SizeComplete
            };
        })).OrderByDescending(delegate(DirectoryRow r) { return r.Bytes; })
          .ThenBy(delegate(DirectoryRow r) { return r.Path; }, StringComparer.OrdinalIgnoreCase)
          .ToList();

        const int limit = 100;
        offset = children.Count == 0 ? 0 : Math.Min(offset, ((children.Count - 1) / limit) * limit);
        var crumbs = new List<DirectoryBreadcrumb>();
        for (Node n = node; n != null; n = n.Parent)
        {
            crumbs.Add(new DirectoryBreadcrumb { DirectoryId = n.Id, Name = NodeLabel(n), Path = n.Path });
        }
        crumbs.Reverse();
        return new DirectoryPage
        {
            DirectoryId = node.Id,
            CurrentPath = node.Path,
            CurrentName = NodeLabel(node),
            ParentDirectory = node.Parent == null ? null : new DirectoryParentInfo
            {
                DirectoryId = node.Parent.Id,
                Name = NodeLabel(node.Parent),
                Path = node.Parent.Path
            },
            Breadcrumb = crumbs.ToArray(),
            TotalBytes = node.Bytes,
            TotalFileCount = node.Count,
            EligibleCount = node.Eligible,
            ReviewCount = node.Review,
            KeepCount = node.Keep,
            EligibleBytes = node.EligibleBytes,
            ReviewBytes = node.ReviewBytes,
            KeepBytes = node.KeepBytes,
            TotalRows = children.Count,
            PageLimit = limit,
            PageOffset = offset,
            IsPartial = partial || node.Unknown > 0,
            Rows = children.Skip(offset).Take(limit).ToArray()
        };
    }

    public class DirectoryPage
    {
        public int DirectoryId, TotalFileCount, EligibleCount, ReviewCount, KeepCount, TotalRows, PageLimit, PageOffset;
        public long TotalBytes, EligibleBytes, ReviewBytes, KeepBytes;
        public string CurrentPath, CurrentName;
        public bool IsPartial;
        public DirectoryParentInfo ParentDirectory;
        public DirectoryBreadcrumb[] Breadcrumb;
        public DirectoryRow[] Rows;
    }

    public class DirectoryParentInfo { public int DirectoryId; public string Name, Path; }
    public class DirectoryBreadcrumb { public int DirectoryId; public string Name, Path; }

    public class DirectoryRow
    {
        public int DirectoryId, FileCount, EligibleCount, ReviewCount, KeepCount;
        public string Name, Path;
        public long Bytes, EligibleBytes, ReviewBytes, KeepBytes;
        public bool IsDirectory, SizeComplete, IsPartial;
        public ListRow File;
    }
}
