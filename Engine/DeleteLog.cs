using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

// =====================================================================
// 删除审计日志：intent → action → outcome（执行契约 v1）
//
// 为什么必须先有 intent：删除**不可逆**。只有动手之前先把"我准备做什么"落盘，
// 崩溃后才可能分辨"根本没发生"与"发生了但结果丢了"。
//
// 铁律（与 UI 无关，纯函数级）：
//   * 写不了 intent 就**不许派发**操作 —— 日志不可信时不动文件；
//   * 有 intent 无 outcome = 待核实（PendingReconciliation），
//     **不得**推断为"已删除"，也**不得**推断为"还在"；
//   * 恢复分析只报事实，**绝不自动重试**任何文件操作；
//   * 本文件是产品代码中**唯一**允许写盘的地方（仅写日志文件本身）。
//
// 格式：制表符分隔的 key=value，行首标记 I / O。
//      path 的值可能很长且含反斜杠，故对 \\ \t \r \n 做转义；
//      解析按**第一个** '=' 切分，因此值里出现 '=' 不需要特殊处理。
// =====================================================================

public static class DeleteLog
{
    public const string IntentMark = "I";
    public const string OutcomeMark = "O";
    public const long DefaultRotateBytes = 5L * 1024 * 1024;

    /// <summary>每项操作一个唯一 ID。</summary>
    public static string NewOpId() { return Guid.NewGuid().ToString("N"); }

    /// <summary>
    /// 可复用的批量删除审计写入会话：贯穿整个批次只打开一次 WriteThrough 文件句柄，
    /// 消除万级缓存清理时逐行开关句柄与全盘 FlushFileBuffers 的 I/O 风暴。
    /// </summary>
    public sealed class WriterSession : IDisposable
    {
        private readonly object sync = new object();
        private readonly StringBuilder lineBuffer = new StringBuilder(320);
        private FileStream fs;
        private int writeCount;
        private bool disposed;

        internal WriterSession(FileStream stream)
        {
            fs = stream;
        }

        public bool WriteIntent(string opId, string batchId, DeleteRequest r, string target, out string why)
        {
            lock (sync)
            {
                why = "";
                if (disposed || fs == null)
                {
                    why = "日志写入会话已关闭";
                    return false;
                }
                try
                {
                    lineBuffer.Length = 0;
                    AppendIntentFields(lineBuffer, opId, batchId, r, target);
                    lineBuffer.Append("\r\n");
                    byte[] bytes = Encoding.UTF8.GetBytes(lineBuffer.ToString());
                    fs.Write(bytes, 0, bytes.Length);
                    writeCount++;
                    if ((writeCount & 127) == 0) fs.Flush(true);
                    else fs.Flush(false);
                    return true;
                }
                catch (Exception ex)
                {
                    why = ex.GetType().Name + "：" + ex.Message;
                    return false;
                }
            }
        }

        public bool WriteOutcome(string opId, string batchId, DeleteOutcome o, out string why)
        {
            lock (sync)
            {
                why = "";
                if (disposed || fs == null)
                {
                    why = "日志写入会话已关闭";
                    return false;
                }
                try
                {
                    lineBuffer.Length = 0;
                    AppendOutcomeFields(lineBuffer, opId, batchId, o);
                    lineBuffer.Append("\r\n");
                    byte[] bytes = Encoding.UTF8.GetBytes(lineBuffer.ToString());
                    fs.Write(bytes, 0, bytes.Length);
                    writeCount++;
                    bool hardFlush = ((writeCount & 127) == 0)
                        || (o != null && (o.Status == DeleteStatus.OutcomeUnknown || o.Status == DeleteStatus.PendingReconciliation));
                    if (hardFlush) fs.Flush(true);
                    else fs.Flush(false);
                    return true;
                }
                catch (Exception ex)
                {
                    why = ex.GetType().Name + "：" + ex.Message;
                    return false;
                }
            }
        }

        public void Dispose()
        {
            lock (sync)
            {
                if (disposed) return;
                disposed = true;
                if (fs != null)
                {
                    try { fs.Flush(true); } catch { }
                    try { fs.Dispose(); } catch { }
                    fs = null;
                }
            }
        }
    }

    /// <summary>
    /// 打开批量审计日志会话并执行初始可写性落盘探测；不可写时返回 null 并填入原因。
    /// </summary>
    public static WriterSession OpenSession(string logPath, out string why)
    {
        why = "";
        if (String.IsNullOrEmpty(logPath)) { why = "未指定日志路径"; return null; }
        FileStream stream = null;
        try
        {
            string dir = Path.GetDirectoryName(logPath);
            if (!String.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            stream = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read, 16384, FileOptions.None);
            byte[] probe = Encoding.UTF8.GetBytes("# writability-probe\r\n");
            stream.Write(probe, 0, probe.Length);
            stream.Flush(true);
            WriterSession session = new WriterSession(stream);
            stream = null;
            return session;
        }
        catch (Exception ex)
        {
            if (stream != null)
            {
                try { stream.Dispose(); } catch { }
            }
            why = ex.GetType().Name + "：" + ex.Message;
            return null;
        }
    }

    /// <summary>
    /// 写盘可行性预检：日志不可写就必须**在派发任何操作之前**就拒绝整批，
    /// 而不是"先删了再发现记不下来"。
    /// </summary>
    public static bool EnsureWritable(string logPath, out string why)
    {
        why = "";
        if (String.IsNullOrEmpty(logPath)) { why = "未指定日志路径"; return false; }
        try
        {
            string dir = Path.GetDirectoryName(logPath);
            if (!String.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
            using (FileStream fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read))
            {
                byte[] probe = Encoding.UTF8.GetBytes("# writability-probe\r\n");
                fs.Write(probe, 0, probe.Length);
                fs.Flush(true);            // 落盘，而不是留在缓冲区
            }
            return true;
        }
        catch (Exception ex) { why = ex.GetType().Name + "：" + ex.Message; return false; }
    }

    /// <summary>写入"准备执行"记录。返回 false 表示**不得派发**该操作。</summary>
    public static bool WriteIntent(string logPath, string opId, string batchId, DeleteRequest r,
                                   string target, out string why)
    {
        StringBuilder sb = new StringBuilder(256);
        AppendIntentFields(sb, opId, batchId, r, target);
        return Append(logPath, sb.ToString(), out why);
    }

    public static bool WriteOutcome(string logPath, string opId, string batchId, DeleteOutcome o, out string why)
    {
        StringBuilder sb = new StringBuilder(256);
        AppendOutcomeFields(sb, opId, batchId, o);
        return Append(logPath, sb.ToString(), out why);
    }

    private static void AppendIntentFields(StringBuilder sb, string opId, string batchId, DeleteRequest r, string target)
    {
        AppendStamp(sb, DateTime.Now);
        sb.Append('\t').Append(IntentMark);
        sb.Append("\top=").Append(opId);
        sb.Append("\tbatch=").Append(batchId);
        sb.Append("\tpath=").Append(Esc(String.IsNullOrEmpty(target) ? (r == null ? "" : r.Path) : target));
        sb.Append("\tdir=").Append((r != null && r.WasDirectory) ? "1" : "0");
        sb.Append("\tsize=").Append(r == null ? "0" : r.BytesAtScan.ToString());
        sb.Append("\tmtime=").Append(r == null ? "0" : r.LastWriteUtcAtScan.Ticks.ToString());
        sb.Append("\tro=").Append((r != null && r.WasReadOnly) ? "1" : "0");
        sb.Append("\tvol=").Append((r != null && r.IdAtScan.Ok) ? r.IdAtScan.VolumeSerial.ToString() : "-");
        sb.Append("\tidx=").Append((r != null && r.IdAtScan.Ok) ? r.IdAtScan.Index.ToString() : "-");
        sb.Append("\trisk=").Append(Esc(r == null ? "" : r.Risk));
    }

    private static void AppendOutcomeFields(StringBuilder sb, string opId, string batchId, DeleteOutcome o)
    {
        AppendStamp(sb, DateTime.Now);
        sb.Append('\t').Append(OutcomeMark);
        sb.Append("\top=").Append(opId);
        sb.Append("\tbatch=").Append(batchId);
        sb.Append("\tstatus=").Append(o == null ? DeleteStatus.OutcomeUnknown.ToString() : o.Status.ToString());
        sb.Append("\tkind=").Append(o == null ? DeleteRefusalKind.None.ToString() : o.Kind.ToString());
        sb.Append("\tpath=").Append(Esc(o == null ? "" : o.Path));
        sb.Append("\tdetail=").Append(Esc(o == null ? "" : o.Detail));
    }

    private static void AppendStamp(StringBuilder sb, DateTime dt)
    {
        Append4Digits(sb, dt.Year);
        sb.Append('-');
        Append2Digits(sb, dt.Month);
        sb.Append('-');
        Append2Digits(sb, dt.Day);
        sb.Append(' ');
        Append2Digits(sb, dt.Hour);
        sb.Append(':');
        Append2Digits(sb, dt.Minute);
        sb.Append(':');
        Append2Digits(sb, dt.Second);
        sb.Append('.');
        Append3Digits(sb, dt.Millisecond);
    }

    private static void Append2Digits(StringBuilder sb, int v)
    {
        sb.Append((char)('0' + (v / 10) % 10));
        sb.Append((char)('0' + (v % 10)));
    }

    private static void Append3Digits(StringBuilder sb, int v)
    {
        sb.Append((char)('0' + (v / 100) % 10));
        sb.Append((char)('0' + (v / 10) % 10));
        sb.Append((char)('0' + (v % 10)));
    }

    private static void Append4Digits(StringBuilder sb, int v)
    {
        sb.Append((char)('0' + (v / 1000) % 10));
        sb.Append((char)('0' + (v / 100) % 10));
        sb.Append((char)('0' + (v / 10) % 10));
        sb.Append((char)('0' + (v % 10)));
    }

    private static bool Append(string logPath, string line, out string why)
    {
        why = "";
        if (String.IsNullOrEmpty(logPath)) { why = "未指定日志路径"; return false; }
        try
        {
            // 每条都强制落盘：断电/崩溃后「意图」与「结果」必须真的在磁盘上，才能事后核对。
            byte[] bytes = Encoding.UTF8.GetBytes(line + "\r\n");
            using (FileStream fs = new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
            {
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(true);
            }
            return true;
        }
        catch (Exception ex) { why = ex.GetType().Name + "：" + ex.Message; return false; }
    }

    private static string Stamp() { return DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"); }

    /// <summary>值转义：分隔符与反斜杠。</summary>
    public static string Esc(string s)
    {
        if (String.IsNullOrEmpty(s)) return "";
        StringBuilder b = new StringBuilder(s.Length + 8);
        foreach (char c in s)
        {
            if (c == '\\') b.Append("\\\\");
            else if (c == '\t') b.Append("\\t");
            else if (c == '\r') b.Append("\\r");
            else if (c == '\n') b.Append("\\n");
            else b.Append(c);
        }
        return b.ToString();
    }

    public static string Unesc(string s)
    {
        if (String.IsNullOrEmpty(s)) return "";
        StringBuilder b = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] != '\\' || i + 1 >= s.Length) { b.Append(s[i]); continue; }
            char n = s[++i];
            if (n == '\\') b.Append('\\');
            else if (n == 't') b.Append('\t');
            else if (n == 'r') b.Append('\r');
            else if (n == 'n') b.Append('\n');
            else { b.Append('\\'); b.Append(n); }
        }
        return b.ToString();
    }

    /// <summary>
    /// 崩溃后的恢复分析：返回"有 intent 无 outcome"的操作（opId → 目标路径）。
    /// 只报事实：不推断文件是否还在、不推断是否已删除、**绝不重试**。
    /// </summary>
    public static List<KeyValuePair<string, string>> PendingOps(string logPath)
    {
        List<KeyValuePair<string, string>> pending = new List<KeyValuePair<string, string>>();
        if (String.IsNullOrEmpty(logPath) || !File.Exists(logPath)) return pending;

        string[] lines = ReadLinesShared(logPath);
        if (lines == null) return pending;

        Dictionary<string, string> intents = new Dictionary<string, string>();
        List<string> order = new List<string>();
        HashSet<string> outcomes = new HashSet<string>();

        foreach (string raw in lines)
        {
            if (String.IsNullOrEmpty(raw)) continue;
            string[] parts = raw.Split('\t');
            if (parts.Length < 3) continue;
            string mark = parts[1];
            if (mark != IntentMark && mark != OutcomeMark) continue;

            string op = ""; string path = "";
            for (int i = 2; i < parts.Length; i++)
            {
                int eq = parts[i].IndexOf('=');
                if (eq <= 0) continue;
                string k = parts[i].Substring(0, eq);
                string v = parts[i].Substring(eq + 1);
                if (k == "op") op = v;
                else if (k == "path") path = Unesc(v);
            }
            if (op.Length == 0) continue;

            if (mark == IntentMark)
            {
                if (!intents.ContainsKey(op)) { intents[op] = path; order.Add(op); }
            }
            else outcomes.Add(op);
        }

        foreach (string op in order)
            if (!outcomes.Contains(op))
                pending.Add(new KeyValuePair<string, string>(op, intents[op]));
        return pending;
    }

    /// <summary>该日志里出现过的所有 op id（供测试核对"每项都有唯一 ID"）。</summary>
    public static List<string> AllOpIds(string logPath)
    {
        List<string> ids = new List<string>();
        if (String.IsNullOrEmpty(logPath) || !File.Exists(logPath)) return ids;
        string[] lines = ReadLinesShared(logPath);
        if (lines == null) return ids;
        foreach (string raw in lines)
        {
            if (String.IsNullOrEmpty(raw)) continue;
            string[] parts = raw.Split('\t');
            for (int i = 2; i < parts.Length; i++)
            {
                if (!parts[i].StartsWith("op=", StringComparison.Ordinal)) continue;
                string op = parts[i].Substring(3);
                if (op.Length > 0 && !ids.Contains(op)) ids.Add(op);
                break;
            }
        }
        return ids;
    }

    /// <summary>
    /// 仅当日志文件超过阈值且不存在任何未决中断操作（PendingOps == 0）时，
    /// 安全轮转为同目录下的单份 .old 归档备份。若存在任何未决记录则绝对禁止轮转。
    /// </summary>
    public static bool RotateIfOversizedAndClean(string logPath, long maxBytes)
    {
        if (String.IsNullOrEmpty(logPath) || maxBytes < 0) return false;
        try
        {
            FileInfo fi = new FileInfo(logPath);
            if (!fi.Exists || fi.Length <= maxBytes) return false;

            if (ReadLinesShared(logPath) == null) return false;

            List<KeyValuePair<string, string>> pending = PendingOps(logPath);
            if (pending == null || pending.Count > 0) return false;

            string dir = Path.GetDirectoryName(logPath) ?? "";
            string stem = Path.GetFileNameWithoutExtension(logPath);
            string ext = Path.GetExtension(logPath);
            string archiveName = String.IsNullOrEmpty(stem)
                ? "delete-log.old.txt"
                : (String.IsNullOrEmpty(ext) ? (stem + ".old") : (stem + ".old" + ext));
            string archivePath = String.IsNullOrEmpty(dir) ? archiveName : Path.Combine(dir, archiveName);

            using (new FileStream(logPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
            }

            if (File.Exists(archivePath))
            {
                File.Delete(archivePath);
            }
            File.Move(logPath, archivePath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string[] ReadLinesShared(string logPath)
    {
        try
        {
            List<string> list = new List<string>();
            using (FileStream fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    list.Add(line);
                }
            }
            return list.ToArray();
        }
        catch
        {
            return null;
        }
    }
}
