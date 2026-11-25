using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

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
//   * 所有写/读/轮转均经不跟随重解析点句柄核验最终真实路径与硬链接数，
//     消除符号链接/目录联接点重定向追加或删除任意文件的风险。
//
// 格式：制表符分隔的 key=value，行首标记 I / O。
//      对 op / batch / path / risk / detail 统一转义 \\ \t \r \n，
//      解析按**第一个** '=' 切分，杜绝字段与换行注入。
// =====================================================================

public static class DeleteLog
{
    public const string IntentMark = "I";
    public const string OutcomeMark = "O";
    public const long DefaultRotateBytes = 5L * 1024 * 1024;

    private static readonly IntPtr INVALID = new IntPtr(-1);
    private const uint DELETE = 0x00010000;
    private const uint FILE_READ_ATTRIBUTES = 0x80;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x01;
    private const uint FILE_SHARE_WRITE = 0x02;
    private const uint FILE_SHARE_DELETE = 0x04;
    private const uint OPEN_EXISTING = 3;
    private const uint OPEN_ALWAYS = 4;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    private const int FileRenameInfo = 3;
    private const int ERROR_FILE_NOT_FOUND = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint dwFileAttributes, ftCreationLow, ftCreationHigh, ftAccessLow, ftAccessHigh, ftWriteLow, ftWriteHigh;
        public uint dwVolumeSerialNumber, nFileSizeHigh, nFileSizeLow, nNumberOfLinks, nFileIndexHigh, nFileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(IntPtr h, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(IntPtr h, int cls, IntPtr info, uint size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    /// <summary>每项操作一个唯一 ID。</summary>
    public static string NewOpId() { return Guid.NewGuid().ToString("N"); }

    /// <summary>
    /// 可复用的批量删除审计写入会话：贯穿整个批次只打开一次经无重解析点与最终路径核验的文件句柄。
    /// 每次写入立即刷新至操作系统页缓存（进程崩溃可保留），并每 32 次写入、遇到
    /// OutcomeUnknown / PendingReconciliation 以及 Dispose 时执行 Flush(true) 强制落盘，
    /// 在高吞吐与掉电可恢复性之间保持平衡。
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
                    if ((writeCount & 31) == 0) fs.Flush(true);
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
                    bool hardFlush = ((writeCount & 31) == 0)
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

    private static FileStream OpenVerifiedNoReparse(
        string logPath,
        uint access,
        uint share,
        uint disposition,
        uint flags,
        FileAccess managedAccess,
        int bufferSize,
        bool ensureParentDir,
        bool seekToEnd,
        out string why)
    {
        why = "";
        if (String.IsNullOrEmpty(logPath))
        {
            why = "未指定日志路径";
            return null;
        }
        string canon = PathGuard.Canonical(logPath);
        if (canon.Length == 0 || !PathGuard.IsLocalDrivePath(canon))
        {
            why = "日志路径无效（仅支持本地磁盘路径）";
            return null;
        }

        string dir = null;
        try { dir = Path.GetDirectoryName(canon); }
        catch { dir = null; }
        if (String.IsNullOrEmpty(dir))
        {
            why = "无法确定日志父目录";
            return null;
        }
        if (PathGuard.HasAnyReparseComponent(dir))
        {
            why = "日志所在目录链包含符号链接或重解析点";
            return null;
        }

        if (ensureParentDir && !Directory.Exists(dir))
        {
            try { Directory.CreateDirectory(dir); }
            catch (Exception ex)
            {
                why = ex.GetType().Name + "：" + ex.Message;
                return null;
            }
            if (PathGuard.HasAnyReparseComponent(dir))
            {
                why = "创建日志目录后检测到重解析点";
                return null;
            }
        }

        IntPtr h = CreateFileW(canon, access, share, IntPtr.Zero, disposition,
                               flags | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (h == INVALID || h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            why = "打开日志文件失败（" + new Win32Exception(err).Message + "）";
            return null;
        }

        bool ownershipTransferred = false;
        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info))
            {
                why = "无法读取日志文件句柄信息";
                return null;
            }
            if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
            {
                why = "日志路径指向目录或重解析点";
                return null;
            }
            if (info.nNumberOfLinks > 1)
            {
                why = "日志文件存在多个硬链接";
                return null;
            }

            string actualFinal;
            string expectedLong;
            if (!PathGuard.TryGetFinalDosPath(h, out actualFinal)
                || !PathGuard.TryGetLongCanonicalPath(canon, out expectedLong)
                || !String.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
            {
                why = "日志文件真实路径与目标路径不一致（存在重解析点或重定向）";
                return null;
            }

            SafeFileHandle sfh = new SafeFileHandle(h, true);
            ownershipTransferred = true;
            try
            {
                FileStream fs = new FileStream(sfh, managedAccess, bufferSize, false);
                if (seekToEnd) fs.Seek(0, SeekOrigin.End);
                return fs;
            }
            catch (Exception ex)
            {
                try { sfh.Dispose(); } catch { }
                why = ex.GetType().Name + "：" + ex.Message;
                return null;
            }
        }
        finally
        {
            if (!ownershipTransferred)
            {
                CloseHandle(h);
            }
        }
    }

    /// <summary>
    /// 打开批量审计日志会话并执行初始可写性落盘探测；不可写或路径含重解析点时返回 null 并填入原因。
    /// </summary>
    public static WriterSession OpenSession(string logPath, out string why)
    {
        FileStream stream = OpenVerifiedNoReparse(
            logPath,
            GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            OPEN_ALWAYS,
            0,
            FileAccess.Write,
            16384,
            true,
            true,
            out why);
        if (stream == null) return null;

        try
        {
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
        using (FileStream fs = OpenVerifiedNoReparse(
            logPath,
            GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            OPEN_ALWAYS,
            0,
            FileAccess.Write,
            4096,
            true,
            true,
            out why))
        {
            if (fs == null) return false;
            try
            {
                byte[] probe = Encoding.UTF8.GetBytes("# writability-probe\r\n");
                fs.Write(probe, 0, probe.Length);
                fs.Flush(true);            // 落盘，而不是留在缓冲区
                return true;
            }
            catch (Exception ex)
            {
                why = ex.GetType().Name + "：" + ex.Message;
                return false;
            }
        }
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
        sb.Append("\top=").Append(Esc(opId));
        sb.Append("\tbatch=").Append(Esc(batchId));
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
        sb.Append("\top=").Append(Esc(opId));
        sb.Append("\tbatch=").Append(Esc(batchId));
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
        using (FileStream fs = OpenVerifiedNoReparse(
            logPath,
            GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            OPEN_ALWAYS,
            FILE_FLAG_WRITE_THROUGH,
            FileAccess.Write,
            4096,
            true,
            true,
            out why))
        {
            if (fs == null) return false;
            try
            {
                // 每条都强制落盘：断电/崩溃后「意图」与「结果」必须真的在磁盘上，才能事后核对。
                byte[] bytes = Encoding.UTF8.GetBytes(line + "\r\n");
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(true);
                return true;
            }
            catch (Exception ex)
            {
                why = ex.GetType().Name + "：" + ex.Message;
                return false;
            }
        }
    }

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

    private static List<KeyValuePair<string, string>> ParsePendingOpsFromReader(StreamReader sr)
    {
        Dictionary<string, string> intents = new Dictionary<string, string>();
        List<string> order = new List<string>();
        HashSet<string> outcomes = new HashSet<string>();

        string raw;
        while ((raw = sr.ReadLine()) != null)
        {
            if (raw.Length == 0) continue;
            string[] parts = raw.Split('\t');
            if (parts.Length < 3) continue;
            string mark = parts[1];
            if (mark != IntentMark && mark != OutcomeMark) continue;

            string op = "";
            string path = "";
            for (int i = 2; i < parts.Length; i++)
            {
                int eq = parts[i].IndexOf('=');
                if (eq <= 0) continue;
                string k = parts[i].Substring(0, eq);
                string v = parts[i].Substring(eq + 1);
                if (k == "op") op = Unesc(v);
                else if (k == "path") path = Unesc(v);
            }
            if (op.Length == 0) continue;

            if (mark == IntentMark)
            {
                if (!intents.ContainsKey(op)) { intents[op] = path; order.Add(op); }
            }
            else
            {
                outcomes.Add(op);
            }
        }

        List<KeyValuePair<string, string>> pending = new List<KeyValuePair<string, string>>();
        foreach (string op in order)
            if (!outcomes.Contains(op))
                pending.Add(new KeyValuePair<string, string>(op, intents[op]));
        return pending;
    }

    private static bool TryCheckExistingNonReparseLogFile(string canon, out bool exists, out string error)
    {
        exists = false;
        error = "";
        try
        {
            FileAttributes attrs = File.GetAttributes(canon);
            if ((attrs & FileAttributes.ReparsePoint) != 0)
            {
                error = "日志文件为符号链接或重解析点";
                return false;
            }
            if ((attrs & FileAttributes.Directory) != 0)
            {
                error = "日志路径指向目录而非普通文件";
                return false;
            }
            exists = true;
            return true;
        }
        catch (FileNotFoundException)
        {
            exists = false;
            return true;
        }
        catch (DirectoryNotFoundException)
        {
            exists = false;
            return true;
        }
        catch (Exception ex)
        {
            error = "无法读取日志属性：" + ex.GetType().Name;
            return false;
        }
    }

    /// <summary>
    /// 可失败关闭的未决操作流式解析：供需要区分“无未决项”与“日志不可读/含重解析点”的调用方使用。
    /// 日志不存在时返回 true 与空列表；读取失败或含重解析点（含悬空符号链接）时返回 false 并给出错误说明。
    /// </summary>
    public static bool TryPendingOps(string logPath, out List<KeyValuePair<string, string>> pending, out string error)
    {
        pending = new List<KeyValuePair<string, string>>();
        error = "";
        if (String.IsNullOrEmpty(logPath))
        {
            error = "未指定日志路径";
            return false;
        }
        string canon = PathGuard.Canonical(logPath);
        if (canon.Length == 0 || !PathGuard.IsLocalDrivePath(canon))
        {
            error = "日志路径无效";
            return false;
        }
        string dir = null;
        try { dir = Path.GetDirectoryName(canon); }
        catch { dir = null; }
        if (!String.IsNullOrEmpty(dir) && PathGuard.HasAnyReparseComponent(dir))
        {
            error = "日志上级目录包含重解析点";
            return false;
        }
        bool logExists;
        if (!TryCheckExistingNonReparseLogFile(canon, out logExists, out error))
        {
            pending = null;
            return false;
        }
        if (!logExists)
        {
            return true;
        }

        string openErr;
        using (FileStream fs = OpenVerifiedNoReparse(
            canon,
            GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            0,
            FileAccess.Read,
            16384,
            false,
            false,
            out openErr))
        {
            if (fs == null)
            {
                pending = null;
                error = openErr;
                return false;
            }
            try
            {
                using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                {
                    pending = ParsePendingOpsFromReader(sr);
                    return true;
                }
            }
            catch (Exception ex)
            {
                pending = null;
                error = ex.GetType().Name + "：" + ex.Message;
                return false;
            }
        }
    }

    /// <summary>
    /// 崩溃后的恢复分析：返回"有 intent 无 outcome"的操作（opId → 目标路径）。
    /// 只报事实：不推断文件是否还在、不推断是否已删除、**绝不重试**。
    /// </summary>
    public static List<KeyValuePair<string, string>> PendingOps(string logPath)
    {
        List<KeyValuePair<string, string>> pending;
        string error;
        if (!TryPendingOps(logPath, out pending, out error) || pending == null)
            return new List<KeyValuePair<string, string>>();
        return pending;
    }

    /// <summary>该日志里出现过的所有 op id（流式逐行解析，供测试核对"每项都有唯一 ID"）。</summary>
    public static List<string> AllOpIds(string logPath)
    {
        List<string> ids = new List<string>();
        if (String.IsNullOrEmpty(logPath)) return ids;
        string canon = PathGuard.Canonical(logPath);
        if (canon.Length == 0 || !PathGuard.IsLocalDrivePath(canon)) return ids;
        bool logExists;
        string attrErr;
        if (!TryCheckExistingNonReparseLogFile(canon, out logExists, out attrErr) || !logExists)
            return ids;

        string openErr;
        using (FileStream fs = OpenVerifiedNoReparse(
            canon,
            GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            OPEN_EXISTING,
            0,
            FileAccess.Read,
            16384,
            false,
            false,
            out openErr))
        {
            if (fs == null) return ids;
            try
            {
                HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
                using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                {
                    string raw;
                    while ((raw = sr.ReadLine()) != null)
                    {
                        if (raw.Length == 0) continue;
                        string[] parts = raw.Split('\t');
                        for (int i = 2; i < parts.Length; i++)
                        {
                            if (!parts[i].StartsWith("op=", StringComparison.Ordinal)) continue;
                            string op = Unesc(parts[i].Substring(3));
                            if (op.Length > 0 && seen.Add(op)) ids.Add(op);
                            break;
                        }
                    }
                }
            }
            catch { }
        }
        return ids;
    }

    /// <summary>
    /// 仅当日志文件超过阈值且不存在任何未决中断操作（PendingOps == 0）时，
    /// 在持有独占无重解析点文件句柄的同一锁域内流式核验并原子重命名为 .old 归档备份。
    /// 若存在任何未决记录、并发占用或重解析点则绝对禁止轮转。
    /// </summary>
    public static bool RotateIfOversizedAndClean(string logPath, long maxBytes)
    {
        if (String.IsNullOrEmpty(logPath) || maxBytes < 0) return false;
        string canon = PathGuard.Canonical(logPath);
        if (canon.Length == 0 || !PathGuard.IsLocalDrivePath(canon)) return false;

        string dir = null;
        try { dir = Path.GetDirectoryName(canon); }
        catch { dir = null; }
        if (String.IsNullOrEmpty(dir) || PathGuard.HasAnyReparseComponent(dir)) return false;

        IntPtr h = CreateFileW(
            canon,
            DELETE | GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            0,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);
        if (h == INVALID || h == IntPtr.Zero) return false;

        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) return false;
            if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
                return false;
            if (info.nNumberOfLinks > 1) return false;

            string actualFinal;
            string expectedLong;
            if (!PathGuard.TryGetFinalDosPath(h, out actualFinal)
                || !PathGuard.TryGetLongCanonicalPath(canon, out expectedLong)
                || !String.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
                return false;

            long fileSize = ((long)info.nFileSizeHigh << 32) | info.nFileSizeLow;
            if (fileSize <= maxBytes) return false;

            // 在独占句柄上直接流式检查 PendingOps（ownsHandle=false，解析完毕仍保持独占锁）。
            List<KeyValuePair<string, string>> pending;
            using (FileStream fs = new FileStream(new SafeFileHandle(h, false), FileAccess.Read, 16384, false))
            using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
            {
                pending = ParsePendingOpsFromReader(sr);
            }
            if (pending == null || pending.Count > 0) return false;

            string stem = Path.GetFileNameWithoutExtension(canon);
            string ext = Path.GetExtension(canon);
            string archiveName = String.IsNullOrEmpty(stem)
                ? "delete-log.old.txt"
                : (String.IsNullOrEmpty(ext) ? (stem + ".old") : (stem + ".old" + ext));
            string archivePath = Path.Combine(dir, archiveName);

            if (!IsArchiveTargetSafe(archivePath)) return false;

            return RenameHandleReplaceIfExists(h, archivePath);
        }
        catch
        {
            return false;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private static bool IsArchiveTargetSafe(string archivePath)
    {
        string canonArchive = PathGuard.Canonical(archivePath);
        if (canonArchive.Length == 0 || !PathGuard.IsLocalDrivePath(canonArchive)) return false;

        IntPtr h = CreateFileW(
            canonArchive,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);
        if (h == INVALID || h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return err == ERROR_FILE_NOT_FOUND;
        }
        try
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(h, out info)) return false;
            if ((info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
                return false;
            if (info.nNumberOfLinks > 1) return false;

            string actualFinal;
            string expectedLong;
            if (!PathGuard.TryGetFinalDosPath(h, out actualFinal)
                || !PathGuard.TryGetLongCanonicalPath(canonArchive, out expectedLong)
                || !String.Equals(actualFinal, expectedLong, StringComparison.OrdinalIgnoreCase))
                return false;

            return true;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private static bool RenameHandleReplaceIfExists(IntPtr handle, string destFullPath)
    {
        byte[] nameBytes = Encoding.Unicode.GetBytes(destFullPath);
        int headerSize = IntPtr.Size * 2 + 4;
        int totalSize = headerSize + nameBytes.Length + 2;
        IntPtr buf = Marshal.AllocHGlobal(totalSize);
        try
        {
            for (int i = 0; i < headerSize; i++) Marshal.WriteByte(buf, i, 0);
            Marshal.WriteByte(buf, 0, 1);                             // ReplaceIfExists = TRUE
            Marshal.WriteIntPtr(buf, IntPtr.Size, IntPtr.Zero);       // RootDirectory = NULL
            Marshal.WriteInt32(buf, IntPtr.Size * 2, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, new IntPtr(buf.ToInt64() + headerSize), nameBytes.Length);
            Marshal.WriteInt16(buf, headerSize + nameBytes.Length, 0);
            return SetFileInformationByHandle(handle, FileRenameInfo, buf, (uint)totalSize);
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }
}
