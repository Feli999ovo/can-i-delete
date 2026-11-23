using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

// =====================================================================
// 回收站行为防护（P0 第二轮）。
//
// 背景（已用 IL 与官方文档核实）：
//   Microsoft.VisualBasic 的 RecycleOption.SendToRecycleBin 最终调用
//   SHFileOperation，fFlags = FOF_NO_CONNECTED_ELEMENTS | FOF_NOCONFIRMMKDIR
//                       | FOF_NOCONFIRMATION | FOF_SILENT | FOF_ALLOWUNDO
//   —— 它 **不设置** FOF_WANTNUKEWARNING。
//   而微软对该标志的说明正是「文件被永久销毁而非回收时给出警告」，
//   即：FOF_ALLOWUNDO 只表示「尽量回收」，不保证一定回收。
//   当目标放不进回收站（体积超配额、单卷回收站被关闭、可移动/网络磁盘等）时，
//   Shell 会直接永久删除，且因为 FOF_SILENT|FOF_NOCONFIRMATION 而**不会提示**。
//
// 因此这里做两件事：
//   1) 调用之前：能判定「回收站不可保证」的一律拒绝（绝不尝试永久删除）。
//   2) 调用之后：去回收站元数据里找证据，找不到就报告「未确认」，
//      不再把「原路径消失」当成「已进入回收站」。
// =====================================================================

/// <summary>回收站可用性与事后取证。</summary>
public static class RecycleBinProbe
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string mountPoint, StringBuilder name, uint cch);

    // ---------- 调用之前：能否保证回收 ---------- //
    /// <summary>
    /// 派发前的可用性 / 容量预检（执行契约 v1）。
    ///
    /// 语义必须说清楚：这是**必要而非充分**条件。通过它**不等于**能成功回收。
    /// 本函数只能排除已知的“肯定回收不了”的情形。
    ///
    /// v1 相比旧版的变更：
    ///   * 配额**未知即拒绝**（旧版配额未知时只拦 &gt;1GiB，是 fail-open）；
    ///   * 体积不完整时拒绝（下界不得当上限用）；
    ///   * 拒绝理由细分为 kind，供前置拒绝矩阵逐条断言。
    ///
    /// 仍未解决的局限：只能用“卷配额总量”比，拿不到回收站**剩余**空间，
    /// 因此配额足够但回收站已满时仍可能不被回收 —— 这项只能靠事后取证发现。
    /// </summary>
    public static bool IsSupported(string path, long bytes, bool sizeComplete,
                                   out string reason, out DeleteRefusalKind kind)
    {
        reason = "";
        kind = DeleteRefusalKind.None;

        // 体积是下界就不允许做容量判断。
        if (!sizeComplete)
        {
            reason = "给的体积不完整（仅为已知下界），不能用于容量判断";
            kind = DeleteRefusalKind.DirSizeIncomplete;
            return false;
        }

        string canon = PathGuard.Canonical(path);
        if (canon.Length == 0)
        {
            kind = DeleteRefusalKind.PathNotCanonical;
            reason = "路径无法解析";
            return false;
        }
        if (!PathGuard.IsFixedLocalDrive(canon))
        {
            kind = DeleteRefusalKind.VolumeNotSupported;
            reason = "目标不在本地固定磁盘上（网络位置 / 可移动磁盘无法保证进入回收站）";
            return false;
        }

        string root = Path.GetPathRoot(canon);
        if (String.IsNullOrEmpty(root))
        {
            kind = DeleteRefusalKind.VolumeNotSupported;
            reason = "无法确定所属磁盘";
            return false;
        }

        string bin = Path.Combine(root, "$Recycle.Bin");
        if (!Directory.Exists(bin))
        {
            kind = DeleteRefusalKind.VolumeNotSupported;
            reason = "该磁盘上没有回收站目录（" + bin + "），删除会直接永久删除";
            return false;
        }

        if (NukeOnDelete(root))
        {
            kind = DeleteRefusalKind.NukeOnDelete;
            reason = "该磁盘的回收站设置为「不将文件移到回收站」，删除会直接永久删除";
            return false;
        }

        long quota = MaxCapacityBytes(root);
        if (quota <= 0)
        {
            // 未知即拒绝：拿不到配额就无法排除“放不进 ⇒ 被静默永久删除”。
            kind = DeleteRefusalKind.CapacityUnknown;
            reason = "无法确定该磁盘的回收站配额；无法排除目标被永久删除，已拒绝";
            return false;
        }
        if (bytes > quota)
        {
            kind = DeleteRefusalKind.CapacityInsufficient;
            reason = "目标体积（" + bytes + " 字节）超过该磁盘回收站配额（" + quota + " 字节），可能被永久删除";
            return false;
        }

        return true;
    }

    /// <summary>
    /// 旧签名保留（仅供不传完整性的既有调用点），**不应用于新的派发路径**。
    /// 它把 sizeComplete 当作 true，因此会在界上最保守地放行；
    /// 新代码请一律用四参数重载。
    /// </summary>
    public static bool IsSupported(string path, long bytes, out string reason)
    {
        DeleteRefusalKind k;
        return IsSupported(path, bytes, true, out reason, out k);
    }

    private static bool NukeOnDelete(string volumeRoot)
    {
        // 全局开关
        object global = ReadValue(@"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket", "NukeOnDelete");
        if (ToLong(global) == 1) return true;

        string guid = VolumeGuid(volumeRoot);
        if (guid.Length == 0) return false;      // 读不到就交给事后取证兜底
        object perVol = ReadValue(
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\" + guid, "NukeOnDelete");
        return ToLong(perVol) == 1;
    }

    /// <summary>
    /// 仅供自动化测试注入回收站配额。产品代码不设置。
    ///   0  = 读注册表实际值（正常情况）
    ///   &gt;0= 强制按该值（字节）
    ///   -1 = 强制“配额未知”，用于覆盖该分支
    /// </summary>
    public static long QuotaOverrideBytes = 0;

    /// <summary>该卷回收站容量上限（字节）。0 表示未知，不做体积判断。</summary>
    private static long MaxCapacityBytes(string volumeRoot)
    {
        if (QuotaOverrideBytes == -1) return 0;
        if (QuotaOverrideBytes > 0) return QuotaOverrideBytes;

        long mb = 0;
        string guid = VolumeGuid(volumeRoot);
        if (guid.Length > 0)
            mb = ToLong(ReadValue(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\" + guid, "MaxCapacity"));
        if (mb <= 0)
            mb = ToLong(ReadValue(@"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket", "MaxCapacity"));
        if (mb <= 0) return 0;
        return mb * 1024L * 1024L;
    }

    /// <summary>
    /// 把 "\\?\Volume{guid}\" 转成注册表键名 "{guid}"。
    /// 注意：BitBucket\Volume 下的子键名只有花括号部分，**不含** "Volume" 前缀；
    /// 早期版本拼成 "Volume{guid}" 导致 NukeOnDelete / MaxCapacity 永远查不到，
    /// 安全检查会静默失效。已改为可测函数并有回归用例。
    /// </summary>
    public static string VolumeKeyName(string volumeRoot)
    {
        try
        {
            if (String.IsNullOrEmpty(volumeRoot)) return "";
            string mount = volumeRoot;
            if (!mount.EndsWith("\\", StringComparison.Ordinal)) mount += "\\";
            StringBuilder sb = new StringBuilder(64);
            if (!GetVolumeNameForVolumeMountPointW(mount, sb, (uint)sb.Capacity)) return "";
            string s = sb.ToString();
            int i = s.IndexOf('{');
            if (i < 0) return "";
            int j = s.IndexOf('}', i);
            return j > i ? s.Substring(i, j - i + 1) : "";
        }
        catch { return ""; }
    }

    private static string VolumeGuid(string volumeRoot)
    {
        return VolumeKeyName(volumeRoot);
    }

    private static object ReadValue(string subKey, string name)
    {
        try
        {
            using (RegistryKey k = Registry.CurrentUser.OpenSubKey(subKey, false))
            {
                if (k == null) return null;
                return k.GetValue(name);
            }
        }
        catch { return null; }
    }

    private static long ToLong(object o)
    {
        if (o == null) return 0;
        try { return Convert.ToInt64(o); }
        catch { return 0; }
    }

    // ---------- 调用之后：是否真的进了回收站 ---------- //
    /// <summary>回收站中一条记录。</summary>
    public sealed class BinEntry
    {
        public string OriginalPath = "";
        public long Size;
        public DateTime DeletedUtc;
        public string MetadataFile = "";
        public string PayloadFile = "";
    }

    /// <summary>
    /// 在目标所在卷的回收站元数据里查找“本次删除”留下的记录。
    ///
    /// 必须同时匹配三件事，否则不得作为证据：
    ///   1) 原路径；
    ///   2) 体积（目录可用负数跳过）；
    ///   3) 删除时间晚于本次调用发起之前若干秒。
    /// 原因（实测）：E: 盘存在 464 个 $I 元数据但只有 1 个 $R 内容项，
    /// 即大量陈旧元数据残留；只看路径会把历史记录当成新删除的证据。
    /// </summary>
    public static bool Confirm(string path, long expectedBytes, DateTime notBeforeUtc,
                               out string evidence, out bool inconclusive)
    {
        evidence = "";
        inconclusive = false;

        string canon = PathGuard.Canonical(path);
        string root = Path.GetPathRoot(canon);
        if (String.IsNullOrEmpty(root)) { inconclusive = true; return false; }

        string bin = Path.Combine(root, "$Recycle.Bin");
        string[] dirs;
        try
        {
            if (!Directory.Exists(bin)) { inconclusive = true; return false; }
            dirs = Directory.GetDirectories(bin);
        }
        catch { inconclusive = true; return false; }

        if (dirs.Length == 0) { inconclusive = true; return false; }

        bool scannedAny = false;
        foreach (string dir in dirs)
        {
            string[] meta;
            try { meta = Directory.GetFiles(dir, "$I*"); }
            catch { continue; }
            foreach (string m in meta)
            {
                scannedAny = true;
                BinEntry e = ParseMetadata(m);
                if (e == null) continue;
                if (!string.Equals(PathGuard.Canonical(e.OriginalPath), canon, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (expectedBytes >= 0 && e.Size != expectedBytes) continue;          // 体积不符 → 可能不是本次
                if (e.DeletedUtc != DateTime.MinValue
                    && e.DeletedUtc < notBeforeUtc.AddSeconds(-5)) continue;           // 太旧 → 陈旧记录

                // $R 内容项与 $I 同目录同名尾
                string payload = Path.Combine(Path.GetDirectoryName(m),
                    "$R" + Path.GetFileName(m).Substring(2));
                e.MetadataFile = m;
                e.PayloadFile = (File.Exists(payload) || Directory.Exists(payload)) ? payload : "";
                evidence = "回收站记录 " + Path.GetFileName(m)
                         + "，原路径 " + e.OriginalPath
                         + "，大小 " + e.Size + "B，删除时间 " + e.DeletedUtc.ToString("u")
                         + (e.PayloadFile.Length > 0
                            ? "，内容项 " + Path.GetFileName(e.PayloadFile)
                            : "，内容项未找到（可能已被清理，但元数据与本次匹配）");
                return true;
            }
        }

        if (!scannedAny) inconclusive = true;
        return false;
    }

    /// <summary>解析 $I 元数据文件（版本 1：固定 260 宽字符；版本 2：长度前缀）。</summary>
    public static BinEntry ParseMetadata(string file)
    {
        byte[] b;
        try
        {
            FileInfo fi = new FileInfo(file);
            if (fi.Length < 24) return null;
            int len = (int)Math.Min(fi.Length, 4096);
            b = new byte[len];
            using (FileStream fs = File.OpenRead(file))
            {
                int read = 0;
                while (read < len)
                {
                    int n = fs.Read(b, read, len - read);
                    if (n <= 0) break;
                    read += n;
                }
            }
            if (b.Length < 24) return null;
        }
        catch { return null; }

        BinEntry e = new BinEntry();
        long version = BitConverter.ToInt64(b, 0);
        e.Size = BitConverter.ToInt64(b, 8);
        long ticks = BitConverter.ToInt64(b, 16);
        try { e.DeletedUtc = DateTime.FromFileTimeUtc(ticks); }
        catch { e.DeletedUtc = DateTime.MinValue; }

        string path = "";
        if (version >= 2)
        {
            if (b.Length >= 28)
            {
                int chars = BitConverter.ToInt32(b, 24);
                if (chars > 0)
                {
                    int avail = Math.Min(chars, (b.Length - 28) / 2);
                    if (avail > 0) path = Encoding.Unicode.GetString(b, 28, avail * 2);
                }
            }
        }
        else
        {
            int avail = Math.Min(260, (b.Length - 24) / 2);
            if (avail > 0) path = Encoding.Unicode.GetString(b, 24, avail * 2);
        }

        int nul = path.IndexOf('\0');
        if (nul >= 0) path = path.Substring(0, nul);
        e.OriginalPath = path;
        return e;
    }
}
