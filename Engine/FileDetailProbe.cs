using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>单文件技术详情快照（按需只读探测，供文件详情抽屉展示）。</summary>
public sealed class FileTechInfo
{
    public string Created = "未读取";
    public string Accessed = "未读取";
    public string Attributes = "未读取";
    public string Process = "未读取";
}

/// <summary>
/// 按需读取单个文件的真实创建时间、最后访问时间、属性组合及占用进程。
/// 全程只读：使用 FileInfo 读取元数据，使用 Windows Restart Manager 查询占用进程，绝不修改目标文件。
/// </summary>
public static class FileDetailProbe
{
    private const int ERROR_SUCCESS = 0;
    private const int ERROR_MORE_DATA = 234;
    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    private enum RM_APP_TYPE
    {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, StringBuilder strSessionKey);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint dwSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, IntPtr rgApplications, uint nServices, string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded,
        ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint dwSessionHandle);

    public static FileTechInfo Inspect(string path)
    {
        FileTechInfo info = new FileTechInfo();
        if (string.IsNullOrEmpty(path) || path.Trim().Length == 0)
        {
            info.Created = "无法读取";
            info.Accessed = "无法读取";
            info.Attributes = "无法读取";
            info.Process = "无法读取";
            return info;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch
        {
            info.Created = "无法读取";
            info.Accessed = "无法读取";
            info.Attributes = "无法读取";
            info.Process = "无法读取";
            return info;
        }

        FileInfo fi = null;
        bool existsAsFile = false;
        try
        {
            fi = new FileInfo(fullPath);
            existsAsFile = fi.Exists;
        }
        catch
        {
            existsAsFile = false;
        }

        if (!existsAsFile || fi == null)
        {
            info.Created = "无法读取";
            info.Accessed = "无法读取";
            info.Attributes = "无法读取";
            info.Process = "无法读取";
            return info;
        }

        try
        {
            DateTime createdUtc = fi.CreationTimeUtc;
            info.Created = (createdUtc == DateTime.MinValue || createdUtc.Year <= 1601)
                ? "无法读取"
                : createdUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        }
        catch
        {
            info.Created = "无法读取";
        }

        try
        {
            DateTime accessedUtc = fi.LastAccessTimeUtc;
            info.Accessed = (accessedUtc == DateTime.MinValue || accessedUtc.Year <= 1601)
                ? "无法读取"
                : accessedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        }
        catch
        {
            info.Accessed = "无法读取";
        }

        try
        {
            FileAttributes attr = fi.Attributes;
            if ((int)attr == -1)
            {
                info.Attributes = "无法读取";
            }
            else
            {
                info.Attributes = FormatAttributes(attr);
            }
        }
        catch
        {
            info.Attributes = "无法读取";
        }

        info.Process = ProbeLockingProcesses(fullPath);
        return info;
    }

    private static string FormatAttributes(FileAttributes attr)
    {
        List<string> tags = new List<string>();
        if ((attr & FileAttributes.ReadOnly) != 0) tags.Add("只读");
        if ((attr & FileAttributes.Hidden) != 0) tags.Add("隐藏");
        if ((attr & FileAttributes.System) != 0) tags.Add("系统");
        if ((attr & FileAttributes.Compressed) != 0) tags.Add("压缩");
        if ((attr & FileAttributes.Encrypted) != 0) tags.Add("加密");
        if ((attr & FileAttributes.Temporary) != 0) tags.Add("临时");
        if ((attr & FileAttributes.ReparsePoint) != 0) tags.Add("重解析点");
        if ((attr & FileAttributes.Offline) != 0) tags.Add("脱机");
        if ((attr & FileAttributes.Archive) != 0) tags.Add("存档");
        if (tags.Count == 0) return "普通文件";
        return String.Join("、", tags.ToArray());
    }

    private static string ProbeLockingProcesses(string fullPath)
    {
        uint sessionHandle = 0;
        bool sessionStarted = false;
        try
        {
            StringBuilder key = new StringBuilder(64);
            int startRc = RmStartSession(out sessionHandle, 0, key);
            if (startRc != ERROR_SUCCESS) return "无法读取";
            sessionStarted = true;

            string[] resources = new string[] { fullPath };
            int regRc = RmRegisterResources(sessionHandle, 1u, resources, 0u, IntPtr.Zero, 0u, null);
            if (regRc != ERROR_SUCCESS) return "无法读取";

            uint needed = 0;
            uint count = 0;
            uint rebootReasons = 0;
            int listRc = RmGetList(sessionHandle, out needed, ref count, null, ref rebootReasons);
            if (listRc == ERROR_SUCCESS && needed == 0) return "未占用";

            RM_PROCESS_INFO[] procInfos = null;
            for (int attempt = 0; attempt < 3 && listRc == ERROR_MORE_DATA; attempt++)
            {
                count = needed + 4u;
                procInfos = new RM_PROCESS_INFO[count];
                listRc = RmGetList(sessionHandle, out needed, ref count, procInfos, ref rebootReasons);
                if (listRc == ERROR_SUCCESS) break;
            }

            if (listRc != ERROR_SUCCESS) return "无法读取";
            if (count == 0 || procInfos == null) return "未占用";

            List<string> results = new List<string>();
            HashSet<int> seenPids = new HashSet<int>();
            int limit = (int)Math.Min((uint)procInfos.Length, count);
            for (int i = 0; i < limit; i++)
            {
                int pid = procInfos[i].Process.dwProcessId;
                if (pid <= 0 || !seenPids.Add(pid)) continue;
                results.Add(FormatProcessEntry(pid, procInfos[i]));
                if (results.Count >= 3) break;
            }

            if (results.Count == 0) return "未占用";
            return String.Join("、", results.ToArray());
        }
        catch
        {
            return "无法读取";
        }
        finally
        {
            if (sessionStarted)
            {
                try { RmEndSession(sessionHandle); } catch { }
            }
        }
    }

    private static string FormatProcessEntry(int pid, RM_PROCESS_INFO info)
    {
        string name = "";
        try
        {
            using (Process p = Process.GetProcessById(pid))
            {
                if (!string.IsNullOrEmpty(p.ProcessName))
                {
                    name = p.ProcessName.Trim();
                    if (name.Length > 0 && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        name = name + ".exe";
                    }
                }
            }
        }
        catch
        {
        }

        if (name.Length == 0 && !string.IsNullOrEmpty(info.strAppName))
        {
            name = info.strAppName.Trim();
        }
        if (name.Length == 0 && !string.IsNullOrEmpty(info.strServiceShortName))
        {
            name = info.strServiceShortName.Trim();
        }
        if (name.Length == 0)
        {
            name = "进程";
        }

        return name + " (PID " + pid + ")";
    }
}
