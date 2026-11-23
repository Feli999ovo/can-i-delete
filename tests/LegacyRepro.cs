using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

// 旧漏洞复现用例（P0 回归基线）。
//
// 本文件断言的是「应当具备的安全行为」，而不是「当前行为」。
// 在 P0 整改之前它整体 FAIL（7 条 S1-1 路径片段误判）—— 那批失败就是漏洞的自动化证据。
// 整改完成后，同一文件必须全绿。
//
// 覆盖两个层次：
//   规则层  EvidenceRules.Evaluate   —— 名字/路径 是否还能单独判出「安全」
//   策略层  SafetyPolicy.Decide      —— 在受控范围与实时状态下是否仍会误授权
//
// 编译与运行：见 tests\run-tests.bat
static class LegacyRepro
{
    static int total, failed;

    static ScanItem Item(string fullPath, int days)
    {
        ScanItem it = new ScanItem();
        it.Path = fullPath;
        it.Name = Path.GetFileName(fullPath);
        it.IsDirectory = false;
        it.Days = days;
        it.IsReparse = false;          // 显式给出，避免因文件不存在而被判为重解析点
        it.LastWriteUtc = DateTime.UtcNow;
        return it;
    }

    /// <summary>断言：该文件不得被判为「安全」（分级层面）。</summary>
    static void ExpectNotSafe(string id, string name, string fullPath, int days)
    {
        total++;
        Evidence rules = EvidenceRules.Evaluate(name, fullPath, days);
        Evidence policy = SafetyPolicy.Decide(Item(fullPath, days), LockState.Free);
        if (rules.Risk == "安全" || policy.Risk == "安全")
        {
            failed++;
            Console.WriteLine("FAIL " + id + "  误判为安全 | 规则层=" + rules.Risk + " 策略层=" + policy.Risk +
                              " | " + fullPath);
        }
        else
        {
            Console.WriteLine("PASS " + id + "  规则层=" + rules.Risk + " 策略层=" + policy.Risk + " | " + fullPath);
        }
    }

    /// <summary>断言：该文件不得获得删除授权（用于受控范围之外的路径）。</summary>
    static void ExpectNotAuthorized(string id, string name, string fullPath, int days)
    {
        total++;
        Evidence policy = SafetyPolicy.Decide(Item(fullPath, days), LockState.Free);
        if (policy.PolicyEligible)
        {
            failed++;
            Console.WriteLine("FAIL " + id + "  错误地获得了删除授权 | 分级=" + policy.Risk + " | " + fullPath);
        }
        else
        {
            Console.WriteLine("PASS " + id + "  未授权（" + policy.Risk + "） | " + fullPath);
        }
    }

    /// <summary>断言：受控临时目录内的真实缓存仍应判为「安全」并获授权（避免「一律拒绝」）。</summary>
    static void ExpectSafe(string id, string name, string fullPath, int days)
    {
        total++;
        Evidence policy = SafetyPolicy.Decide(Item(fullPath, days), LockState.Free);
        if (policy.Risk == "安全" && policy.PolicyEligible)
        {
            Console.WriteLine("PASS " + id + "  " + policy.Risk + " 已授权 | " + fullPath);
        }
        else
        {
            failed++;
            Console.WriteLine("FAIL " + id + "  期望 安全+授权，实得 " + policy.Risk +
                              " 授权=" + policy.PolicyEligible + " | " + fullPath);
        }
    }

    static int Main()
    {
        // 测试沙盒默认在系统临时目录；可用 CANIDELETE_TEST_ROOT 指向明确授权的测试盘
        // （例如 E 盘测试目录）。只在自建目录内创建/删除，不碰其他用户目录。
        string tmp = Environment.GetEnvironmentVariable("CANIDELETE_TEST_ROOT");
        if (String.IsNullOrEmpty(tmp)) tmp = Path.GetTempPath();
        Console.WriteLine("test root = " + tmp);
        string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        Console.WriteLine("== S1-1 路径片段导致的误判（用户数据被当成缓存） ==");
        ExpectNotSafe("S1-1a", "季度报告.docx", Path.Combine(user, "Documents", "yarn-项目", "季度报告.docx"), 400);
        ExpectNotAuthorized("S1-1a*", "季度报告.docx", Path.Combine(user, "Documents", "yarn-项目", "季度报告.docx"), 400);
        ExpectNotSafe("S1-1b", "notes.log", @"D:\installer notes\notes.log", 400);
        ExpectNotSafe("S1-1c", "photo.dmp", Path.Combine(user, "Downloads", "photo.dmp"), 400);
        ExpectNotAuthorized("S1-1c*", "photo.dmp", Path.Combine(user, "Downloads", "photo.dmp"), 400);
        ExpectNotSafe("S1-1d", "合同.docx", Path.Combine(user, "Documents", "_cacache备份", "合同.docx"), 400);
        ExpectNotSafe("S1-1e", "thumbcache_notes.txt", Path.Combine(user, "Documents", "thumbcache_notes.txt"), 400);
        ExpectNotAuthorized("S1-1e*", "thumbcache_notes.txt", Path.Combine(user, "Documents", "thumbcache_notes.txt"), 400);
        ExpectNotSafe("S1-1f", "客户资料.xlsx", Path.Combine(user, "Documents", "钉钉dingtalk导出", "客户资料.xlsx"), 400);
        ExpectNotSafe("S1-1g", "架构图.vsdx", Path.Combine(user, "Desktop", "wechat_temp归档", "架构图.vsdx"), 400);

        Console.WriteLine();
        Console.WriteLine("== S1-2 仅凭未修改时间认定安全 ==");
        ExpectNotSafe("S1-2a", "unknown_ab12.dat", Path.Combine(user, "Documents", "unknown_ab12.dat"), 365);
        ExpectNotSafe("S1-2b", "unknown_cd34.bin", Path.Combine(tmp, "unknown_cd34.bin"), 365);
        // 【P0-B】需复核 = 没有删除授权
        total++;
        Evidence unk = SafetyPolicy.Decide(Item(Path.Combine(tmp, "unknown_cd34.bin"), 365), LockState.Free);
        if (unk.Risk == "需复核" && !unk.PolicyEligible)
        {
            Console.WriteLine("PASS S1-2b*  需复核且无授权 | " + Path.Combine(tmp, "unknown_cd34.bin"));
        }
        else
        {
            failed++;
            Console.WriteLine("FAIL S1-2b*  期望 需复核+无授权，实得 " + unk.Risk + " 授权=" + unk.PolicyEligible);
        }

        Console.WriteLine();
        Console.WriteLine("== P0-B 反向验证：只有「结构 + 内容校验」通过才授权 ==");
        string sandbox = Path.Combine(tmp, "cid-legacy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sandbox);
        try
        {
            string root = Path.Combine(sandbox, "_cacache", "content-v2", "sha512");
            Directory.CreateDirectory(root);
            CacheRoots.InjectForTest("TMP-PKGCACHE", root);

            // 负向：Temp 内仅凭名字/位置一律不授权
            ExpectNotAuthorized("POS-1", "npm-cache-_cacache", Path.Combine(tmp, "npm-cache-_cacache"), 30);
            ExpectNotAuthorized("POS-2", "~DF8A21C3.TMP", Path.Combine(tmp, "~DF8A21C3.TMP"), 30);

            // 正向：真 cacache 内容项（结构 + SHA-512 自证）必须授权
            string content = "legacy-pos-3-real-cache-content";
            byte[] d;
            using (SHA512 sha = SHA512.Create()) d = sha.ComputeHash(Encoding.UTF8.GetBytes(content));
            StringBuilder sb = new StringBuilder();
            foreach (byte b in d) sb.Append(b.ToString("x2"));
            string hex = sb.ToString();
            string dir = Path.Combine(root, hex.Substring(0, 2), hex.Substring(2, 2));
            Directory.CreateDirectory(dir);
            string real = Path.Combine(dir, hex.Substring(4));      // 实测：文件名 124 位
            File.WriteAllText(real, content);
            ExpectSafe("POS-3", Path.GetFileName(real), real, 30);

            // 负向：结构对但内容哈希不符 → 不授权
            string fakeDir = Path.Combine(root, "aa", "aa");
            Directory.CreateDirectory(fakeDir);
            string fake = Path.Combine(fakeDir, new string('a', 124));
            File.WriteAllText(fake, "冒充缓存内容的重要文档");
            ExpectNotAuthorized("POS-4", Path.GetFileName(fake), fake, 30);
        }
        finally
        {
            CacheRoots.ClearInjectedForTest();
            try { if (Directory.Exists(sandbox)) Directory.Delete(sandbox, true); } catch { }
        }

        Console.WriteLine();
        Console.WriteLine("total=" + total + "  failed=" + failed);
        return failed;
    }
}
