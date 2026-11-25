using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

public static class SelfTest
{
    private static int passed;
    private static int failed;

    private static void Check(string name, bool condition)
    {
        if (condition)
        {
            passed++;
        }
        else
        {
            failed++;
            Console.WriteLine("  [FAIL] " + name);
        }
    }

    [STAThread]
    public static int Main(string[] args)
    {
        AppDomain.CurrentDomain.AssemblyResolve += delegate(object s, ResolveEventArgs e)
        {
            try
            {
                string asmName = new System.Reflection.AssemblyName(e.Name).Name + ".dll";
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string p1 = Path.Combine(baseDir, "lib", asmName);
                if (File.Exists(p1)) return System.Reflection.Assembly.LoadFrom(p1);
                string p2 = Path.GetFullPath(Path.Combine(baseDir, "..", "lib", asmName));
                if (File.Exists(p2)) return System.Reflection.Assembly.LoadFrom(p2);
            }
            catch { }
            return null;
        };

        Stopwatch sw = Stopwatch.StartNew();
        string sandbox = Path.Combine(Path.GetTempPath(), "cid-v08-selftest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sandbox);

        try
        {
            Console.WriteLine("=== Group A: CacheRuleRegistry & 8-Category Positive/Negative Rules ===");
            RunGroupA(sandbox);

            Console.WriteLine("=== Group B: Multi-Root Fast Scan, Reparse Guard, Handle Skip & PathPool ===");
            RunGroupB(sandbox);

            Console.WriteLine("=== Group C: Handle-Verified Permanent Clean & Multi-Root Clean Integration ===");
            RunGroupC(sandbox);

            Console.WriteLine("=== Group D: Single-File Recycle Contract & AnPingBridge Full Pipeline ===");
            RunGroupD(sandbox);

            Console.WriteLine("=== Group E: v1.0.0 Host Hardening, Log Rotation, Single-Instance & Binary Metadata ===");
            RunGroupE(sandbox);

            Console.WriteLine("=== Group F: Full-Stack Security Audit Regression Suite (F1-F7) ===");
            RunGroupF(sandbox);
        }
        catch (Exception ex)
        {
            failed++;
            Console.WriteLine("  [FATAL] Unhandled exception in SelfTest: " + ex);
        }
        finally
        {
            CacheRoots.ClearInjectedForTest();
            CacheRuleRegistry.ClearQuickScanRootsForTest();
            ChatStorageLocator.ClearMockChatRootsForTest();
            Program.StartupAutoAction = "";
            PathPool.Clear();
            TryDeleteSandbox(sandbox);
        }

        sw.Stop();
        Console.WriteLine("------------------------------------------------------------");
        Console.WriteLine("SelfTest summary: passed=" + passed + " failed=" + failed + " elapsed=" + sw.ElapsedMilliseconds + "ms");
        return failed == 0 ? 0 : 1;
    }

    // =====================================================================
    // Group A: Rule Positive/Negative Cases & CacheRuleRegistry Consistency
    // =====================================================================
    private static void RunGroupA(string sandbox)
    {
        CacheRuleSpec[] specs = CacheRuleRegistry.All;
        Check("A1: Registry has 10 cleanable rules", specs != null && specs.Length == 10);

        string[] expectedOrder = new string[]
        {
            "TMP-PKGCACHE",
            "TMP-BROWSERCACHE",
            "TMP-CHATCACHE",
            "TMP-APPCACHE",
            "TMP-THUMBCACHE",
            "TMP-SHADERCACHE",
            "TMP-SYSTEMP",
            "TMP-WER",
            "TMP-WINUPDATE",
            "TMP-CRASHDUMP"
        };
        string[] bannedTerms = new string[] { "释放", "已释放", "可清理", "不需要清理", "放心删", "暂存区" };

        for (int i = 0; i < expectedOrder.Length; i++)
        {
            CacheRuleSpec s = specs[i];
            Check("A2: Spec order matches " + expectedOrder[i], s.Id == expectedOrder[i] && s.Order == i);
            Check("A3: Spec metadata complete for " + s.Id,
                !string.IsNullOrEmpty(s.CategoryId)
                && !string.IsNullOrEmpty(s.CategoryName)
                && !string.IsNullOrEmpty(s.GroupTitle)
                && !string.IsNullOrEmpty(s.GroupCost)
                && !string.IsNullOrEmpty(s.RuleLabel)
                && !string.IsNullOrEmpty(s.ExplainType)
                && !string.IsNullOrEmpty(s.ExplainPurpose) && s.ExplainPurpose.Length <= 40
                && !string.IsNullOrEmpty(s.ExplainRiskText) && s.ExplainRiskText.Length <= 40
                && s.ExplainSteps != null && s.ExplainSteps.Length > 0
                && s.MatchPatterns != null && s.MatchPatterns.Length > 0
                && s.DiscoverDefaultRoots != null
                && s.VerifyFile != null
                && s.VerifyStream != null);

            bool expectConfirm = (s.Id == "TMP-CRASHDUMP");
            Check("A4: Separate confirm flag on " + s.Id, s.RequiresSeparateConfirm == expectConfirm);
            if (expectConfirm)
            {
                Check("A4b: Crash dump confirm label", s.ConfirmLabel == "我确认不再需要这份崩溃报告");
            }

            string combinedText = s.GroupTitle + "|" + s.GroupCost + "|" + s.RuleLabel + "|" + s.ExplainType + "|" + s.ExplainPurpose + "|" + s.ExplainRiskText;
            for (int b = 0; b < bannedTerms.Length; b++)
            {
                Check("A5: No banned term '" + bannedTerms[b] + "' in " + s.Id, combinedText.IndexOf(bannedTerms[b], StringComparison.Ordinal) < 0);
            }

            ListRow sampleRow = new ListRow { Path = Path.Combine(sandbox, "sample.bin"), Name = "sample.bin", RuleId = s.Id, PolicyEligible = true, ContentVerified = true, Risk = "安全" };
            AnPingExplanation.Detail exp = AnPingExplanation.For(sampleRow);
            Check("A6: AnPingExplanation consumes registry for " + s.Id,
                exp != null && exp.type == s.ExplainType && exp.summary == "可随主页「清理」一键清理" && exp.risk == "影响很小" && exp.purpose.Length <= 40 && exp.riskText.Length <= 40);
            Check("A7: ScanText.RuleLabel consumes registry for " + s.Id, ScanText.RuleLabel(s.Id).IndexOf(s.RuleLabel, StringComparison.Ordinal) >= 0);
        }

        // CleanSelection dynamic validation
        string[] pickedRules;
        var validMsg = new Dictionary<string, object>
        {
            { "scanSessionId", 7L },
            { "rules", new ArrayList { "TMP-PKGCACHE", "TMP-BROWSERCACHE", "TMP-CHATCACHE", "TMP-APPCACHE", "TMP-SYSTEMP", "TMP-WER", "TMP-WINUPDATE" } }
        };
        Check("A8: CleanSelection accepts valid non-confirm rules (incl. CHATCACHE, APPCACHE, WER & WINUPDATE)",
            CleanSelection.Validate(validMsg, 7L, out pickedRules) == null && pickedRules.Length == 7);

        var dumpNoConfirm = new Dictionary<string, object>
        {
            { "scanSessionId", 7L },
            { "rules", new ArrayList { "TMP-CRASHDUMP" } }
        };
        Check("A9: CleanSelection blocks TMP-CRASHDUMP without separate confirm", CleanSelection.Validate(dumpNoConfirm, 7L, out pickedRules) != null);

        var dumpConfirmed = new Dictionary<string, object>
        {
            { "scanSessionId", 7L },
            { "rules", new ArrayList { "TMP-CRASHDUMP" } },
            { "confirmedRules", new ArrayList { "TMP-CRASHDUMP" } }
        };
        Check("A10: CleanSelection accepts TMP-CRASHDUMP with confirmedRules", CleanSelection.Validate(dumpConfirmed, 7L, out pickedRules) == null);

        // Positive & negative file verification across all 6 rule families in %TEMP% sandbox
        string rSandbox = Path.Combine(sandbox, "rules");
        Directory.CreateDirectory(rSandbox);
        CacheRoots.ClearInjectedForTest();

        try
        {
            // 1. TMP-PKGCACHE: npm + pip + NuGet + Yarn + pnpm
            string npmRoot = Path.Combine(rSandbox, "npm-cache", "_cacache", "content-v2", "sha512");
            string pipRoot = Path.Combine(rSandbox, "pip", "cache");
            string nugetRoot = Path.Combine(rSandbox, "NuGet", "v3-cache");
            string yarnRoot = Path.Combine(rSandbox, "Yarn", "Cache");
            string pnpmRoot = Path.Combine(rSandbox, "pnpm-cache");
            Directory.CreateDirectory(npmRoot);
            Directory.CreateDirectory(pipRoot);
            Directory.CreateDirectory(nugetRoot);
            Directory.CreateDirectory(yarnRoot);
            Directory.CreateDirectory(pnpmRoot);
            CacheRoots.InjectForTest("TMP-PKGCACHE", npmRoot);
            CacheRoots.InjectForTest("TMP-PKGCACHE", pipRoot);
            CacheRoots.InjectForTest("TMP-PKGCACHE", nugetRoot);
            CacheRoots.InjectForTest("TMP-PKGCACHE", yarnRoot);
            CacheRoots.InjectForTest("TMP-PKGCACHE", pnpmRoot);

            string npmValid = CreateNpmCacacheFile(npmRoot, "npm-verified-payload-001");
            Check("A11: npm SHA-512 verified cache eligible", DecideFile(npmValid).PolicyEligible);

            string npmFakeDir = Path.Combine(npmRoot, "ab", "cd");
            Directory.CreateDirectory(npmFakeDir);
            string npmFake = Path.Combine(npmFakeDir, new string('e', 124));
            File.WriteAllText(npmFake, "wrong-sha512-user-text");
            Check("A12: npm mismatched SHA-512 rejected", !DecideFile(npmFake).PolicyEligible);

            string pipWhl = Path.Combine(pipRoot, "urllib3-2.0.0-py3-none-any.whl");
            WriteMinimalZip(pipWhl, "urllib3/__init__.py", Encoding.ASCII.GetBytes("# wheel"));
            Check("A13: pip valid .whl eligible", DecideFile(pipWhl).PolicyEligible);

            string fakePdfWhl = Path.Combine(pipRoot, "disguised-report-py3-none-any.whl");
            File.WriteAllBytes(fakePdfWhl, Encoding.ASCII.GetBytes("%PDF-1.7 user document disguised as wheel"));
            string fakeDocxYarnZip = Path.Combine(yarnRoot, "disguised-office-doc.zip");
            WriteMinimalZip(fakeDocxYarnZip, "word/document.xml", Encoding.ASCII.GetBytes("<w:document/>"));
            Check("A14: Disguised PDF .whl and Office docx .zip in Yarn cache rejected",
                !DecideFile(fakePdfWhl).PolicyEligible && !DecideFile(fakeDocxYarnZip).PolicyEligible);

            string nugetPkg = Path.Combine(nugetRoot, "newtonsoft.json.13.0.3.nupkg");
            WriteMinimalZip(nugetPkg, "Newtonsoft.Json.nuspec", Encoding.ASCII.GetBytes("<package/>"));
            Check("A15: NuGet valid .nupkg eligible", DecideFile(nugetPkg).PolicyEligible);

            string yarnTgz = Path.Combine(yarnRoot, "npm-react-18.2.0.tgz");
            WriteGzipFile(yarnTgz, Encoding.UTF8.GetBytes("package/package.json{\"name\":\"react\"}"));
            Check("A16: Yarn valid .tgz eligible", DecideFile(yarnTgz).PolicyEligible);

            string yarnFakePdf = Path.Combine(yarnRoot, "contract.tgz");
            File.WriteAllBytes(yarnFakePdf, Encoding.ASCII.GetBytes("%PDF-1.7 user document"));
            Check("A17: PDF disguised as Yarn .tgz rejected", !DecideFile(yarnFakePdf).PolicyEligible);

            string pnpmJson = Path.Combine(pnpmRoot, "metadata-lodash.json");
            File.WriteAllText(pnpmJson, "{\"name\":\"lodash\",\"versions\":{\"4.17.21\":{}}}");
            Check("A18: pnpm valid metadata .json eligible", DecideFile(pnpmJson).PolicyEligible);

            string pnpmFakeSqlite = Path.Combine(pnpmRoot, "pnpm-db.dat");
            File.WriteAllBytes(pnpmFakeSqlite, Encoding.ASCII.GetBytes("SQLite format 3\0user-db-payload"));
            Check("A19: SQLite disguised in pnpm-cache rejected", !DecideFile(pnpmFakeSqlite).PolicyEligible);

            // 2. TMP-BROWSERCACHE: Edge/Chrome cache vs Cookies/Login Data
            string edgeProfile = Path.Combine(rSandbox, "Edge", "User Data", "Default");
            string edgeCacheData = Path.Combine(edgeProfile, "Cache", "Cache_Data");
            Directory.CreateDirectory(edgeCacheData);
            CacheRoots.InjectForTest("TMP-BROWSERCACHE", edgeCacheData);

            string simpleEntry = Path.Combine(edgeCacheData, "1a2b3c4d5e6f7890_0");
            WriteChromiumSimpleCacheFile(simpleEntry);
            Check("A20: Chromium Simple Cache entry eligible", DecideFile(simpleEntry).PolicyEligible);

            string cookiesFile = Path.Combine(edgeProfile, "Cookies");
            File.WriteAllBytes(cookiesFile, Encoding.ASCII.GetBytes("SQLite format 3\0cookies"));
            string loginDataFile = Path.Combine(edgeProfile, "Login Data");
            File.WriteAllBytes(loginDataFile, Encoding.ASCII.GetBytes("SQLite format 3\0logins"));
            Check("A21: Browser Cookies hard rejected", !DecideFile(cookiesFile).PolicyEligible && DecideFile(cookiesFile).Risk != "安全");
            Check("A22: Browser Login Data hard rejected", !DecideFile(loginDataFile).PolicyEligible && DecideFile(loginDataFile).Risk != "安全");

            // 3. TMP-THUMBCACHE: CMMM vs *_idx.db
            string explorerDir = Path.Combine(rSandbox, "Microsoft", "Windows", "Explorer");
            Directory.CreateDirectory(explorerDir);
            CacheRoots.InjectForTest("TMP-THUMBCACHE", explorerDir);

            string thumbValid = Path.Combine(explorerDir, "thumbcache_256.db");
            WriteValidCmmmThumbcache(thumbValid);
            Check("A23: Explorer CMMM thumbcache eligible", DecideFile(thumbValid).PolicyEligible);

            string thumbIdx = Path.Combine(explorerDir, "thumbcache_idx.db");
            WriteValidCmmmThumbcache(thumbIdx);
            Check("A24: Explorer thumbcache_idx.db rejected", !DecideFile(thumbIdx).PolicyEligible);

            // 4. TMP-SHADERCACHE: DXBC shader vs lock/PDF
            string shaderDir = Path.Combine(rSandbox, "D3DSCache");
            Directory.CreateDirectory(shaderDir);
            CacheRoots.InjectForTest("TMP-SHADERCACHE", shaderDir);

            string dxbcVal = Path.Combine(shaderDir, "8899aabbccdd.val");
            WriteValidDxbcShader(dxbcVal);
            Check("A25: DirectX DXBC shader .val eligible", DecideFile(dxbcVal).PolicyEligible);

            string shaderFake = Path.Combine(shaderDir, "8899aabbccdd.lock");
            File.WriteAllBytes(shaderFake, new byte[] { 1, 2, 3, 4 });
            Check("A26: D3DSCache .lock file rejected", !DecideFile(shaderFake).PolicyEligible);

            // 5. TMP-SYSTEMP: >24h .tmp vs 2h .tmp vs disguised header / Office ~ draft
            string tempDir = Path.Combine(rSandbox, "Temp");
            Directory.CreateDirectory(tempDir);
            CacheRoots.InjectForTest("TMP-SYSTEMP", tempDir);

            string oldTmp = Path.Combine(tempDir, "old_build_log_01.tmp");
            File.WriteAllText(oldTmp, "plain temporary diagnostic scratch log line\r\n");
            File.SetLastWriteTimeUtc(oldTmp, DateTime.UtcNow.AddHours(-30));
            Check("A27: 30h old benign .tmp in Temp eligible", DecideFile(oldTmp).PolicyEligible);

            string freshTmp = Path.Combine(tempDir, "fresh_active_02.tmp");
            File.WriteAllText(freshTmp, "recent scratch content\r\n");
            File.SetLastWriteTimeUtc(freshTmp, DateTime.UtcNow.AddHours(-2));
            Check("A28: 2h fresh .tmp in Temp rejected", !DecideFile(freshTmp).PolicyEligible);

            string disguisedPdfTmp = Path.Combine(tempDir, "important_scan.tmp");
            File.WriteAllBytes(disguisedPdfTmp, Encoding.ASCII.GetBytes("%PDF-1.5 important contract"));
            File.SetLastWriteTimeUtc(disguisedPdfTmp, DateTime.UtcNow.AddHours(-48));
            Check("A29: 48h .tmp with %PDF header rejected", !DecideFile(disguisedPdfTmp).PolicyEligible);

            string officeDraftTmp = Path.Combine(tempDir, "~DF8A21C3.TMP");
            File.WriteAllText(officeDraftTmp, "office autorecover draft");
            File.SetLastWriteTimeUtc(officeDraftTmp, DateTime.UtcNow.AddHours(-48));
            Check("A30: Office ~*.TMP draft rejected", !DecideFile(officeDraftTmp).PolicyEligible);

            // 6. TMP-CRASHDUMP: MDMP vs PAGEDU64 kernel dump
            string dumpDir = Path.Combine(rSandbox, "CrashDumps");
            Directory.CreateDirectory(dumpDir);
            CacheRoots.InjectForTest("TMP-CRASHDUMP", dumpDir);

            string mdmpValid = Path.Combine(dumpDir, "app.exe.4321.dmp");
            WriteValidMdmp(mdmpValid);
            Check("A31: Valid user-mode MDMP crash dump eligible", DecideFile(mdmpValid).PolicyEligible);

            string kernelDump = Path.Combine(dumpDir, "kernel.4321.dmp");
            byte[] kd = new byte[128];
            Encoding.ASCII.GetBytes("PAGEDU64").CopyTo(kd, 0);
            File.WriteAllBytes(kernelDump, kd);
            Check("A32: Kernel PAGEDU64 dump rejected", !DecideFile(kernelDump).PolicyEligible);

            // 7. Windows\Installer\*.msi & System32 & Legacy S1/S2 false-positive repros
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string msiPath = Path.Combine(winDir, "Installer", "12ab34cd.msi");
            Evidence msiEv = EvidenceRules.Evaluate("12ab34cd.msi", msiPath, 500);
            Check("A33: Windows\\Installer\\*.msi forced KEEP-MSICACHE",
                msiEv.Risk == EvidenceRules.RiskKeep && msiEv.RuleId == "KEEP-MSICACHE" && !msiEv.PolicyEligible);

            string sysDll = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
            Evidence sysEv = EvidenceRules.Evaluate("kernel32.dll", sysDll, 500);
            Check("A34: System32 DLL forced KEEP-SYSTEM",
                sysEv.Risk == EvidenceRules.RiskKeep && !sysEv.PolicyEligible);

            string userDir = Path.Combine(rSandbox, "FakeUser");
            string[] legacyUnsafe = new string[]
            {
                Path.Combine(userDir, "Documents", "yarn-项目", "季度报告.docx"),
                @"D:\installer notes\notes.log",
                Path.Combine(userDir, "Downloads", "photo.dmp"),
                Path.Combine(userDir, "Documents", "_cacache备份", "合同.docx"),
                Path.Combine(userDir, "Documents", "thumbcache_notes.txt"),
                Path.Combine(userDir, "Documents", "钉钉dingtalk导出", "客户资料.xlsx"),
                Path.Combine(userDir, "Desktop", "wechat_temp归档", "架构图.vsdx"),
                Path.Combine(userDir, "Documents", "unknown_ab12.dat")
            };
            for (int i = 0; i < legacyUnsafe.Length; i++)
            {
                string p = legacyUnsafe[i];
                Evidence er = EvidenceRules.Evaluate(Path.GetFileName(p), p, 400);
                ScanItem si = new ScanItem { Path = p, Name = Path.GetFileName(p), Days = 400, IsDirectory = false, IsReparse = false, LastWriteUtc = DateTime.UtcNow.AddDays(-400) };
                Evidence sp = SafetyPolicy.Decide(si, LockState.Free);
                Check("A35." + i + ": Legacy S1/S2 negative never Safe/Eligible (" + Path.GetFileName(p) + ")",
                    er.Risk != "安全" && sp.Risk != "安全" && !sp.PolicyEligible);
            }

            // =================================================================
            // 8. v0.8.0 Expanded 8-Rule Positive & Negative Safety Matrix
            // =================================================================

            // (1) TMP-PKGCACHE expansion: go-build & uv\cache
            string goBuildRoot = Path.Combine(rSandbox, "go-build");
            string goSub = Path.Combine(goBuildRoot, "0a");
            string uvCacheRoot = Path.Combine(rSandbox, "uv", "cache");
            Directory.CreateDirectory(goSub);
            Directory.CreateDirectory(uvCacheRoot);
            CacheRoots.InjectForTest("TMP-PKGCACHE", goBuildRoot);
            CacheRoots.InjectForTest("TMP-PKGCACHE", uvCacheRoot);

            string goValidD = Path.Combine(goSub, new string('a', 64) + "-d");
            File.WriteAllBytes(goValidD, new byte[] { 0x67, 0x6F, 0x20, 0x6F, 0x62, 0x6A, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 });
            string uvValidWhl = Path.Combine(uvCacheRoot, "pkg.whl");
            WriteMinimalZip(uvValidWhl, "pkg/__init__.py", Encoding.ASCII.GetBytes("# uv wheel"));
            Check("A36: go-build <64hex>-d & uv\\cache\\pkg.whl eligible",
                DecideFile(goValidD).PolicyEligible && DecideFile(uvValidWhl).PolicyEligible);

            string goFakePdf = Path.Combine(goSub, new string('b', 64) + "-d");
            File.WriteAllBytes(goFakePdf, Encoding.ASCII.GetBytes("%PDF-1.7 user document disguised in go-build"));
            string uvFakePdf = Path.Combine(uvCacheRoot, "disguised.whl");
            File.WriteAllBytes(uvFakePdf, Encoding.ASCII.GetBytes("%PDF-1.7 user document disguised in uv cache"));
            Check("A37: Disguised %PDF in go-build and uv\\cache rejected",
                !DecideFile(goFakePdf).PolicyEligible && !DecideFile(uvFakePdf).PolicyEligible);

            // (2) TMP-BROWSERCACHE expansion: Firefox cache2/entries + protected sqlite/json + Brave Cache_Data
            string ffProfile = Path.Combine(rSandbox, "Mozilla", "Firefox", "Profiles", "abc.default-release");
            string ffEntries = Path.Combine(ffProfile, "cache2", "entries");
            string ffStartup = Path.Combine(ffProfile, "startupCache");
            Directory.CreateDirectory(ffEntries);
            Directory.CreateDirectory(ffStartup);
            CacheRoots.InjectForTest("TMP-BROWSERCACHE", ffEntries);
            CacheRoots.InjectForTest("TMP-BROWSERCACHE", ffStartup);

            string ffValidEntry = Path.Combine(ffEntries, "0123456789abcdef0123456789abcdef01234567");
            File.WriteAllBytes(ffValidEntry, Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/css\r\n\r\nbody{margin:0}"));
            string ffStartupBin = Path.Combine(ffStartup, "startupCache.8.little");
            byte[] ffStartupBytes = new byte[32];
            Encoding.ASCII.GetBytes("mozXulCache").CopyTo(ffStartupBytes, 0);
            ffStartupBytes[12] = 0x01; ffStartupBytes[13] = 0x02;
            File.WriteAllBytes(ffStartupBin, ffStartupBytes);
            Check("A38: Firefox cache2\\entries\\<40hex> & startupCache eligible",
                DecideFile(ffValidEntry).PolicyEligible && DecideFile(ffStartupBin).PolicyEligible);

            string ffCookies = Path.Combine(ffProfile, "cookies.sqlite");
            File.WriteAllBytes(ffCookies, Encoding.ASCII.GetBytes("SQLite format 3\0ff-cookies"));
            string ffPlaces = Path.Combine(ffProfile, "places.sqlite");
            File.WriteAllBytes(ffPlaces, Encoding.ASCII.GetBytes("SQLite format 3\0ff-places"));
            string ffLogins = Path.Combine(ffProfile, "logins.json");
            File.WriteAllText(ffLogins, "{\"logins\":[]}");
            string ffFakeSqliteEntry = Path.Combine(ffEntries, "fedcba9876543210fedcba9876543210fedcba98");
            File.WriteAllBytes(ffFakeSqliteEntry, Encoding.ASCII.GetBytes("SQLite format 3\0disguised-db"));
            Check("A39: Firefox cookies.sqlite / places.sqlite / logins.json & SQLite-header entry hard rejected",
                !DecideFile(ffCookies).PolicyEligible && DecideFile(ffCookies).Risk != "安全"
                && !DecideFile(ffPlaces).PolicyEligible && DecideFile(ffPlaces).Risk != "安全"
                && !DecideFile(ffLogins).PolicyEligible && DecideFile(ffLogins).Risk != "安全"
                && !DecideFile(ffFakeSqliteEntry).PolicyEligible);

            string braveCacheData = Path.Combine(rSandbox, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache", "Cache_Data");
            Directory.CreateDirectory(braveCacheData);
            CacheRoots.InjectForTest("TMP-BROWSERCACHE", braveCacheData);
            WriteChromiumBlockfileHeader(Path.Combine(braveCacheData, "index"), true, 512);
            string braveShard = Path.Combine(braveCacheData, "f_00001a");
            File.WriteAllBytes(braveShard, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4, 5, 6, 7, 8 });
            Check("A40: Brave User Data\\Default\\Cache\\Cache_Data\\f_00001a eligible",
                DecideFile(braveShard).PolicyEligible && DecideFile(braveShard).RuleId == "TMP-BROWSERCACHE");

            // (3) TMP-APPCACHE: Desktop Electron/CEF, VS Code VSIX, WebView2 & Protected settings/leveldb/docx
            string codeCacheData = Path.Combine(rSandbox, "Code", "Cache", "Cache_Data");
            string larkGpuCache = Path.Combine(rSandbox, "LarkShell", "GPUCache");
            string ebWebViewCache = Path.Combine(rSandbox, "AppX", "EBWebView", "Default", "Cache", "Cache_Data");
            string codeVsixDir = Path.Combine(rSandbox, "Code", "CachedExtensionVsiXs");
            Directory.CreateDirectory(codeCacheData);
            Directory.CreateDirectory(larkGpuCache);
            Directory.CreateDirectory(ebWebViewCache);
            Directory.CreateDirectory(codeVsixDir);
            CacheRoots.InjectForTest("TMP-APPCACHE", codeCacheData);
            CacheRoots.InjectForTest("TMP-APPCACHE", larkGpuCache);
            CacheRoots.InjectForTest("TMP-APPCACHE", ebWebViewCache);
            CacheRoots.InjectForTest("TMP-APPCACHE", codeVsixDir);

            WriteChromiumBlockfileHeader(Path.Combine(codeCacheData, "index"), true, 512);
            string codeShard = Path.Combine(codeCacheData, "f_000001");
            File.WriteAllBytes(codeShard, new byte[] { 0x1F, 0x8B, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 });

            WriteChromiumBlockfileHeader(Path.Combine(larkGpuCache, "index"), true, 512);
            string larkData1 = Path.Combine(larkGpuCache, "data_1");
            WriteChromiumBlockfileHeader(larkData1, false, 1024);

            string wvSimple = Path.Combine(ebWebViewCache, "fedcba9876543210_0");
            WriteChromiumSimpleCacheFile(wvSimple);

            string extVsix = Path.Combine(codeVsixDir, "ext.vsix");
            WriteMinimalZip(extVsix, "extension/package.json", Encoding.UTF8.GetBytes("{\"name\":\"demo-ext\"}"));

            Check("A41: Code Cache_Data, LarkShell GPUCache, EBWebView Cache_Data & Code ext.vsix eligible under TMP-APPCACHE",
                DecideFile(codeShard).PolicyEligible && DecideFile(codeShard).RuleId == "TMP-APPCACHE"
                && DecideFile(larkData1).PolicyEligible && DecideFile(larkData1).RuleId == "TMP-APPCACHE"
                && DecideFile(wvSimple).PolicyEligible && DecideFile(wvSimple).RuleId == "TMP-APPCACHE"
                && DecideFile(extVsix).PolicyEligible && DecideFile(extVsix).RuleId == "TMP-APPCACHE");

            string codeSettings = Path.Combine(rSandbox, "Code", "User", "settings.json");
            Directory.CreateDirectory(Path.GetDirectoryName(codeSettings));
            File.WriteAllText(codeSettings, "{\"editor.tabSize\":4}");

            string codeLevelDb = Path.Combine(rSandbox, "Code", "Local Storage", "leveldb", "000005.ldb");
            Directory.CreateDirectory(Path.GetDirectoryName(codeLevelDb));
            File.WriteAllBytes(codeLevelDb, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });

            string fakeDocxVsix = Path.Combine(codeVsixDir, "disguised_word.vsix");
            WriteMinimalZip(fakeDocxVsix, "word/document.xml", Encoding.UTF8.GetBytes("<w:document/>"));

            Check("A42: Code\\User\\settings.json, Local Storage\\leveldb & Word .docx disguised as .vsix hard rejected",
                !DecideFile(codeSettings).PolicyEligible && DecideFile(codeSettings).Risk != "安全"
                && !DecideFile(codeLevelDb).PolicyEligible && DecideFile(codeLevelDb).Risk != "安全"
                && !DecideFile(fakeDocxVsix).PolicyEligible);

            // (4) TMP-SHADERCACHE expansion: NVIDIA\DXCache & AMD\DxCache vs .lock / plain text / %PDF
            string nvDxCache = Path.Combine(rSandbox, "NVIDIA", "DXCache");
            string amdDxCache = Path.Combine(rSandbox, "AMD", "DxCache");
            Directory.CreateDirectory(nvDxCache);
            Directory.CreateDirectory(amdDxCache);
            CacheRoots.InjectForTest("TMP-SHADERCACHE", nvDxCache);
            CacheRoots.InjectForTest("TMP-SHADERCACHE", amdDxCache);

            string nvShaderBin = Path.Combine(nvDxCache, "shader01.bin");
            WriteBinaryShader(nvShaderBin, "NVDA");
            string nvShaderToc = Path.Combine(nvDxCache, "shader01.toc");
            WriteBinaryShader(nvShaderToc, "NVDA");
            string amdChunkBin = Path.Combine(amdDxCache, "chunk.bin");
            WriteBinaryShader(amdChunkBin, "AMDX");
            Check("A43: NVIDIA DXCache .bin/.toc & AMD DxCache chunk.bin eligible",
                DecideFile(nvShaderBin).PolicyEligible
                && DecideFile(nvShaderToc).PolicyEligible
                && DecideFile(amdChunkBin).PolicyEligible);

            string nvLock = Path.Combine(nvDxCache, "shader01.lock");
            File.WriteAllBytes(nvLock, new byte[32]);
            string amdPlainText = Path.Combine(amdDxCache, "plain_notes.bin");
            File.WriteAllText(amdPlainText, "readable plain ascii note that is not binary shader data\r\n");
            string nvPdfFake = Path.Combine(nvDxCache, "fake_manual.bin");
            File.WriteAllBytes(nvPdfFake, Encoding.ASCII.GetBytes("%PDF-1.7 user document disguised in DXCache"));
            Check("A44: Shader .lock, pure ASCII text & %PDF header hard rejected",
                !DecideFile(nvLock).PolicyEligible
                && !DecideFile(amdPlainText).PolicyEligible
                && !DecideFile(nvPdfFake).PolicyEligible);

            // (5) TMP-SYSTEMP deep expansion: 24h logs/etl + 48h installer sandboxes + critical red-line negatives
            string ariaLog30h = Path.Combine(tempDir, "aria-debug.log");
            File.WriteAllText(ariaLog30h, "2026-11-20 10:00:00 [INFO] aria telemetry flushed\r\n");
            File.SetLastWriteTimeUtc(ariaLog30h, DateTime.UtcNow.AddHours(-30));

            string traceEtl30h = Path.Combine(tempDir, "trace.etl");
            byte[] etlBytes = new byte[64];
            etlBytes[0] = 0x00; etlBytes[1] = 0x04; etlBytes[2] = 0x2C; etlBytes[3] = 0x01; etlBytes[4] = 0xAA;
            File.WriteAllBytes(traceEtl30h, etlBytes);
            File.SetLastWriteTimeUtc(traceEtl30h, DateTime.UtcNow.AddHours(-30));

            Check("A45: 30h Temp\\aria-debug.log & Temp\\trace.etl eligible",
                DecideFile(ariaLog30h).PolicyEligible && DecideFile(traceEtl30h).PolicyEligible);

            string freshLog2h = Path.Combine(tempDir, "fresh-session.log");
            File.WriteAllText(freshLog2h, "recent diagnostic line\r\n");
            File.SetLastWriteTimeUtc(freshLog2h, DateTime.UtcNow.AddHours(-2));
            Evidence outsideNotesEv = EvidenceRules.Evaluate("notes.log", @"D:\installer notes\notes.log", 400);
            Evidence outsideInstallerLogEv = EvidenceRules.Evaluate("installer_debug.log", @"D:\installer notes\installer_debug.log", 400);
            Check("A46: 2h fresh Temp .log rejected, non-Temp notes.log never hits TMP-SYSTEMP & non-Temp installer_debug.log hits REVIEW-INSTALLERLOG",
                !DecideFile(freshLog2h).PolicyEligible
                && outsideNotesEv.RuleId != "TMP-SYSTEMP" && outsideNotesEv.Risk != "安全" && !outsideNotesEv.PolicyEligible
                && outsideInstallerLogEv.RuleId == "REVIEW-INSTALLERLOG" && outsideInstallerLogEv.Risk != "安全" && !outsideInstallerLogEv.PolicyEligible);

            string innoDir = Path.Combine(tempDir, "is-9A2BC.tmp");
            string scopedDir = Path.Combine(tempDir, "scoped_dir123_45");
            string squirrelDir = Path.Combine(tempDir, "SquirrelTemp");
            Directory.CreateDirectory(innoDir);
            Directory.CreateDirectory(scopedDir);
            Directory.CreateDirectory(squirrelDir);

            string setup50h = Path.Combine(innoDir, "setup.exe");
            WritePeExe(setup50h);
            File.SetLastWriteTimeUtc(setup50h, DateTime.UtcNow.AddHours(-50));

            string payloadZip50h = Path.Combine(scopedDir, "payload.zip");
            WriteMinimalZip(payloadZip50h, "crx/manifest.json", Encoding.ASCII.GetBytes("{\"v\":1}"));
            File.SetLastWriteTimeUtc(payloadZip50h, DateTime.UtcNow.AddHours(-50));

            string packCab50h = Path.Combine(squirrelDir, "pack.cab");
            WriteMscfCab(packCab50h);
            File.SetLastWriteTimeUtc(packCab50h, DateTime.UtcNow.AddHours(-50));

            Check("A47: 50h Temp installer sandboxes (is-*.tmp\\setup.exe, scoped_dir\\payload.zip, SquirrelTemp\\pack.cab) eligible",
                DecideFile(setup50h).PolicyEligible
                && DecideFile(payloadZip50h).PolicyEligible
                && DecideFile(packCab50h).PolicyEligible);

            // Critical Red-Line Negatives for TMP-SYSTEMP:
            string setup12h = Path.Combine(innoDir, "active_setup_12h.exe");
            WritePeExe(setup12h);
            File.SetLastWriteTimeUtc(setup12h, DateTime.UtcNow.AddHours(-12));

            string setup36h = Path.Combine(innoDir, "recent_setup_36h.exe");
            WritePeExe(setup36h);
            File.SetLastWriteTimeUtc(setup36h, DateTime.UtcNow.AddHours(-36));

            Check("A48: Under-48h (12h & 36h) Temp\\is-9A2BC.tmp\\*.exe strictly rejected",
                !DecideFile(setup12h).PolicyEligible && !DecideFile(setup36h).PolicyEligible);

            string preview7zDir = Path.Combine(tempDir, "7zO8899");
            string previewRarDir = Path.Combine(tempDir, "Rar$EXa1");
            Directory.CreateDirectory(preview7zDir);
            Directory.CreateDirectory(previewRarDir);

            string contractDocx100h = Path.Combine(preview7zDir, "合同.docx");
            WriteMinimalZip(contractDocx100h, "word/document.xml", Encoding.UTF8.GetBytes("<w:document/>"));
            File.SetLastWriteTimeUtc(contractDocx100h, DateTime.UtcNow.AddHours(-100));

            string quoteXlsx100h = Path.Combine(previewRarDir, "报价单.xlsx");
            WriteMinimalZip(quoteXlsx100h, "xl/workbook.xml", Encoding.UTF8.GetBytes("<workbook/>"));
            File.SetLastWriteTimeUtc(quoteXlsx100h, DateTime.UtcNow.AddHours(-100));

            string disguisedOfficeZip100h = Path.Combine(innoDir, "disguised.zip");
            WriteMinimalZip(disguisedOfficeZip100h, "word/document.xml", Encoding.UTF8.GetBytes("<w:document/>"));
            File.SetLastWriteTimeUtc(disguisedOfficeZip100h, DateTime.UtcNow.AddHours(-100));

            string disguisedPdf100h = Path.Combine(innoDir, "disguised_pdf.dat");
            File.WriteAllBytes(disguisedPdf100h, Encoding.ASCII.GetBytes("%PDF-1.7 confidential contract inside temp sandbox"));
            File.SetLastWriteTimeUtc(disguisedPdf100h, DateTime.UtcNow.AddHours(-100));

            Check("A49: 100h Temp\\7zO8899\\合同.docx & Temp\\Rar$EXa1\\报价单.xlsx 100% rejected",
                !DecideFile(contractDocx100h).PolicyEligible && DecideFile(contractDocx100h).Risk != "安全"
                && !DecideFile(quoteXlsx100h).PolicyEligible && DecideFile(quoteXlsx100h).Risk != "安全");
            Check("A50: 100h Temp\\is-9A2BC.tmp\\disguised.zip (Office OpenXML) & %PDF header 100% rejected",
                !DecideFile(disguisedOfficeZip100h).PolicyEligible
                && !DecideFile(disguisedPdf100h).PolicyEligible);

            // (6) TMP-WER: Report.wer (UTF-16LE) & diag.cab (MSCF) vs fake %PDF .cab & PAGEDU64 kernel dump
            string werArchiveRoot = Path.Combine(rSandbox, "Microsoft", "Windows", "WER", "ReportArchive");
            string werAppDir = Path.Combine(werArchiveRoot, "AppCrash_demo");
            Directory.CreateDirectory(werAppDir);
            CacheRoots.InjectForTest("TMP-WER", werArchiveRoot);

            string werValidReport = Path.Combine(werAppDir, "Report.wer");
            WriteUtf16WerReport(werValidReport);
            string werValidCab = Path.Combine(werAppDir, "diag.cab");
            WriteMscfCab(werValidCab);
            Check("A51: WER Report.wer (UTF-16LE) & diag.cab (MSCF) eligible under TMP-WER",
                DecideFile(werValidReport).PolicyEligible && DecideFile(werValidReport).RuleId == "TMP-WER"
                && DecideFile(werValidCab).PolicyEligible && DecideFile(werValidCab).RuleId == "TMP-WER");

            string werFakePdfCab = Path.Combine(werAppDir, "fake_pdf.cab");
            File.WriteAllBytes(werFakePdfCab, Encoding.ASCII.GetBytes("%PDF-1.7 user document disguised as diag.cab 0123456789"));
            string werKernelDmp = Path.Combine(werAppDir, "kernel_crash.dmp");
            byte[] werKd = new byte[128];
            Encoding.ASCII.GetBytes("PAGEDU64").CopyTo(werKd, 0);
            File.WriteAllBytes(werKernelDmp, werKd);
            Check("A52: Disguised %PDF .cab & PAGEDU64 kernel dump in WER hard rejected",
                !DecideFile(werFakePdfCab).PolicyEligible && !DecideFile(werKernelDmp).PolicyEligible);

            // =================================================================
            // 9. v0.9.0 ChatStorageLocator, TMP-CHATCACHE, KEEP-CHATDB & TMP-WINUPDATE
            // =================================================================
            string mockDocsDir = Path.Combine(rSandbox, "MockDocuments");
            Directory.CreateDirectory(mockDocsDir);
            string parsedMyDoc = ChatStorageLocator.ParseWeChatConfigIniContent("  MyDocument: \r\n", mockDocsDir);
            string customChatParent = Path.Combine(rSandbox, "CustomWeChatDisk", "WeChatData");
            string customWcFilesDir = Path.Combine(customChatParent, "WeChat Files");
            Directory.CreateDirectory(customWcFilesDir);
            string parsedCustomExisting = ChatStorageLocator.ParseWeChatConfigIniContent(customChatParent, mockDocsDir);
            string parsedDriveCustom = ChatStorageLocator.ParseWeChatConfigIniContent(@"D:\WeChatData", mockDocsDir);
            Check("A55: ParseWeChatConfigIniContent resolves MyDocument: & custom D:\\WeChatData",
                string.Equals(parsedMyDoc, PathGuard.Canonical(Path.Combine(mockDocsDir, "WeChat Files")), StringComparison.OrdinalIgnoreCase)
                && string.Equals(parsedCustomExisting, PathGuard.Canonical(customWcFilesDir), StringComparison.OrdinalIgnoreCase)
                && string.Equals(parsedDriveCustom, @"D:\WeChatData\WeChat Files", StringComparison.OrdinalIgnoreCase));

            // TMP-CHATCACHE & KEEP-CHATDB positive/negative matrix
            string wcRoot = Path.Combine(rSandbox, "WeChat Files");
            string qqRoot = Path.Combine(rSandbox, "Tencent Files");
            string snsCacheDir = Path.Combine(wcRoot, "wxid_demo", "FileStorage", "Sns", "Cache", "2026-11");
            string appletDir = Path.Combine(wcRoot, "All Users", "Applet", "wx12345");
            string wcFileDir = Path.Combine(wcRoot, "wxid_demo", "FileStorage", "File", "2026-11");
            string wcVideoDir = Path.Combine(wcRoot, "wxid_demo", "FileStorage", "Video", "2026-11");
            string wcMsgMultiDir = Path.Combine(wcRoot, "wxid_demo", "Msg", "Multi");
            string qqFileRecvDir = Path.Combine(qqRoot, "10001", "FileRecv");
            Directory.CreateDirectory(snsCacheDir);
            Directory.CreateDirectory(appletDir);
            Directory.CreateDirectory(wcFileDir);
            Directory.CreateDirectory(wcVideoDir);
            Directory.CreateDirectory(wcMsgMultiDir);
            Directory.CreateDirectory(qqFileRecvDir);

            ChatStorageLocator.SetMockChatRootsForTest(new ChatStorageLocator.ChatDataFolder[]
            {
                new ChatStorageLocator.ChatDataFolder { AppName = "微信", Kind = "wechat", Path = wcRoot },
                new ChatStorageLocator.ChatDataFolder { AppName = "QQ", Kind = "qq", Path = qqRoot }
            });

            string snsPhoto = Path.Combine(snsCacheDir, "sns_moment_01");
            File.WriteAllBytes(snsPhoto, new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 1, 2, 3, 4, 5, 6, 7, 8 });
            string appletPkg = Path.Combine(appletDir, "pkg.wxapkg");
            WriteWxapkg(appletPkg);
            Check("A56: TMP-CHATCACHE authorizes Sns\\Cache moment photo & Applet\\pkg.wxapkg",
                DecideFile(snsPhoto).PolicyEligible && DecideFile(snsPhoto).RuleId == "TMP-CHATCACHE"
                && DecideFile(appletPkg).PolicyEligible && DecideFile(appletPkg).RuleId == "TMP-CHATCACHE");

            string contractPdf = Path.Combine(wcFileDir, "项目合同.pdf");
            File.WriteAllBytes(contractPdf, Encoding.ASCII.GetBytes("%PDF-1.7 important user contract received via WeChat"));
            string familyMp4 = Path.Combine(wcVideoDir, "家庭录像.mp4");
            WriteMp4Header(familyMp4, 256);
            string quoteXlsx = Path.Combine(qqFileRecvDir, "报价表.xlsx");
            WriteMinimalZip(quoteXlsx, "xl/workbook.xml", Encoding.UTF8.GetBytes("<workbook/>"));
            string disguisedSnsPdf = Path.Combine(snsCacheDir, "disguised_doc.dat");
            File.WriteAllBytes(disguisedSnsPdf, Encoding.ASCII.GetBytes("%PDF-1.7 disguised PDF inside Sns Cache"));

            Check("A57: Chat received user files (项目合同.pdf, 家庭录像.mp4, 报价表.xlsx) & disguised PDF strictly rejected",
                !DecideFile(contractPdf).PolicyEligible && DecideFile(contractPdf).Risk != "安全"
                && !DecideFile(familyMp4).PolicyEligible && DecideFile(familyMp4).Risk != "安全"
                && !DecideFile(quoteXlsx).PolicyEligible && DecideFile(quoteXlsx).Risk != "安全"
                && !DecideFile(disguisedSnsPdf).PolicyEligible
                && ChatStorageLocator.IsChatReceivedUserFile(contractPdf)
                && ChatStorageLocator.IsChatReceivedUserFile(familyMp4)
                && ChatStorageLocator.IsChatReceivedUserFile(quoteXlsx)
                && !ChatStorageLocator.IsChatReceivedUserFile(snsPhoto));

            string msgDb = Path.Combine(wcMsgMultiDir, "MSG0.db");
            File.WriteAllBytes(msgDb, Encoding.ASCII.GetBytes("SQLite format 3\0wechat-chat-history-db"));
            Evidence msgDbEv = DecideFile(msgDb);
            Check("A58: Msg\\Multi\\MSG0.db forced KEEP-CHATDB (Risk == 保留, PolicyEligible == false, not chat received file)",
                msgDbEv.RuleId == "KEEP-CHATDB"
                && msgDbEv.Risk == EvidenceRules.RiskKeep
                && !msgDbEv.PolicyEligible
                && !ChatStorageLocator.IsChatReceivedUserFile(msgDb));

            // TMP-WINUPDATE positive/negative matrix
            string sdRoot = Path.Combine(rSandbox, "SoftwareDistribution");
            string sdDownload = Path.Combine(sdRoot, "Download");
            string sdDataStore = Path.Combine(sdRoot, "DataStore");
            Directory.CreateDirectory(sdDownload);
            Directory.CreateDirectory(sdDataStore);
            CacheRoots.InjectForTest("TMP-WINUPDATE", sdDownload);

            string cab60h = Path.Combine(sdDownload, "kb5034441.cab");
            WriteMscfCab(cab60h);
            File.SetLastWriteTimeUtc(cab60h, DateTime.UtcNow.AddHours(-60));

            string esd60h = Path.Combine(sdDownload, "update_payload.esd");
            WriteMswimEsd(esd60h);
            File.SetLastWriteTimeUtc(esd60h, DateTime.UtcNow.AddHours(-60));

            Check("A59: TMP-WINUPDATE authorizes 60h SoftwareDistribution\\Download .cab (MSCF) & .esd (MSWIM)",
                DecideFile(cab60h).PolicyEligible && DecideFile(cab60h).RuleId == "TMP-WINUPDATE"
                && DecideFile(esd60h).PolicyEligible && DecideFile(esd60h).RuleId == "TMP-WINUPDATE");

            string cab6h = Path.Combine(sdDownload, "pending_patch_6h.cab");
            WriteMscfCab(cab6h);
            File.SetLastWriteTimeUtc(cab6h, DateTime.UtcNow.AddHours(-6));

            string dataStoreEdb = Path.Combine(sdDataStore, "DataStore.edb");
            byte[] edbBuf = new byte[64];
            edbBuf[4] = 0xEF; edbBuf[5] = 0xCD; edbBuf[6] = 0xAB; edbBuf[7] = 0x89;
            File.WriteAllBytes(dataStoreEdb, edbBuf);
            File.SetLastWriteTimeUtc(dataStoreEdb, DateTime.UtcNow.AddHours(-120));

            string disguisedWinUpdPdf = Path.Combine(sdDownload, "fake_manual.cab");
            File.WriteAllBytes(disguisedWinUpdPdf, Encoding.ASCII.GetBytes("%PDF-1.7 disguised PDF inside SoftwareDistribution Download"));
            File.SetLastWriteTimeUtc(disguisedWinUpdPdf, DateTime.UtcNow.AddHours(-72));

            Check("A60: TMP-WINUPDATE rejects under-48h (6h) patch, DataStore\\DataStore.edb & disguised PDF",
                !DecideFile(cab6h).PolicyEligible && DecideFile(cab6h).Risk != "安全"
                && !DecideFile(dataStoreEdb).PolicyEligible && DecideFile(dataStoreEdb).Risk != "安全"
                && !DecideFile(disguisedWinUpdPdf).PolicyEligible);
        }
        finally
        {
            ChatStorageLocator.ClearMockChatRootsForTest();
            CacheRoots.ClearInjectedForTest();
        }

        // (7) Cold Root Discovery Performance Gate (< 300 ms) & Self-Directory Exclusion Check
        CacheRoots.ClearInjectedForTest();
        CacheRuleRegistry.ClearQuickScanRootsForTest();
        Stopwatch coldProbeSw = Stopwatch.StartNew();
        CacheRuleRegistry.RefreshRootsCache();
        CacheRoots.Root[] discoveredRoots = CacheRuleRegistry.DiscoverExistingRoots();
        coldProbeSw.Stop();
        Console.WriteLine("  [BENCH] Cold DiscoverExistingRoots elapsed = " + coldProbeSw.ElapsedMilliseconds + "ms (count=" + (discoveredRoots != null ? discoveredRoots.Length : 0) + ")");
        Check("A53: Cold CacheRuleRegistry.DiscoverExistingRoots() < 300 ms",
            discoveredRoots != null && coldProbeSw.ElapsedMilliseconds < 300);

        bool hasSelfCanIDelete = false;
        string selfAppRoot = PathGuard.Canonical(AppDataPaths.Root);
        for (int i = 0; i < discoveredRoots.Length; i++)
        {
            string d = discoveredRoots[i].Directory ?? "";
            if (d.IndexOf("CanIDelete", StringComparison.OrdinalIgnoreCase) >= 0
                || d.IndexOf("can-i-delete", StringComparison.OrdinalIgnoreCase) >= 0
                || (!string.IsNullOrEmpty(selfAppRoot) && PathGuard.IsInside(selfAppRoot, d)))
            {
                hasSelfCanIDelete = true;
                break;
            }
        }
        Check("A54: Self CanIDelete / AppDataPaths.Root never present in DiscoverExistingRoots()", !hasSelfCanIDelete);
    }

    // =====================================================================
    // Group B: ScanEngine, Multi-Root Quick Scan, Reparse Skip & PathPool
    // =====================================================================
    private static void RunGroupB(string sandbox)
    {
        // B1: PathPool memory interning across 5,000 ListRow instances in same directory
        PathPool.Clear();
        string sharedDir = Path.Combine(sandbox, "pool-bench", "nested", "cache");
        ListRow[] poolRows = new ListRow[5000];
        for (int i = 0; i < poolRows.Length; i++)
        {
            string name = "entry_" + i.ToString("0000") + ".bin";
            ListRow r = new ListRow();
            r.Name = name;
            r.Path = Path.Combine(sharedDir, name);
            poolRows[i] = r;
        }
        bool allSameRef = true;
        bool allPathsIntact = true;
        string firstDirRef = poolRows[0].DirectoryPath;
        for (int i = 1; i < poolRows.Length; i++)
        {
            if (!object.ReferenceEquals(firstDirRef, poolRows[i].DirectoryPath))
                allSameRef = false;
            if (poolRows[i].Path != Path.Combine(sharedDir, "entry_" + i.ToString("0000") + ".bin"))
                allPathsIntact = false;
        }
        Check("B1: 5000 ListRow instances share single ReferenceEquals DirectoryPath", allSameRef && firstDirRef == sharedDir);
        Check("B2: ListRow.Path round-trips exact full path for all 5000 rows", allPathsIntact);

        // B2: Multi-root StartTargets + Reparse junction not followed + Non-candidate skips CreateFileW
        string bRoot = Path.Combine(sandbox, "scan-b");
        string root1 = Path.Combine(bRoot, "npm-root", "_cacache", "content-v2", "sha512");
        string root2 = Path.Combine(bRoot, "thumb-root", "Explorer");
        string root3 = Path.Combine(bRoot, "review-root");
        string outsideTarget = Path.Combine(bRoot, "outside-secret");
        Directory.CreateDirectory(root1);
        Directory.CreateDirectory(root2);
        Directory.CreateDirectory(root3);
        Directory.CreateDirectory(outsideTarget);
        File.WriteAllText(Path.Combine(outsideTarget, "must_not_follow.txt"), "secret outside junction");

        CacheRoots.ClearInjectedForTest();
        CacheRoots.InjectForTest("TMP-PKGCACHE", root1);
        CacheRoots.InjectForTest("TMP-THUMBCACHE", root2);

        try
        {
            string npmFile = CreateNpmCacacheFile(root1, "multi-root-npm-1");
            string thumbFile = Path.Combine(root2, "thumbcache_96.db");
            WriteValidCmmmThumbcache(thumbFile);
            string reviewFile = Path.Combine(root3, "notes_review.dat");
            File.WriteAllBytes(reviewFile, new byte[] { 10, 20, 30, 40, 50 });

            // Create NTFS directory junction inside root3 -> outsideTarget
            string junctionPath = Path.Combine(root3, "junction_to_outside");
            bool junctionCreated = TryCreateJunction(junctionPath, outsideTarget);

            ScanSessionHost host = new ScanSessionHost();
            ScanBudget budget = ScanSessionHost.BudgetFromEnvironment(null);
            budget.Recursive = true;

            string why;
            bool started = host.StartTargets(new string[] { root1, root2, root3 }, budget, out why);
            Check("B3: ScanSessionHost.StartTargets starts 3 roots", started && string.IsNullOrEmpty(why));

            List<ListRow> scanned = PumpUntilDone(host, 5000);
            List<ListRow> filesOnly = new List<ListRow>();
            for (int i = 0; i < scanned.Count; i++)
            {
                if (!scanned[i].IsDirectory) filesOnly.Add(scanned[i]);
            }

            Check("B4: Multi-root scan found exact 3 files across 3 roots (junction target excluded)", filesOnly.Count == 3);

            if (junctionCreated)
            {
                Check("B5: Junction recorded in Coverage.ReparseSkipped and never followed",
                    host.Progress.Coverage != null && host.Progress.Coverage.ReparseSkipped >= 1);
            }

            ListRow scannedNpm = FindByPath(filesOnly, npmFile);
            ListRow scannedReview = FindByPath(filesOnly, reviewFile);
            Check("B6: Candidate safe cache file captured strong FileIdentity during scan",
                scannedNpm != null && scannedNpm.PolicyEligible && scannedNpm.Id.Ok);
            Check("B7: Non-candidate review file skipped CreateFileW strong identity during scan",
                scannedReview != null && !scannedReview.PolicyEligible && !scannedReview.Id.Ok && scannedReview.Bytes == 5);

            // Multi-root DirectorySummary aggregation check
            DirectorySummary summary = new DirectorySummary(new string[] { root1, root2, root3 }, "常见缓存位置（3 处）");
            summary.StartScan(1L);
            summary.UpdateFromRows(scanned, 0);
            DirectorySummary.DirectoryPage topPage = summary.Query(1L, 0, 0);
            Check("B8: Multi-root DirectorySummary aggregates all 3 roots without dropping",
                topPage != null && topPage.TotalFileCount == 3 && topPage.Rows.Length == 3);

            // Cancellation check with deterministic slow fake enumerator
            ScanSessionHost cancelHost = new ScanSessionHost(new SlowFakeEnumerator(200), null);
            ScanBudget cancelBudget = ScanSessionHost.BudgetFromEnvironment(null);
            string cancelWhy;
            Check("B9: Start slow session for cancel check", cancelHost.Start(root3, cancelBudget, out cancelWhy));
            Thread.Sleep(25);
            cancelHost.RequestCancel();
            PumpUntilDone(cancelHost, 3000);
            Check("B10: Cancelled scan does not claim exhaustive completion", !cancelHost.Progress.IsScanExhaustive);
        }
        finally
        {
            CacheRoots.ClearInjectedForTest();
        }

        // B11..B16: Authentic Chromium Blockfile pool (locked data_0..3 + 50 f_000xxx + Code Cache + Cookies) & 2,000-file throughput benchmark
        string chromeProfile = Path.Combine(sandbox, "chrome-blockfile", "Google", "Chrome", "User Data", "Profile 4");
        string chromeCacheData = Path.Combine(chromeProfile, "Cache", "Cache_Data");
        string chromeCodeJs = Path.Combine(chromeProfile, "Code Cache", "js");
        Directory.CreateDirectory(chromeCacheData);
        Directory.CreateDirectory(chromeCodeJs);

        CacheRoots.ClearInjectedForTest();
        CacheRoots.InjectForTest("TMP-BROWSERCACHE", chromeCacheData);
        CacheRoots.InjectForTest("TMP-BROWSERCACHE", Path.Combine(chromeProfile, "Code Cache"));
        CacheRuleRegistry.RefreshRootsCache();

        List<FileStream> heldLocks = new List<FileStream>();
        try
        {
            WriteChromiumBlockfileHeader(Path.Combine(chromeCacheData, "index"), true, 512);
            for (int d = 0; d <= 3; d++)
            {
                string dp = Path.Combine(chromeCacheData, "data_" + d);
                WriteChromiumBlockfileHeader(dp, false, 8192);
                // Hold exclusive write handle (FileShare.Read) simulating running Chrome browser
                heldLocks.Add(new FileStream(dp, FileMode.Open, FileAccess.ReadWrite, FileShare.Read));
            }

            for (int i = 1; i <= 50; i++)
            {
                string shardName = "f_" + i.ToString("000000");
                string shardPath = Path.Combine(chromeCacheData, shardName);
                int kind = i % 5;
                if (kind == 0)
                    File.WriteAllBytes(shardPath, new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44 });
                else if (kind == 1)
                    File.WriteAllBytes(shardPath, new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52 });
                else if (kind == 2)
                    WriteMinimalZip(shardPath, "bundle/asset.bin", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
                else if (kind == 3)
                    File.WriteAllBytes(shardPath, Encoding.ASCII.GetBytes("%PDF-1.7 cached web whitepaper stream payload"));
                else
                    File.WriteAllBytes(shardPath, new byte[] { 0x1F, 0x8B, 0x08, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A });
            }

            WriteChromiumSimpleIndex(Path.Combine(chromeCodeJs, "index"));
            string codeEntryPath = Path.Combine(chromeCodeJs, "0123456789abcdef_0");
            WriteV8CodeCacheEntry(codeEntryPath);

            string chromeCookies = Path.Combine(chromeProfile, "Cookies");
            File.WriteAllBytes(chromeCookies, Encoding.ASCII.GetBytes("SQLite format 3\0user-chrome-cookies"));

            ScanSessionHost bfHost = new ScanSessionHost();
            ScanBudget bfBudget = ScanSessionHost.BudgetFromEnvironment(null);
            bfBudget.Recursive = true;
            string bfWhy;
            Check("B11: Start ScanSessionHost on simulated running Chrome profile", bfHost.Start(chromeProfile, bfBudget, out bfWhy));
            List<ListRow> bfRows = PumpUntilDoneHighSpeed(bfHost, 5000);

            int fEligibleCount = 0;
            int lockedDataCount = 0;
            ListRow lockedData2 = null;
            ListRow codeRow = FindByPath(bfRows, codeEntryPath);
            ListRow cookiesRow = FindByPath(bfRows, chromeCookies);

            for (int i = 0; i < bfRows.Count; i++)
            {
                ListRow r = bfRows[i];
                if (r.IsDirectory) continue;
                if (r.Name.StartsWith("f_0000", StringComparison.OrdinalIgnoreCase))
                {
                    if (r.PolicyEligible && r.Risk == "安全") fEligibleCount++;
                }
                if (r.Name == "data_0" || r.Name == "data_1" || r.Name == "data_2" || r.Name == "data_3")
                {
                    if (!r.PolicyEligible && r.Risk == "保留" && r.LockedCleanableCache) lockedDataCount++;
                    if (r.Name == "data_2") lockedData2 = r;
                }
            }

            Check("B12: All 50 extensionless f_000001..f_000050 shards (JPEG/PNG/ZIP/PDF/GZIP) PolicyEligible == true", fEligibleCount == 50);
            Check("B13: Code Cache\\js\\0123456789abcdef_0 PolicyEligible == true", codeRow != null && codeRow.PolicyEligible && codeRow.Risk == "安全");
            Check("B14: Chrome Cookies hard rejected (!PolicyEligible && Risk != 安全)", cookiesRow != null && !cookiesRow.PolicyEligible && cookiesRow.Risk != "安全");
            Check("B15: Locked data_0..3 marked LockedCleanableCache == true while remaining PolicyEligible == false", lockedDataCount == 4 && lockedData2 != null);

            AnPingExplanation.Detail dLocked2 = AnPingExplanation.For(lockedData2);
            bool stepsGuideChrome = false;
            if (dLocked2 != null && dLocked2.steps != null)
            {
                for (int s = 0; s < dLocked2.steps.Length; s++)
                {
                    if (dLocked2.steps[s].IndexOf("Chrome", StringComparison.OrdinalIgnoreCase) >= 0
                        && dLocked2.steps[s].IndexOf("重新扫描", StringComparison.Ordinal) >= 0)
                    {
                        stepsGuideChrome = true;
                    }
                }
            }
            Check("B16: AnPingExplanation.For(lockedData2) returns risk=='影响很小', identifies Chrome & guides rescan without contradiction",
                dLocked2 != null
                && dLocked2.risk == "影响很小"
                && dLocked2.type.IndexOf("Chrome", StringComparison.OrdinalIgnoreCase) >= 0
                && !string.IsNullOrEmpty(dLocked2.summary)
                && dLocked2.riskText.IndexOf("不知道它属于哪个程序", StringComparison.Ordinal) < 0
                && stepsGuideChrome);
        }
        finally
        {
            for (int i = 0; i < heldLocks.Count; i++)
            {
                try { heldLocks[i].Dispose(); } catch { }
            }
            CacheRoots.ClearInjectedForTest();
        }

        // B17: Throughput benchmark — 2,000 cache files full ScanSessionHost scan < 2000 ms
        string benchDir = Path.Combine(sandbox, "throughput-bench", "Google", "Chrome", "User Data", "Default", "Cache", "Cache_Data");
        Directory.CreateDirectory(benchDir);
        CacheRoots.ClearInjectedForTest();
        CacheRoots.InjectForTest("TMP-BROWSERCACHE", benchDir);
        try
        {
            WriteChromiumBlockfileHeader(Path.Combine(benchDir, "index"), true, 512);
            byte[] samplePayload = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
            for (int i = 1; i <= 2000; i++)
            {
                string p = Path.Combine(benchDir, "f_" + i.ToString("x6"));
                File.WriteAllBytes(p, samplePayload);
            }

            CacheRuleRegistry.RefreshRootsCache();
            ScanSessionHost benchHost = new ScanSessionHost();
            ScanBudget benchBudget = ScanSessionHost.BudgetFromEnvironment(null);
            benchBudget.Recursive = true;

            Stopwatch benchSw = Stopwatch.StartNew();
            string benchWhy;
            bool benchStarted = benchHost.Start(benchDir, benchBudget, out benchWhy);
            List<ListRow> benchRows = PumpUntilDoneHighSpeed(benchHost, 10000);
            benchSw.Stop();

            int benchEligible = 0;
            for (int i = 0; i < benchRows.Count; i++)
            {
                if (!benchRows[i].IsDirectory && benchRows[i].PolicyEligible) benchEligible++;
            }
            Console.WriteLine("  [BENCH] 2,001 cache files ScanSessionHost elapsed = " + benchSw.ElapsedMilliseconds + "ms (eligible=" + benchEligible + ")");
            Check("B17: 2,000-file cache scan completes in < 2000 ms with 100% accuracy",
                benchStarted && benchSw.ElapsedMilliseconds < 2000 && benchEligible == 2001);
        }
        finally
        {
            CacheRoots.ClearInjectedForTest();
        }
    }

    // =====================================================================
    // Group C: Permanent Clean Guards & Multi-Root Clean Integration
    // =====================================================================
    private static void RunGroupC(string sandbox)
    {
        string cRoot = Path.Combine(sandbox, "clean-c");
        string pkgRoot = Path.Combine(cRoot, "Yarn", "Cache");
        string thumbRoot = Path.Combine(cRoot, "Explorer");
        string tempRoot = Path.Combine(cRoot, "Temp");
        Directory.CreateDirectory(pkgRoot);
        Directory.CreateDirectory(thumbRoot);
        Directory.CreateDirectory(tempRoot);

        CacheRoots.ClearInjectedForTest();
        CacheRoots.InjectForTest("TMP-PKGCACHE", pkgRoot);
        CacheRoots.InjectForTest("TMP-THUMBCACHE", thumbRoot);
        CacheRoots.InjectForTest("TMP-SYSTEMP", tempRoot);

        string logPath = Path.Combine(cRoot, "delete-log.txt");

        try
        {
            // Create files across 3 roots:
            // 1) Valid Yarn .tgz (to be deleted)
            string fOkYarn = Path.Combine(pkgRoot, "axios-1.6.0.tgz");
            WriteGzipFile(fOkYarn, Encoding.UTF8.GetBytes("package/index.js"));
            // 2) Valid thumbcache (to be deleted)
            string fOkThumb = Path.Combine(thumbRoot, "thumbcache_1024.db");
            WriteValidCmmmThumbcache(fOkThumb);
            // 3) Valid 30h .tmp (to be deleted)
            string fOkTmp = Path.Combine(tempRoot, "stale_worker.tmp");
            File.WriteAllText(fOkTmp, "stale worker output log\r\n");
            File.SetLastWriteTimeUtc(fOkTmp, DateTime.UtcNow.AddHours(-30));
            // 4) Locked .tgz (must be skipped/refused, file untouched)
            string fLocked = Path.Combine(pkgRoot, "locked-pkg-1.0.0.tgz");
            WriteGzipFile(fLocked, Encoding.UTF8.GetBytes("locked package"));
            // 5) Tampered content after scan (same size & mtime, overwritten with %PDF-!)
            string fTampered = Path.Combine(tempRoot, "tampered_after_scan.tmp");
            byte[] initialBenign = Encoding.ASCII.GetBytes("123456789012345678901234567890");
            File.WriteAllBytes(fTampered, initialBenign);
            DateTime fixedUtc = DateTime.UtcNow.AddHours(-36);
            File.SetLastWriteTimeUtc(fTampered, fixedUtc);

            // Multi-root scan
            ScanSessionHost host = new ScanSessionHost();
            ScanBudget budget = ScanSessionHost.BudgetFromEnvironment(null);
            budget.Recursive = true;
            string why;
            string[] roots = new string[] { pkgRoot, thumbRoot, tempRoot };
            Check("C1: Multi-root scan before permanent clean", host.StartTargets(roots, budget, out why));
            List<ListRow> rows = PumpUntilDone(host, 5000);

            List<DeleteRequest> reqs = new List<DeleteRequest>();
            for (int i = 0; i < rows.Count; i++)
            {
                ListRow r = rows[i];
                if (r.IsDirectory || !r.PolicyEligible) continue;
                reqs.Add(new DeleteRequest
                {
                    Path = r.Path,
                    WasDirectory = false,
                    BytesAtScan = r.Bytes,
                    LastWriteUtcAtScan = r.LastWriteUtc,
                    WasReadOnly = r.WasReadOnly,
                    PolicyEligible = r.PolicyEligible,
                    Risk = r.Risk,
                    IdAtScan = r.Id
                });
            }
            Check("C2: All 5 cache files initially eligible at scan", reqs.Count == 5);

            // Tamper fTampered with PDF magic header of exact same byte length & restore mtime!
            byte[] pdfBytes = Encoding.ASCII.GetBytes("%PDF-1.7-secret-user-doc-00000"); // 30 bytes
            File.WriteAllBytes(fTampered, pdfBytes);
            File.SetLastWriteTimeUtc(fTampered, fixedUtc);

            // Hold exclusive lock on fLocked during DeleteEngine.Execute
            List<DeleteOutcome> outcomes;
            using (FileStream lockStream = new FileStream(fLocked, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                outcomes = DeleteEngine.Execute(reqs, roots, new PermanentDeleteBin(), logPath);
            }

            Check("C3: Multi-root permanent clean deleted 3 valid files across all 3 roots (no OutOfScope!)",
                !File.Exists(fOkYarn) && !File.Exists(fOkThumb) && !File.Exists(fOkTmp));
            Check("C4: Locked file skipped and untouched", File.Exists(fLocked));
            Check("C5: Content-tampered (%PDF) file blocked at handle level and untouched", File.Exists(fTampered));

            int verifiedDeletes = 0;
            int outOfScopeCount = 0;
            for (int i = 0; i < outcomes.Count; i++)
            {
                if (outcomes[i].Status == DeleteStatus.DeletedVerified) verifiedDeletes++;
                if (outcomes[i].Kind == DeleteRefusalKind.OutOfScope) outOfScopeCount++;
            }
            Check("C6: Outcome counts exact (3 DeletedVerified, 0 OutOfScope)", verifiedDeletes == 3 && outOfScopeCount == 0);

            // Crash log reconciliation test (intent without outcome)
            string crashLog = Path.Combine(cRoot, "crash-log.txt");
            string opWhy;
            DeleteRequest dummyReq = new DeleteRequest { Path = fLocked, BytesAtScan = 10, PolicyEligible = true, Risk = "安全" };
            Check("C7: Write simulated interrupted intent", DeleteLog.WriteIntent(crashLog, "op-crash-1", "batch-1", dummyReq, fLocked, out opWhy));
            List<DeleteOutcome> pending = DeleteEngine.Reconcile(crashLog);
            Check("C8: Reconcile reports PendingReconciliation & DispatchUncertain without deleting",
                pending.Count == 1
                && pending[0].Status == DeleteStatus.PendingReconciliation
                && pending[0].DispatchUncertain
                && pending[0].NeedsUrgentReview
                && File.Exists(fLocked));

            // C9..C10: DeleteLog.OpenSession 1,000-transaction batch write + reconciliation check
            string batchLog = Path.Combine(cRoot, "batch-1000-log.txt");
            string batchWhy;
            Stopwatch batchSw = Stopwatch.StartNew();
            using (DeleteLog.WriterSession ws = DeleteLog.OpenSession(batchLog, out batchWhy))
            {
                Check("C9a: DeleteLog.OpenSession opens writable handle", ws != null && string.IsNullOrEmpty(batchWhy));
                for (int i = 0; i < 1000; i++)
                {
                    string oid = "op-b-" + i.ToString("0000");
                    string p = Path.Combine(tempRoot, "batch_item_" + i + ".tmp");
                    DeleteRequest br = new DeleteRequest { Path = p, BytesAtScan = 64, PolicyEligible = true, Risk = "安全" };
                    DeleteOutcome bo = new DeleteOutcome
                    {
                        Path = p,
                        Status = DeleteStatus.DeletedVerified,
                        Kind = DeleteRefusalKind.None,
                        Detail = "verified"
                    };
                    string w1, w2;
                    if (!ws.WriteIntent(oid, "batch-1000", br, p, out w1) || !ws.WriteOutcome(oid, "batch-1000", bo, out w2))
                    {
                        failed++;
                        break;
                    }
                }
                string wTail;
                string tailPath = Path.Combine(tempRoot, "tail_unclosed.tmp");
                ws.WriteIntent("op-b-tail", "batch-1000", new DeleteRequest { Path = tailPath, BytesAtScan = 32, PolicyEligible = true, Risk = "安全" }, tailPath, out wTail);
            }
            batchSw.Stop();
            Console.WriteLine("  [BENCH] DeleteLog.OpenSession 1,000 intent+outcome pairs elapsed = " + batchSw.ElapsedMilliseconds + "ms");
            List<string> allBatchOps = DeleteLog.AllOpIds(batchLog);
            List<DeleteOutcome> tailPending = DeleteEngine.Reconcile(batchLog);
            Check("C9b: 1,000 batch transactions recorded (< 500ms) & exact 1 dangling intent reconciled",
                batchSw.ElapsedMilliseconds < 500
                && allBatchOps.Count == 1001
                && tailPending.Count == 1
                && tailPending[0].Path.EndsWith("tail_unclosed.tmp", StringComparison.OrdinalIgnoreCase));

            // C11..C12: DeleteEngine.PruneEmptyParentDirs safety & stopRoot preservation
            string pruneRoot = Path.Combine(cRoot, "prune-stop-root");
            string emptyBranchLeaf = Path.Combine(pruneRoot, "is-OLD01.tmp", "sub_payload");
            string protectedSibling = Path.Combine(pruneRoot, "is-NEW02.tmp");
            Directory.CreateDirectory(emptyBranchLeaf);
            Directory.CreateDirectory(protectedSibling);

            string deletedInEmptyBranch = Path.Combine(emptyBranchLeaf, "setup.exe");
            string deletedInProtectedSibling = Path.Combine(protectedSibling, "gone.tmp");
            string keptInProtectedSibling = Path.Combine(protectedSibling, "fresh_keep.exe");
            File.WriteAllBytes(keptInProtectedSibling, new byte[] { 1, 2, 3, 4 });
            // Simulate setup.exe and gone.tmp already deleted by DeleteEngine.Execute:
            int prunedCount = DeleteEngine.PruneEmptyParentDirs(
                new string[] { deletedInEmptyBranch, deletedInProtectedSibling },
                new string[] { pruneRoot });

            Check("C10: PruneEmptyParentDirs removes empty nested subdirs (sub_payload + is-OLD01.tmp)",
                prunedCount == 2
                && !Directory.Exists(emptyBranchLeaf)
                && !Directory.Exists(Path.Combine(pruneRoot, "is-OLD01.tmp")));
            Check("C11: PruneEmptyParentDirs preserves sibling subdir with protected file & preserves stopRoot itself",
                Directory.Exists(protectedSibling)
                && File.Exists(keptInProtectedSibling)
                && Directory.Exists(pruneRoot));
        }
        finally
        {
            CacheRoots.ClearInjectedForTest();
        }
    }

    // =====================================================================
    // Group D: Single-File Recycle Contract & AnPingBridge Full Pipeline
    // =====================================================================
    private static void RunGroupD(string sandbox)
    {
        Check("D0: BuildAllowsRealDeletion remains false", !DeleteEngine.BuildAllowsRealDeletion);
        bool directBinBlocked = false;
        try { new WindowsRecycleBin().SendFile(Path.Combine(sandbox, "nonexistent.bin")); }
        catch (InvalidOperationException) { directBinBlocked = true; }
        Check("D0b: Direct WindowsRecycleBin.SendFile blocked by gate (RealGateBypasses == 0)",
            directBinBlocked && WindowsRecycleBin.RealGateBypasses == 0);

        string revExe, revArgs, revWhy;
        Check("D0c: Program.TryBuildRevealCommand rejects quote injection & relative path",
            !Program.TryBuildRevealCommand("relative\\file.txt", out revExe, out revArgs, out revWhy)
            && !Program.TryBuildRevealCommand("C:\\bad\"quote.txt", out revExe, out revArgs, out revWhy)
            && !Program.BuildRevealStartInfo("explorer.exe", "/select,\"C:\\a\"").UseShellExecute);

        string dRoot = Path.Combine(sandbox, "recycle-d");
        string scanDir1 = Path.Combine(dRoot, "rootA");
        string scanDir2 = Path.Combine(dRoot, "rootB");
        string outsideDir = Path.Combine(dRoot, "outside");
        Directory.CreateDirectory(scanDir1);
        Directory.CreateDirectory(scanDir2);
        Directory.CreateDirectory(outsideDir);

        string logPath = Path.Combine(dRoot, "recycle-log.txt");
        FakeRecycleBin fakeBin = new FakeRecycleBin();
        string[] allowedRoots = new string[] { scanDir1, scanDir2 };

        // D1: Review large file with IdAtScan.Ok == false (fast-scan non-candidate) succeeds via Fake IRecycleBin
        string reviewLarge = Path.Combine(scanDir1, "old_archive_backup.zip");
        File.WriteAllBytes(reviewLarge, new byte[4096]);
        FileInfo fiLarge = new FileInfo(reviewLarge);
        DeleteRequest reqReview = new DeleteRequest
        {
            Path = reviewLarge,
            WasDirectory = false,
            BytesAtScan = fiLarge.Length,
            LastWriteUtcAtScan = fiLarge.LastWriteTimeUtc,
            WasReadOnly = false,
            PolicyEligible = false,
            Risk = EvidenceRules.RiskReview,
            IdAtScan = default(FileIdentity) // Ok == false, matching ScanEngine non-candidate optimization!
        };
        DeleteOutcome outOk = DeleteEngine.ExecuteSingleRecycle(reqReview, allowedRoots, fakeBin, logPath);
        Check("D1: ExecuteSingleRecycle recycles review file & logs outcome",
            outOk.Status == DeleteStatus.RecycledVerified && !File.Exists(reviewLarge) && fakeBin.RecycledPaths.Count == 1 && File.Exists(logPath));

        // D2: KEEP-* protected files hard refused
        string msiProtected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Installer", "fake_pkg.msi");
        DeleteRequest reqKeep = new DeleteRequest
        {
            Path = msiProtected,
            WasDirectory = false,
            BytesAtScan = 1024,
            LastWriteUtcAtScan = DateTime.UtcNow,
            Risk = EvidenceRules.RiskKeep
        };
        DeleteOutcome outKeep = DeleteEngine.ExecuteSingleRecycle(reqKeep, allowedRoots, fakeBin, logPath);
        Check("D2: KEEP-* file hard refused before dispatch",
            outKeep.Status == DeleteStatus.RefusedNotDispatched && !outKeep.WasDispatched);

        string lockFile = Path.Combine(scanDir1, "session.lock");
        File.WriteAllText(lockFile, "lock");
        FileInfo fiLock = new FileInfo(lockFile);
        DeleteRequest reqLockRule = new DeleteRequest
        {
            Path = lockFile,
            WasDirectory = false,
            BytesAtScan = fiLock.Length,
            LastWriteUtcAtScan = fiLock.LastWriteTimeUtc,
            Risk = EvidenceRules.RiskReview // Even if caller spoofed RiskReview, live Evaluate catches KEEP-LOCK!
        };
        DeleteOutcome outLockRule = DeleteEngine.ExecuteSingleRecycle(reqLockRule, allowedRoots, fakeBin, logPath);
        Check("D3: Live KEEP-LOCK evaluation blocks spoofed request",
            outLockRule.Status == DeleteStatus.RefusedNotDispatched && !outLockRule.WasDispatched && File.Exists(lockFile));

        // D3: Out-of-scope, directory, tampered size, occupied file, PermanentDeleteBin all hard refused
        string outFile = Path.Combine(outsideDir, "outside.dat");
        File.WriteAllBytes(outFile, new byte[] { 1, 2, 3 });
        FileInfo fiOut = new FileInfo(outFile);
        DeleteOutcome outScope = DeleteEngine.ExecuteSingleRecycle(new DeleteRequest
        {
            Path = outFile,
            BytesAtScan = fiOut.Length,
            LastWriteUtcAtScan = fiOut.LastWriteTimeUtc,
            Risk = EvidenceRules.RiskReview
        }, allowedRoots, fakeBin, logPath);
        Check("D4: Out-of-scope file refused", outScope.Status == DeleteStatus.RefusedNotDispatched && outScope.Kind == DeleteRefusalKind.OutOfScope && File.Exists(outFile));

        DeleteOutcome outDir = DeleteEngine.ExecuteSingleRecycle(new DeleteRequest
        {
            Path = scanDir1,
            WasDirectory = true,
            Risk = EvidenceRules.RiskReview
        }, allowedRoots, fakeBin, logPath);
        Check("D5: Directory refused", outDir.Status == DeleteStatus.RefusedNotDispatched && outDir.Kind == DeleteRefusalKind.DirectoryRefused);

        string tamperFile = Path.Combine(scanDir2, "changing.bin");
        File.WriteAllBytes(tamperFile, new byte[100]);
        FileInfo fiTamper = new FileInfo(tamperFile);
        DeleteRequest reqTamper = new DeleteRequest
        {
            Path = tamperFile,
            BytesAtScan = fiTamper.Length,
            LastWriteUtcAtScan = fiTamper.LastWriteTimeUtc,
            Risk = EvidenceRules.RiskReview
        };
        File.WriteAllBytes(tamperFile, new byte[250]); // size changed after scan!
        DeleteOutcome outTamper = DeleteEngine.ExecuteSingleRecycle(reqTamper, allowedRoots, fakeBin, logPath);
        Check("D6: Size-tampered file refused", outTamper.Status == DeleteStatus.RefusedNotDispatched && outTamper.Kind == DeleteRefusalKind.WeakIdentityChanged && File.Exists(tamperFile));

        string reparseLink = Path.Combine(scanDir2, "reparse_dir_link");
        if (TryCreateJunction(reparseLink, outsideDir))
        {
            DeleteOutcome outReparse = DeleteEngine.ExecuteSingleRecycle(new DeleteRequest
            {
                Path = Path.Combine(reparseLink, "outside.dat"),
                BytesAtScan = fiOut.Length,
                LastWriteUtcAtScan = fiOut.LastWriteTimeUtc,
                Risk = EvidenceRules.RiskReview
            }, allowedRoots, fakeBin, logPath);
            Check("D6b: Reparse ancestor refused by ExecuteSingleRecycle",
                outReparse.Status == DeleteStatus.RefusedNotDispatched && outReparse.Kind == DeleteRefusalKind.ReparseAncestor && File.Exists(outFile));
        }

        string busyFile = Path.Combine(scanDir2, "busy.bin");
        File.WriteAllBytes(busyFile, new byte[64]);
        FileInfo fiBusy = new FileInfo(busyFile);
        using (FileStream fs = new FileStream(busyFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            FileTechInfo tech = FileDetailProbe.Inspect(busyFile);
            Check("D7: FileDetailProbe.Inspect detects locking process via Restart Manager",
                tech != null && tech.Process != "未占用" && tech.Process != "无法读取"
                && tech.Process.IndexOf("PID " + Process.GetCurrentProcess().Id, StringComparison.OrdinalIgnoreCase) >= 0);

            DeleteOutcome outBusy = DeleteEngine.ExecuteSingleRecycle(new DeleteRequest
            {
                Path = busyFile,
                BytesAtScan = fiBusy.Length,
                LastWriteUtcAtScan = fiBusy.LastWriteTimeUtc,
                Risk = EvidenceRules.RiskReview
            }, allowedRoots, fakeBin, logPath);
            Check("D8: Occupied file refused by ExecuteSingleRecycle", outBusy.Status == DeleteStatus.RefusedNotDispatched && File.Exists(busyFile));
        }

        DeleteOutcome outPermForbidden = DeleteEngine.ExecuteSingleRecycle(new DeleteRequest
        {
            Path = busyFile,
            BytesAtScan = fiBusy.Length,
            LastWriteUtcAtScan = fiBusy.LastWriteTimeUtc,
            Risk = EvidenceRules.RiskReview
        }, allowedRoots, new PermanentDeleteBin(), logPath);
        Check("D9: PermanentDeleteBin explicitly rejected by ExecuteSingleRecycle",
            outPermForbidden.Status == DeleteStatus.RefusedNotDispatched && outPermForbidden.Kind == DeleteRefusalKind.GateDisabled);

        // D10..D16: Full AnPingBridge headless pipeline test
        string bridgeSandbox = Path.Combine(dRoot, "bridge");
        string bPkg = Path.Combine(bridgeSandbox, "Yarn", "Cache");
        string bMisc = Path.Combine(bridgeSandbox, "DownloadsSub");
        Directory.CreateDirectory(bPkg);
        Directory.CreateDirectory(bMisc);

        string bYarnTgz = Path.Combine(bPkg, "vite-5.0.0.tgz");
        WriteGzipFile(bYarnTgz, Encoding.UTF8.GetBytes("package/dist/node/index.js"));
        string bBigMovie = Path.Combine(bMisc, "recording_demo.mp4");
        File.WriteAllBytes(bBigMovie, new byte[16384]);
        string bKeepLock = Path.Combine(bMisc, "daemon.lock");
        File.WriteAllText(bKeepLock, "active-lock");

        JavaScriptSerializer ser = new JavaScriptSerializer();
        List<Dictionary<string, object>> posted = new List<Dictionary<string, object>>();
        object postGate = new object();

        using (Form dummyForm = new Form())
        using (AnPingBridge bridge = new AnPingBridge(dummyForm, null))
        {
            FakeRecycleBin bridgeFakeBin = new FakeRecycleBin();
            bridge.SetRecycleBinForTest(bridgeFakeBin);
            bridge.SetDeleteLogPathForTest(Path.Combine(bridgeSandbox, "bridge-delete-log.txt"));
            bridge.SetMessageCaptureForTest(delegate(string json)
            {
                lock (postGate)
                {
                    posted.Add(ser.Deserialize<Dictionary<string, object>>(json));
                }
            });

            // 1) Empty quick scan (0 roots) -> friendly scanComplete 0 B
            CacheRoots.ClearInjectedForTest();
            CacheRuleRegistry.SetQuickScanRootsForTest(new string[0]);
            bridge.HandleWebMessage("{\"action\":\"startQuickScan\"}");
            Dictionary<string, object> emptyComplete = FindLastAction(posted, postGate, "scanComplete");
            Check("D10: Empty startQuickScan returns friendly 0 B scanComplete",
                emptyComplete != null && Convert.ToBoolean(emptyComplete["completed"]) && Convert.ToInt32(emptyComplete["fileCount"]) == 0);

            // 2) Multi-root quick scan with injected roots
            lock (postGate) { posted.Clear(); }
            CacheRoots.InjectForTest("TMP-PKGCACHE", bPkg);
            CacheRuleRegistry.SetQuickScanRootsForTest(new string[] { bPkg, bMisc });

            bridge.HandleWebMessage("{\"action\":\"startQuickScan\"}");
            DeadlinePumpBridge(bridge, posted, postGate, "scanComplete", 4000);
            Dictionary<string, object> scanComp = FindLastAction(posted, postGate, "scanComplete");
            Check("D11: Multi-root startQuickScan completes with 3 analyzed files",
                scanComp != null && Convert.ToBoolean(scanComp["completed"]) && Convert.ToInt32(scanComp["fileCount"]) == 3);

            long sid = Convert.ToInt64(scanComp["scanSessionId"]);

            // 3) cleanSummary returns CacheRuleRegistry metadata
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"cleanSummary\",\"request\":11,\"scanSessionId\":" + sid + "}");
            Dictionary<string, object> summaryMsg = FindLastAction(posted, postGate, "cleanSummary");
            ArrayList groups = summaryMsg != null && summaryMsg.ContainsKey("groups") ? summaryMsg["groups"] as ArrayList : null;
            Dictionary<string, object> firstGroup = groups != null && groups.Count > 0 ? groups[0] as Dictionary<string, object> : null;
            Check("D12: cleanSummary dynamically emits rule title & cost from CacheRuleRegistry",
                firstGroup != null
                && Convert.ToString(firstGroup["rule"]) == "TMP-PKGCACHE"
                && Convert.ToString(firstGroup["title"]).IndexOf("Yarn", StringComparison.OrdinalIgnoreCase) >= 0
                && !string.IsNullOrEmpty(Convert.ToString(firstGroup["cost"])));

            // 4) largeFiles defaults to excludeCacheShards: true & supports excludeCacheShards: false
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"largeFiles\",\"request\":12,\"scanSessionId\":" + sid + ",\"limit\":50}");
            Dictionary<string, object> lfMsg = FindLastAction(posted, postGate, "largeFilesPage");
            ArrayList lfFiles = lfMsg != null && lfMsg.ContainsKey("files") ? lfMsg["files"] as ArrayList : null;
            Check("D13: largeFilesPage defaults to excludeCacheShards:true (filters Yarn cache shard, keeps 2 independent files)",
                lfMsg != null
                && Convert.ToBoolean(lfMsg["excludeCacheShards"])
                && Convert.ToInt32(lfMsg["independentCount"]) == 2
                && Convert.ToInt32(lfMsg["allFileCount"]) == 3
                && lfFiles != null && lfFiles.Count == 2
                && Convert.ToString(((Dictionary<string, object>)lfFiles[0])["n"]) == "recording_demo.mp4");

            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"largeFiles\",\"request\":120,\"scanSessionId\":" + sid + ",\"limit\":50,\"excludeCacheShards\":false}");
            Dictionary<string, object> lfAllMsg = FindLastAction(posted, postGate, "largeFilesPage");
            ArrayList lfAllFiles = lfAllMsg != null && lfAllMsg.ContainsKey("files") ? lfAllMsg["files"] as ArrayList : null;
            Check("D13b: largeFilesPage with excludeCacheShards:false returns all 3 files",
                lfAllMsg != null && !Convert.ToBoolean(lfAllMsg["excludeCacheShards"])
                && lfAllFiles != null && lfAllFiles.Count == 3);

            int movieId = -1;
            int lockId = -1;
            for (int i = 0; i < lfFiles.Count; i++)
            {
                var fObj = (Dictionary<string, object>)lfFiles[i];
                string n = Convert.ToString(fObj["n"]);
                if (n == "recording_demo.mp4") movieId = Convert.ToInt32(fObj["id"]);
                if (n == "daemon.lock") lockId = Convert.ToInt32(fObj["id"]);
            }

            // 5) fileTech returns async FileDetailProbe result
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"fileTech\",\"request\":13,\"id\":" + movieId + "}");
            Dictionary<string, object> techMsg = WaitAction(posted, postGate, "fileTechResult", 3000);
            Check("D14: fileTechResult returns real timestamps and 未占用",
                techMsg != null && Convert.ToString(techMsg["process"]) == "未占用" && Convert.ToString(techMsg["created"]) != "无法读取");

            // 6) recycleSingleFile hard-refuses KEEP file & recycles review file on STA thread
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"recycleSingleFile\",\"request\":14,\"scanSessionId\":" + sid + ",\"id\":" + lockId + "}");
            Dictionary<string, object> recKeepMsg = WaitAction(posted, postGate, "recycleSingleResult", 3000);
            Check("D15: Bridge recycleSingleFile refuses keep file",
                recKeepMsg != null && !Convert.ToBoolean(recKeepMsg["success"]) && File.Exists(bKeepLock));

            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"recycleSingleFile\",\"request\":15,\"scanSessionId\":" + sid + ",\"id\":" + movieId + "}");
            Dictionary<string, object> recOkMsg = WaitAction(posted, postGate, "recycleSingleResult", 3000);
            Check("D16: Bridge recycleSingleFile recycles review large file via STA worker",
                recOkMsg != null && Convert.ToBoolean(recOkMsg["success"]) && !File.Exists(bBigMovie) && bridgeFakeBin.RecycledPaths.Count == 1);

            // 7) cleanEligible after multi-root quick scan permanently deletes Yarn cache without OutOfScope!
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"cleanEligible\",\"request\":16,\"scanSessionId\":" + sid + ",\"rules\":[\"TMP-PKGCACHE\"]}");
            Dictionary<string, object> cleanMsg = WaitAction(posted, postGate, "cleanResult", 4000);
            Check("D17: Bridge cleanEligible after startQuickScan deletes multi-root cache cleanly",
                cleanMsg != null && Convert.ToInt32(cleanMsg["deleted"]) == 1 && !File.Exists(bYarnTgz) && File.Exists(bKeepLock));

            // 8) D18..D21: Bridge lockedCacheBytes & largeFiles excludeCacheShards on Chrome Blockfile + user .iso/.mp4
            string mixRoot = Path.Combine(bridgeSandbox, "mix-v072");
            string mixChromeCache = Path.Combine(mixRoot, "Google", "Chrome", "User Data", "Default", "Cache", "Cache_Data");
            string mixDownloads = Path.Combine(mixRoot, "Downloads");
            Directory.CreateDirectory(mixChromeCache);
            Directory.CreateDirectory(mixDownloads);

            WriteChromiumBlockfileHeader(Path.Combine(mixChromeCache, "index"), true, 512);
            string mixData2 = Path.Combine(mixChromeCache, "data_2");
            WriteChromiumBlockfileHeader(mixData2, false, 65536);
            string mixShard1 = Path.Combine(mixChromeCache, "f_000001");
            byte[] shardBuf = new byte[32768];
            shardBuf[0] = 0xFF; shardBuf[1] = 0xD8; shardBuf[2] = 0xFF; shardBuf[3] = 0xE0;
            File.WriteAllBytes(mixShard1, shardBuf);

            string mixIso = Path.Combine(mixDownloads, "Windows11_Setup.iso");
            File.WriteAllBytes(mixIso, new byte[131072]);
            string mixMp4 = Path.Combine(mixDownloads, "screen_capture.mp4");
            File.WriteAllBytes(mixMp4, new byte[98304]);

            CacheRoots.ClearInjectedForTest();
            CacheRoots.InjectForTest("TMP-BROWSERCACHE", mixChromeCache);
            CacheRuleRegistry.ClearQuickScanRootsForTest();

            using (FileStream holdData2 = new FileStream(mixData2, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
            {
                lock (postGate) { posted.Clear(); }
                string escapedMixRoot = mixRoot.Replace("\\", "\\\\");
                bridge.HandleWebMessage("{\"action\":\"startScan\",\"targets\":[\"" + escapedMixRoot + "\"]}");
                DeadlinePumpBridge(bridge, posted, postGate, "scanComplete", 5000);
                Dictionary<string, object> mixComp = FindLastAction(posted, postGate, "scanComplete");
                Check("D18: Bridge scanComplete emits exact lockedCacheBytes for occupied data_2",
                    mixComp != null && Convert.ToInt64(mixComp["lockedCacheBytes"]) == 65536L);

                long mixSid = Convert.ToInt64(mixComp["scanSessionId"]);

                lock (postGate) { posted.Clear(); }
                bridge.HandleWebMessage("{\"action\":\"cleanSummary\",\"request\":21,\"scanSessionId\":" + mixSid + "}");
                Dictionary<string, object> mixSum = FindLastAction(posted, postGate, "cleanSummary");
                Check("D19: Bridge cleanSummary forwards lockedCacheBytes",
                    mixSum != null && Convert.ToInt64(mixSum["lockedCacheBytes"]) == 65536L);

                lock (postGate) { posted.Clear(); }
                bridge.HandleWebMessage("{\"action\":\"largeFiles\",\"request\":22,\"scanSessionId\":" + mixSid + ",\"limit\":50,\"excludeCacheShards\":true}");
                Dictionary<string, object> mixLfIndep = FindLastAction(posted, postGate, "largeFilesPage");
                ArrayList indepArr = mixLfIndep != null ? mixLfIndep["files"] as ArrayList : null;
                bool allSummariesReadable = indepArr != null && indepArr.Count == 2;
                if (allSummariesReadable)
                {
                    string n0 = Convert.ToString(((Dictionary<string, object>)indepArr[0])["n"]);
                    string n1 = Convert.ToString(((Dictionary<string, object>)indepArr[1])["n"]);
                    if (n0 != "Windows11_Setup.iso" || n1 != "screen_capture.mp4") allSummariesReadable = false;
                    for (int k = 0; k < indepArr.Count; k++)
                    {
                        var fItem = (Dictionary<string, object>)indepArr[k];
                        var xItem = fItem["x"] as Dictionary<string, object>;
                        var detItem = xItem != null ? xItem["detail"] as Dictionary<string, object> : null;
                        string sumTxt = detItem != null && detItem.ContainsKey("summary") ? Convert.ToString(detItem["summary"]) : "";
                        if (string.IsNullOrEmpty(sumTxt) || sumTxt.Length > 30) allSummariesReadable = false;
                    }
                }
                Check("D20: largeFiles excludeCacheShards:true filters f_000001/data_2, keeps .iso/.mp4 with readable detail.summary",
                    mixLfIndep != null
                    && Convert.ToInt32(mixLfIndep["independentCount"]) == 2
                    && Convert.ToInt32(mixLfIndep["allFileCount"]) == 5
                    && allSummariesReadable);

                lock (postGate) { posted.Clear(); }
                bridge.HandleWebMessage("{\"action\":\"largeFiles\",\"request\":23,\"scanSessionId\":" + mixSid + ",\"limit\":50,\"excludeCacheShards\":false}");
                Dictionary<string, object> mixLfAll = FindLastAction(posted, postGate, "largeFilesPage");
                ArrayList allArr = mixLfAll != null ? mixLfAll["files"] as ArrayList : null;
                bool data2SummaryOk = false;
                if (allArr != null)
                {
                    for (int k = 0; k < allArr.Count; k++)
                    {
                        var fItem = (Dictionary<string, object>)allArr[k];
                        if (Convert.ToString(fItem["n"]) == "data_2")
                        {
                            var xItem = fItem["x"] as Dictionary<string, object>;
                            var detItem = xItem != null ? xItem["detail"] as Dictionary<string, object> : null;
                            string sumTxt = detItem != null && detItem.ContainsKey("summary") ? Convert.ToString(detItem["summary"]) : "";
                            if (sumTxt.IndexOf("Chrome", StringComparison.OrdinalIgnoreCase) >= 0
                                && sumTxt.IndexOf("占用", StringComparison.Ordinal) >= 0)
                            {
                                data2SummaryOk = true;
                            }
                        }
                    }
                }
                Check("D21: largeFiles excludeCacheShards:false includes data_2 with Chrome occupied summary",
                    allArr != null && allArr.Count == 5 && data2SummaryOk);
            }

            // 9) D22..D24: Bridge compatibility with new v0.8 rules (TMP-APPCACHE, TMP-SYSTEMP->systmp, TMP-WER->dump) & self-root filter
            string v08Root = Path.Combine(bridgeSandbox, "bridge-v08");
            string v08AppCache = Path.Combine(v08Root, "Code", "CachedExtensionVsiXs");
            string v08Temp = Path.Combine(v08Root, "Temp");
            string v08Wer = Path.Combine(v08Root, "Microsoft", "Windows", "WER", "ReportArchive", "AppCrash_1");
            Directory.CreateDirectory(v08AppCache);
            Directory.CreateDirectory(v08Temp);
            Directory.CreateDirectory(v08Wer);

            string v08Vsix = Path.Combine(v08AppCache, "eslint.vsix");
            WriteMinimalZip(v08Vsix, "extension/package.json", Encoding.UTF8.GetBytes("{\"name\":\"eslint\"}"));
            string v08Log = Path.Combine(v08Temp, "aria-old.log");
            File.WriteAllText(v08Log, "expired temp log\r\n");
            File.SetLastWriteTimeUtc(v08Log, DateTime.UtcNow.AddHours(-36));
            string v08WerFile = Path.Combine(v08Wer, "Report.wer");
            WriteUtf16WerReport(v08WerFile);

            // Simulate self-root accidentally included in candidate roots: AnPingBridge must filter it out
            string simulatedSelfSub = Path.Combine(AppDataPaths.Root, "WebView2Data");
            CacheRoots.ClearInjectedForTest();
            CacheRoots.InjectForTest("TMP-APPCACHE", v08AppCache);
            CacheRoots.InjectForTest("TMP-SYSTEMP", v08Temp);
            CacheRoots.InjectForTest("TMP-WER", Path.Combine(v08Root, "Microsoft", "Windows", "WER", "ReportArchive"));
            CacheRuleRegistry.SetQuickScanRootsForTest(new string[] { v08AppCache, v08Temp, Path.Combine(v08Root, "Microsoft", "Windows", "WER", "ReportArchive"), simulatedSelfSub });

            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"startQuickScan\"}");
            DeadlinePumpBridge(bridge, posted, postGate, "scanComplete", 5000);
            Dictionary<string, object> v08Comp = FindLastAction(posted, postGate, "scanComplete");
            ArrayList v08Cats = v08Comp != null ? v08Comp["categories"] as ArrayList : null;
            bool sawAppCat = false, sawSysTmpCat = false, sawDumpCat = false;
            if (v08Cats != null)
            {
                for (int k = 0; k < v08Cats.Count; k++)
                {
                    var catObj = (Dictionary<string, object>)v08Cats[k];
                    string cid = Convert.ToString(catObj["id"]);
                    if (cid == "app") sawAppCat = true;
                    if (cid == "systmp") sawSysTmpCat = true;
                    if (cid == "dump") sawDumpCat = true;
                }
            }
            Check("D22: Bridge aggregates new categories (app, systmp, dump) & filters self AppDataPaths.Root",
                v08Comp != null
                && Convert.ToInt32(v08Comp["fileCount"]) == 3
                && sawAppCat && sawSysTmpCat && sawDumpCat);

            long v08Sid = Convert.ToInt64(v08Comp["scanSessionId"]);
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"cleanSummary\",\"request\":31,\"scanSessionId\":" + v08Sid + "}");
            Dictionary<string, object> v08Sum = FindLastAction(posted, postGate, "cleanSummary");
            ArrayList v08Groups = v08Sum != null ? v08Sum["groups"] as ArrayList : null;
            Check("D23: Bridge cleanSummary emits all 3 new/expanded groups (TMP-APPCACHE, TMP-SYSTEMP, TMP-WER)",
                v08Groups != null && v08Groups.Count == 3);

            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"cleanEligible\",\"request\":32,\"scanSessionId\":" + v08Sid + ",\"rules\":[\"TMP-APPCACHE\",\"TMP-SYSTEMP\",\"TMP-WER\"]}");
            Dictionary<string, object> v08Clean = WaitAction(posted, postGate, "cleanResult", 4000);
            Check("D24: Bridge cleanEligible deletes TMP-APPCACHE, TMP-SYSTEMP & TMP-WER without separate confirm",
                v08Clean != null && Convert.ToInt32(v08Clean["deleted"]) == 3
                && !File.Exists(v08Vsix) && !File.Exists(v08Log) && !File.Exists(v08WerFile));

            // 10) D25..D33: v0.9.0 ChatStorageLocator + startChatScan + largeFiles(chat) + KEEP-CHATDB recycle block + 50ms cleanProgress throttle + PruneEmptyParentDirs + UAC StartupAutoAction & relaunchAdmin
            string v09Root = Path.Combine(bridgeSandbox, "bridge-v09-chat");
            string v09Wc = Path.Combine(v09Root, "WeChat Files");
            string v09Qq = Path.Combine(v09Root, "Tencent Files");
            string v09SnsMonth = Path.Combine(v09Wc, "wxid_demo", "FileStorage", "Sns", "Cache", "2026-11");
            string v09Applet = Path.Combine(v09Wc, "All Users", "Applet", "wx999");
            string v09WcFile = Path.Combine(v09Wc, "wxid_demo", "FileStorage", "File", "2026-11");
            string v09WcVideo = Path.Combine(v09Wc, "wxid_demo", "FileStorage", "Video", "2026-11");
            string v09WcMsg = Path.Combine(v09Wc, "wxid_demo", "Msg", "Multi");
            string v09QqRecv = Path.Combine(v09Qq, "10001", "FileRecv");
            Directory.CreateDirectory(v09SnsMonth);
            Directory.CreateDirectory(v09Applet);
            Directory.CreateDirectory(v09WcFile);
            Directory.CreateDirectory(v09WcVideo);
            Directory.CreateDirectory(v09WcMsg);
            Directory.CreateDirectory(v09QqRecv);

            // 40 Sns\Cache files + 1 .wxapkg (41 pure cache files)
            for (int m = 1; m <= 40; m++)
            {
                string sp = Path.Combine(v09SnsMonth, "sns_img_" + m.ToString("000") + ".jpg");
                File.WriteAllBytes(sp, new byte[] { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, (byte)m, 2, 3, 4, 5, 6, 7, 8 });
            }
            string v09Pkg = Path.Combine(v09Applet, "pkg.wxapkg");
            WriteWxapkg(v09Pkg);

            // 3 chat received user files + 1 KEEP-CHATDB database
            string v09Pdf = Path.Combine(v09WcFile, "项目合同.pdf");
            File.WriteAllBytes(v09Pdf, Encoding.ASCII.GetBytes("%PDF-1.7 important user contract payload 0123456789"));
            string v09Mp4 = Path.Combine(v09WcVideo, "家庭录像.mp4");
            WriteMp4Header(v09Mp4, 4096);
            string v09Xlsx = Path.Combine(v09QqRecv, "报价表.xlsx");
            WriteMinimalZip(v09Xlsx, "xl/workbook.xml", Encoding.UTF8.GetBytes("<workbook/>"));
            string v09MsgDb = Path.Combine(v09WcMsg, "MSG0.db");
            File.WriteAllBytes(v09MsgDb, Encoding.ASCII.GetBytes("SQLite format 3\0wechat-msg0-protected-database"));

            CacheRoots.ClearInjectedForTest();
            CacheRuleRegistry.ClearQuickScanRootsForTest();
            ChatStorageLocator.SetMockChatRootsForTest(new ChatStorageLocator.ChatDataFolder[]
            {
                new ChatStorageLocator.ChatDataFolder { AppName = "微信", Kind = "wechat", Path = v09Wc },
                new ChatStorageLocator.ChatDataFolder { AppName = "QQ", Kind = "qq", Path = v09Qq }
            });

            // Direct ExecuteSingleRecycle on MSG0.db must hard-refuse even if caller spoofs RiskReview!
            FileInfo fiMsgDb = new FileInfo(v09MsgDb);
            DeleteOutcome outMsgDb = DeleteEngine.ExecuteSingleRecycle(new DeleteRequest
            {
                Path = v09MsgDb,
                WasDirectory = false,
                BytesAtScan = fiMsgDb.Length,
                LastWriteUtcAtScan = fiMsgDb.LastWriteTimeUtc,
                Risk = EvidenceRules.RiskReview
            }, new string[] { v09Wc }, bridgeFakeBin, Path.Combine(bridgeSandbox, "bridge-delete-log.txt"));
            Check("D25: ExecuteSingleRecycle hard-refuses KEEP-CHATDB MSG0.db even when RiskReview spoofed",
                outMsgDb.Status == DeleteStatus.RefusedNotDispatched && !outMsgDb.WasDispatched && File.Exists(v09MsgDb));

            // getDrives returns chatFolders & accurately formatted GB drive descriptions
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"getDrives\"}");
            Dictionary<string, object> drivesMsg = FindLastAction(posted, postGate, "drivesList");
            ArrayList chatFoldersArr = drivesMsg != null && drivesMsg.ContainsKey("chatFolders") ? drivesMsg["chatFolders"] as ArrayList : null;
            ArrayList drivesArr = drivesMsg != null && drivesMsg.ContainsKey("drives") ? drivesMsg["drives"] as ArrayList : null;
            bool driveDescAccurate = AnPingBridge.FormatGb(200L * 1024L * 1024L * 1024L) == "200.0 GB"
                && AnPingBridge.FormatGb((long)(66.12 * 1024.0 * 1024.0 * 1024.0)) == "66.1 GB"
                && drivesArr != null && drivesArr.Count > 0;
            if (driveDescAccurate)
            {
                for (int k = 0; k < drivesArr.Count; k++)
                {
                    var dObj = (Dictionary<string, object>)drivesArr[k];
                    string dPath = Convert.ToString(dObj["path"]);
                    string dDesc = Convert.ToString(dObj["desc"]);
                    DriveInfo realDi = new DriveInfo(dPath);
                    string expectedTotal = AnPingBridge.FormatGb(realDi.TotalSize);
                    if (!System.Text.RegularExpressions.Regex.IsMatch(dDesc, @"^可用 \d+\.\d GB / 共 \d+\.\d GB$")
                        || !dDesc.EndsWith(" / 共 " + expectedTotal, StringComparison.Ordinal))
                    {
                        driveDescAccurate = false;
                    }
                }
            }
            Check("D26: drivesList includes mocked chatFolders & accurate FormatGb drive descriptions",
                chatFoldersArr != null && chatFoldersArr.Count == 2 && driveDescAccurate);

            // startChatScan full pipeline + drive context & admin metadata
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"startChatScan\"}");
            DeadlinePumpBridge(bridge, posted, postGate, "scanComplete", 6000);
            Dictionary<string, object> chatStarted = FindLastAction(posted, postGate, "scanStarted");
            Dictionary<string, object> chatComp = FindLastAction(posted, postGate, "scanComplete");
            Check("D27: startChatScan analyzes all 45 files and emits driveFreeBytes/driveTotalBytes & admin flags",
                chatStarted != null
                && Convert.ToBoolean(chatStarted["chat"])
                && Convert.ToString(chatStarted["target"]).StartsWith("微信 / QQ 存储空间", StringComparison.Ordinal)
                && chatComp != null
                && Convert.ToBoolean(chatComp["completed"])
                && Convert.ToInt32(chatComp["fileCount"]) == 45
                && Convert.ToInt64(chatComp["driveTotalBytes"]) > 0L
                && chatComp.ContainsKey("isAdmin")
                && chatComp.ContainsKey("hasAdminTargets"));

            long chatSid = Convert.ToInt64(chatComp["scanSessionId"]);

            // largeFiles(filterMode="chat") returns exact 3 chat received user files, 0 cache shards, 0 MSG0.db
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"largeFiles\",\"request\":41,\"scanSessionId\":" + chatSid + ",\"limit\":50,\"filterMode\":\"chat\"}");
            Dictionary<string, object> lfChatMsg = FindLastAction(posted, postGate, "largeFilesPage");
            ArrayList lfChatFiles = lfChatMsg != null && lfChatMsg.ContainsKey("files") ? lfChatMsg["files"] as ArrayList : null;
            bool chatNamesExact = lfChatFiles != null && lfChatFiles.Count == 3;
            if (chatNamesExact)
            {
                HashSet<string> gotNames = new HashSet<string>(StringComparer.Ordinal);
                for (int k = 0; k < lfChatFiles.Count; k++)
                {
                    gotNames.Add(Convert.ToString(((Dictionary<string, object>)lfChatFiles[k])["n"]));
                }
                chatNamesExact = gotNames.Contains("家庭录像.mp4")
                    && gotNames.Contains("项目合同.pdf")
                    && gotNames.Contains("报价表.xlsx")
                    && !gotNames.Contains("MSG0.db")
                    && !gotNames.Contains("pkg.wxapkg");
            }
            Check("D28: largeFiles(filterMode=chat) returns exact 3 chat received files & excludes pure caches + MSG0.db",
                lfChatMsg != null
                && Convert.ToString(lfChatMsg["filterMode"]) == "chat"
                && Convert.ToInt32(lfChatMsg["chatFileCount"]) == 3
                && Convert.ToInt64(lfChatMsg["chatFileBytes"]) > 0L
                && Convert.ToInt32(lfChatMsg["independentCount"]) == 4
                && Convert.ToInt32(lfChatMsg["allFileCount"]) == 45
                && chatNamesExact);

            // Find MSG0.db id via filterMode="independent" and verify Bridge recycleSingleFile hard-refuses it
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"largeFiles\",\"request\":42,\"scanSessionId\":" + chatSid + ",\"limit\":50,\"filterMode\":\"independent\"}");
            Dictionary<string, object> lfIndepChat = FindLastAction(posted, postGate, "largeFilesPage");
            ArrayList indepChatFiles = lfIndepChat != null ? lfIndepChat["files"] as ArrayList : null;
            int msgDbFileId = -1;
            if (indepChatFiles != null)
            {
                for (int k = 0; k < indepChatFiles.Count; k++)
                {
                    var fObj = (Dictionary<string, object>)indepChatFiles[k];
                    if (Convert.ToString(fObj["n"]) == "MSG0.db")
                    {
                        msgDbFileId = Convert.ToInt32(fObj["id"]);
                        Check("D29a: ProjectFile marks MSG0.db judgement=='keep'", Convert.ToString(fObj["j"]) == "keep");
                    }
                }
            }
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"recycleSingleFile\",\"request\":43,\"scanSessionId\":" + chatSid + ",\"id\":" + msgDbFileId + "}");
            Dictionary<string, object> recMsgDbRes = WaitAction(posted, postGate, "recycleSingleResult", 3000);
            Check("D29b: Bridge recycleSingleFile hard-refuses MSG0.db",
                msgDbFileId > 0 && recMsgDbRes != null && !Convert.ToBoolean(recMsgDbRes["success"]) && File.Exists(v09MsgDb));

            // Clean TMP-CHATCACHE: verify 41 cache files deleted, 50ms cleanProgress throttling, empty Sns\Cache\2026-11 pruned, and all 4 user/db files untouched!
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"cleanEligible\",\"request\":44,\"scanSessionId\":" + chatSid + ",\"rules\":[\"TMP-CHATCACHE\"]}");
            Dictionary<string, object> chatCleanRes = WaitAction(posted, postGate, "cleanResult", 5000);
            int cleanProgCount = 0;
            Dictionary<string, object> lastCleanProg = null;
            lock (postGate)
            {
                for (int k = 0; k < posted.Count; k++)
                {
                    object act;
                    if (posted[k] != null && posted[k].TryGetValue("action", out act) && Convert.ToString(act) == "cleanProgress")
                    {
                        cleanProgCount++;
                        lastCleanProg = posted[k];
                    }
                }
            }
            Check("D30: cleanEligible deletes 41 chat cache files, throttles cleanProgress, prunes empty Sns\\Cache\\2026-11 & preserves chat files/MSG0.db",
                chatCleanRes != null
                && Convert.ToInt32(chatCleanRes["deleted"]) == 41
                && Convert.ToInt32(chatCleanRes["prunedDirs"]) >= 1
                && !Directory.Exists(v09SnsMonth)
                && Directory.Exists(v09Wc)
                && File.Exists(v09Pdf) && File.Exists(v09Mp4) && File.Exists(v09Xlsx) && File.Exists(v09MsgDb)
                && cleanProgCount >= 2 && cleanProgCount < 25
                && lastCleanProg != null && Convert.ToInt32(lastCleanProg["done"]) == 41);

            // UAC StartupAutoAction one-shot consumption & relaunchAdmin test seam (zero real UAC prompt!)
            Program.ParseStartupArgs(new string[] { "--chat-scan" });
            Check("D31a: Program.ParseStartupArgs('--chat-scan') sets StartupAutoAction=='chat'",
                Program.StartupAutoAction == "chat");

            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"init\"}");
            Dictionary<string, object> autoChatStarted = FindLastAction(posted, postGate, "scanStarted");
            DeadlinePumpBridge(bridge, posted, postGate, "scanComplete", 5000);
            Check("D31b: First init consumes StartupAutoAction='chat' and auto-triggers StartChatScan",
                autoChatStarted != null && Convert.ToBoolean(autoChatStarted["chat"]) && Program.StartupAutoAction == "");

            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"init\"}");
            Dictionary<string, object> initStateMsg = FindLastAction(posted, postGate, "initState");
            Check("D31c: Second init does not re-trigger auto scan & emits live home drive/chat context",
                FindLastAction(posted, postGate, "scanStarted") == null
                && initStateMsg != null
                && !string.IsNullOrEmpty(Convert.ToString(initStateMsg["driveLabel"]))
                && Convert.ToInt64(initStateMsg["driveFreeBytes"]) > 0L
                && Convert.ToInt64(initStateMsg["driveTotalBytes"]) > 0L
                && Convert.ToInt32(initStateMsg["chatFolderCount"]) == 2);

            string capturedRelaunchArg = "";
            bridge.SetRelaunchHandlerForTest(delegate(string arg, out bool cancelled, out string err)
            {
                capturedRelaunchArg = arg;
                cancelled = true;
                err = "已取消管理员授权，继续以普通模式运行。";
                return false;
            });
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"relaunchAdmin\",\"mode\":\"quick\"}");
            Dictionary<string, object> uacCancelRes = FindLastAction(posted, postGate, "relaunchAdminResult");
            Check("D32: relaunchAdmin cancel returns ok=false, cancelled=true & keeps hostForm open",
                uacCancelRes != null
                && !Convert.ToBoolean(uacCancelRes["ok"])
                && Convert.ToBoolean(uacCancelRes["cancelled"])
                && capturedRelaunchArg == "--quick-scan"
                && !dummyForm.IsDisposed);

            IntPtr dummyHandle = dummyForm.Handle;
            bool formClosingFired = false;
            dummyForm.FormClosing += delegate(object s, FormClosingEventArgs ev) { formClosingFired = true; };
            bridge.SetRelaunchHandlerForTest(delegate(string arg, out bool cancelled, out string err)
            {
                capturedRelaunchArg = arg;
                cancelled = false;
                err = "";
                return true;
            });
            lock (postGate) { posted.Clear(); }
            bridge.HandleWebMessage("{\"action\":\"relaunchAdmin\",\"mode\":\"chat\"}");
            Application.DoEvents();
            Dictionary<string, object> uacOkRes = FindLastAction(posted, postGate, "relaunchAdminResult");
            Check("D33: relaunchAdmin ok=true passes '--chat-scan' & closes hostForm cleanly",
                dummyHandle != IntPtr.Zero
                && uacOkRes != null
                && Convert.ToBoolean(uacOkRes["ok"])
                && capturedRelaunchArg == "--chat-scan"
                && formClosingFired);

            System.Reflection.Assembly selfAsm = typeof(Program).Assembly;
            object[] infoAttrs = selfAsm.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false);
            string infoVer = infoAttrs.Length > 0 ? ((System.Reflection.AssemblyInformationalVersionAttribute)infoAttrs[0]).InformationalVersion : "";
            Check("D34: Assembly version is 1.0.0.0 / v1.0.0",
                selfAsm.GetName().Version.ToString() == "1.0.0.0" && infoVer == "v1.0.0");

            ChatStorageLocator.ClearMockChatRootsForTest();
        }
    }

    // =====================================================================
    // Group E: v1.0.0 Official Release Hardening (Log Rotate / Mutex / PE)
    // =====================================================================
    private static void RunGroupE(string sandbox)
    {
        string logDir = Path.Combine(sandbox, "groupE-log");
        Directory.CreateDirectory(logDir);

        // --- E1: DeleteLog.RotateIfOversizedAndClean positive & negative ---
        string smallLog = Path.Combine(logDir, "small-log.txt");
        string why;
        DeleteRequest sampleReq = new DeleteRequest();
        sampleReq.Path = Path.Combine(logDir, "dummy_cache_item.bin");
        sampleReq.WasDirectory = false;
        sampleReq.BytesAtScan = 4096;
        sampleReq.LastWriteUtcAtScan = DateTime.UtcNow;
        sampleReq.Risk = "ok";

        DeleteOutcome sampleOut = new DeleteOutcome();
        sampleOut.Path = sampleReq.Path;
        sampleOut.Status = DeleteStatus.DeletedVerified;
        sampleOut.Kind = DeleteRefusalKind.None;
        sampleOut.Detail = "verified";

        Check("E1a: Write single clean pair to small log",
            DeleteLog.EnsureWritable(smallLog, out why)
            && DeleteLog.WriteIntent(smallLog, "op_small_1", "batch_e1", sampleReq, sampleReq.Path, out why)
            && DeleteLog.WriteOutcome(smallLog, "op_small_1", "batch_e1", sampleOut, out why));
        Check("E1b: Under-threshold clean log is not rotated",
            new FileInfo(smallLog).Length <= 1024
            && !DeleteLog.RotateIfOversizedAndClean(smallLog, 1024)
            && File.Exists(smallLog));

        string cleanLog = Path.Combine(logDir, "delete-log.txt");
        string cleanArchive = Path.Combine(logDir, "delete-log.old.txt");
        DeleteLog.EnsureWritable(cleanLog, out why);
        for (int i = 0; i < 12; i++)
        {
            string opId = "op_clean_" + i.ToString("00");
            string p = Path.Combine(logDir, "clean_cache_payload_" + i.ToString("00") + ".cache");
            sampleReq.Path = p;
            sampleOut.Path = p;
            DeleteLog.WriteIntent(cleanLog, opId, "batch_clean", sampleReq, p, out why);
            DeleteLog.WriteOutcome(cleanLog, opId, "batch_clean", sampleOut, out why);
        }
        long cleanLenBefore = new FileInfo(cleanLog).Length;
        Check("E1c: Clean oversized log setup (>1024 bytes & 0 pending)",
            cleanLenBefore > 1024 && DeleteLog.PendingOps(cleanLog).Count == 0);

        bool rotatedClean = DeleteLog.RotateIfOversizedAndClean(cleanLog, 1024);
        Check("E1d: Clean oversized log rotates to .old.txt and clears active path",
            rotatedClean
            && !File.Exists(cleanLog)
            && File.Exists(cleanArchive)
            && new FileInfo(cleanArchive).Length == cleanLenBefore);

        // Second clean rotation replaces previous .old.txt cleanly (single backup cap)
        DeleteLog.EnsureWritable(cleanLog, out why);
        for (int i = 0; i < 14; i++)
        {
            string opId = "op_clean2_" + i.ToString("00");
            string p = Path.Combine(logDir, "clean_cache_second_" + i.ToString("00") + ".cache");
            sampleReq.Path = p;
            sampleOut.Path = p;
            DeleteLog.WriteIntent(cleanLog, opId, "batch_clean2", sampleReq, p, out why);
            DeleteLog.WriteOutcome(cleanLog, opId, "batch_clean2", sampleOut, out why);
        }
        long secondLen = new FileInfo(cleanLog).Length;
        bool rotatedClean2 = DeleteLog.RotateIfOversizedAndClean(cleanLog, 1024);
        Check("E1e: Subsequent clean rotation overwrites single .old.txt archive",
            rotatedClean2
            && !File.Exists(cleanLog)
            && File.Exists(cleanArchive)
            && new FileInfo(cleanArchive).Length == secondLen);

        // Negative case: oversized log containing 1 unresolved Intent (no Outcome) MUST NOT rotate
        string dirtyLog = Path.Combine(logDir, "dirty-log.txt");
        string dirtyArchive = Path.Combine(logDir, "dirty-log.old.txt");
        DeleteLog.EnsureWritable(dirtyLog, out why);
        for (int i = 0; i < 10; i++)
        {
            string opId = "op_ok_" + i.ToString("00");
            string p = Path.Combine(logDir, "ok_before_crash_" + i.ToString("00") + ".cache");
            sampleReq.Path = p;
            sampleOut.Path = p;
            DeleteLog.WriteIntent(dirtyLog, opId, "batch_dirty", sampleReq, p, out why);
            DeleteLog.WriteOutcome(dirtyLog, opId, "batch_dirty", sampleOut, out why);
        }
        string pendingTarget = Path.Combine(logDir, "unresolved_crash_item.tmp");
        sampleReq.Path = pendingTarget;
        DeleteLog.WriteIntent(dirtyLog, "op_pending_crash_99", "batch_dirty", sampleReq, pendingTarget, out why);

        byte[] dirtyBeforeBytes = File.ReadAllBytes(dirtyLog);
        Check("E1f: Dirty oversized log setup (>1024 bytes & 1 pending op)",
            dirtyBeforeBytes.Length > 1024 && DeleteLog.PendingOps(dirtyLog).Count == 1);

        bool rotatedDirty = DeleteLog.RotateIfOversizedAndClean(dirtyLog, 1024);
        byte[] dirtyAfterBytes = File.Exists(dirtyLog) ? File.ReadAllBytes(dirtyLog) : new byte[0];
        bool bytesIdentical = dirtyBeforeBytes.Length == dirtyAfterBytes.Length;
        if (bytesIdentical)
        {
            for (int i = 0; i < dirtyBeforeBytes.Length; i++)
            {
                if (dirtyBeforeBytes[i] != dirtyAfterBytes[i]) { bytesIdentical = false; break; }
            }
        }
        List<KeyValuePair<string, string>> pendingAfter = DeleteLog.PendingOps(dirtyLog);
        Check("E1g: Dirty oversized log refuses rotation & preserves file 100% intact",
            !rotatedDirty
            && File.Exists(dirtyLog)
            && !File.Exists(dirtyArchive)
            && bytesIdentical
            && pendingAfter.Count == 1
            && pendingAfter[0].Key == "op_pending_crash_99"
            && pendingAfter[0].Value == pendingTarget);

        // --- E2: Portable directory instance mutex & activate message determinism/isolation ---
        string dirAData = Path.Combine(Path.Combine(sandbox, "portableA"), "data");
        string dirBData = Path.Combine(Path.Combine(sandbox, "portableB"), "data");
        Directory.CreateDirectory(dirAData);
        Directory.CreateDirectory(dirBData);

        string dirASlashVariant = dirAData.Replace('\\', '/') + "/";
        string dirAUpperTrailing = dirAData.ToUpperInvariant() + "\\";

        string mutexA1 = Program.BuildInstanceMutexName(dirAData);
        string mutexA2 = Program.BuildInstanceMutexName(dirASlashVariant);
        string mutexA3 = Program.BuildInstanceMutexName(dirAUpperTrailing);
        string mutexB1 = Program.BuildInstanceMutexName(dirBData);

        Check("E2a: BuildInstanceMutexName format & slash/case determinism",
            mutexA1 != null
            && mutexA1.StartsWith("Local\\AnPing_Instance_", StringComparison.Ordinal)
            && mutexA1.Length == "Local\\AnPing_Instance_".Length + 16
            && mutexA1 == mutexA2
            && mutexA1 == mutexA3);
        Check("E2b: BuildInstanceMutexName isolates distinct portable directories",
            mutexB1 != null
            && mutexB1.StartsWith("Local\\AnPing_Instance_", StringComparison.Ordinal)
            && mutexA1 != mutexB1);

        string actA1 = Program.BuildActivateMessageName(dirAData);
        string actA2 = Program.BuildActivateMessageName(dirASlashVariant);
        string actB1 = Program.BuildActivateMessageName(dirBData);
        Check("E2c: BuildActivateMessageName determinism & directory isolation",
            actA1 != null
            && actA1.StartsWith("AnPing_Activate_", StringComparison.Ordinal)
            && actA1 == actA2
            && actA1 != actB1);

        // --- E3: Official v1.0.0 binary PE version metadata & native icon resource ---
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string exeCandidate1 = Path.GetFullPath(Path.Combine(baseDir, "..", "can-i-delete.exe"));
        string exeCandidate2 = Path.GetFullPath(Path.Combine(baseDir, "can-i-delete.exe"));
        string exePath = File.Exists(exeCandidate1) ? exeCandidate1 : exeCandidate2;

        Check("E3a: Compiled can-i-delete.exe exists for PE inspection", File.Exists(exePath));
        if (File.Exists(exePath))
        {
            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(exePath);
            Check("E3b: PE FileVersion == 1.0.0.0, ProductName == 按平, ProductVersion contains 1.0.0",
                fvi != null
                && fvi.FileVersion == "1.0.0.0"
                && fvi.ProductName == "按平"
                && fvi.ProductVersion != null
                && fvi.ProductVersion.IndexOf("1.0.0", StringComparison.Ordinal) >= 0);

            using (Icon assocIcon = Icon.ExtractAssociatedIcon(exePath))
            {
                Check("E3c: ExtractAssociatedIcon(can-i-delete.exe) is non-null with valid dimensions",
                    assocIcon != null && assocIcon.Width > 0 && assocIcon.Height > 0);
            }
        }

        string icoCandidate1 = Path.GetFullPath(Path.Combine(baseDir, "..", "assets", "app.ico"));
        string icoCandidate2 = Path.GetFullPath(Path.Combine(baseDir, "assets", "app.ico"));
        string icoPath = File.Exists(icoCandidate1) ? icoCandidate1 : icoCandidate2;
        Check("E3d: Native multi-size assets\\app.ico exists and loads cleanly", File.Exists(icoPath));
        if (File.Exists(icoPath))
        {
            using (Icon rawIcon = new Icon(icoPath, new Size(256, 256)))
            {
                Check("E3e: assets\\app.ico loads valid Icon frame",
                    rawIcon != null && rawIcon.Width > 0 && rawIcon.Height > 0);
            }
        }

        // --- E4: Graceful close helper safety when idle ---
        using (Form f = new Form())
        using (AnPingBridge b = new AnPingBridge(f, null))
        {
            b.StopFileOpGracefully(100);
            Check("E4: AnPingBridge.IsBusyWithFileOp is false when idle & StopFileOpGracefully is safe",
                !b.IsBusyWithFileOp);
        }
    }

    // =====================================================================
    // Group F: Full-Stack Security Audit Regression Suite (F1-F7)
    // =====================================================================
    private static void RunGroupF(string sandbox)
    {
        // --- F1 (RULE-01): Real Office OOXML OPC Bypass vs Genuine .nupkg / .vsix ---
        string f1Root = Path.Combine(sandbox, "groupF-f1");
        string f1Yarn = Path.Combine(f1Root, "Yarn", "Cache");
        string f1Nuget = Path.Combine(f1Root, "NuGet", "v3-cache");
        string f1Temp = Path.Combine(f1Root, "Temp");
        string f1Inno = Path.Combine(f1Temp, "is-abc12.tmp");
        string f1Vsix = Path.Combine(f1Root, "Code", "CachedExtensionVsiXs");
        Directory.CreateDirectory(f1Yarn);
        Directory.CreateDirectory(f1Nuget);
        Directory.CreateDirectory(f1Inno);
        Directory.CreateDirectory(f1Vsix);

        CacheRoots.ClearInjectedForTest();
        try
        {
            CacheRoots.InjectForTest("TMP-PKGCACHE", f1Yarn);
            CacheRoots.InjectForTest("TMP-PKGCACHE", f1Nuget);
            CacheRoots.InjectForTest("TMP-SYSTEMP", f1Temp);
            CacheRoots.InjectForTest("TMP-APPCACHE", f1Vsix);

            byte[] contentTypesXml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"/>");
            byte[] wordDocXml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><w:document/>");
            byte[] nuspecXml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><package><metadata><id>demo</id></metadata></package>");
            byte[] extPkgJson = Encoding.UTF8.GetBytes("{\"name\":\"demo-ext\",\"version\":\"1.0.0\"}");

            string[] opcOfficeEntries = new string[] { "[Content_Types].xml", "word/document.xml" };
            byte[][] opcOfficeBodies = new byte[][] { contentTypesXml, wordDocXml };

            string yarnOpcDoc = Path.Combine(f1Yarn, "real-office-opc.zip");
            WriteMultiEntryZip(yarnOpcDoc, opcOfficeEntries, opcOfficeBodies);

            string tempOpcDoc = Path.Combine(f1Inno, "real-office-opc.zip");
            WriteMultiEntryZip(tempOpcDoc, opcOfficeEntries, opcOfficeBodies);
            File.SetLastWriteTimeUtc(tempOpcDoc, DateTime.UtcNow.AddHours(-60));

            string vsixOpcDoc = Path.Combine(f1Vsix, "real-office-opc.vsix");
            WriteMultiEntryZip(vsixOpcDoc, opcOfficeEntries, opcOfficeBodies);

            Check("F1a: Real ECMA-376 OPC Office .zip rejected in Yarn\\Cache, Temp\\is-abc12.tmp (>48h) & Code\\CachedExtensionVsiXs",
                !DecideFile(yarnOpcDoc).PolicyEligible
                && !DecideFile(tempOpcDoc).PolicyEligible
                && !DecideFile(vsixOpcDoc).PolicyEligible);

            string yarnStreamErr, tempStreamErr, vsixStreamErr;
            using (FileStream fs = File.OpenRead(yarnOpcDoc))
                yarnStreamErr = CacheRuleRegistry.Find("TMP-PKGCACHE").VerifyStream(yarnOpcDoc, fs);
            using (FileStream fs = File.OpenRead(tempOpcDoc))
                tempStreamErr = CacheRuleRegistry.Find("TMP-SYSTEMP").VerifyStream(tempOpcDoc, fs);
            using (FileStream fs = File.OpenRead(vsixOpcDoc))
                vsixStreamErr = CacheRuleRegistry.Find("TMP-APPCACHE").VerifyStream(vsixOpcDoc, fs);
            Check("F1b: Delete-time VerifyStream also rejects real ECMA-376 OPC Office .zip across all 3 rules",
                yarnStreamErr != null && tempStreamErr != null && vsixStreamErr != null);

            string legitNupkg = Path.Combine(f1Nuget, "demo.1.0.0.nupkg");
            WriteMultiEntryZip(legitNupkg,
                new string[] { "[Content_Types].xml", "demo.nuspec" },
                new byte[][] { contentTypesXml, nuspecXml });

            string legitVsix = Path.Combine(f1Vsix, "legit-opc.vsix");
            WriteMultiEntryZip(legitVsix,
                new string[] { "[Content_Types].xml", "extension/package.json" },
                new byte[][] { contentTypesXml, extPkgJson });

            Evidence nupkgEv = DecideFile(legitNupkg);
            Evidence vsixEv = DecideFile(legitVsix);
            string nupkgStreamErr, legitVsixStreamErr;
            using (FileStream fs = File.OpenRead(legitNupkg))
                nupkgStreamErr = CacheRuleRegistry.Find("TMP-PKGCACHE").VerifyStream(legitNupkg, fs);
            using (FileStream fs = File.OpenRead(legitVsix))
                legitVsixStreamErr = CacheRuleRegistry.Find("TMP-APPCACHE").VerifyStream(legitVsix, fs);

            Check("F1c: Genuine OPC .nupkg ([Content_Types].xml + demo.nuspec) & .vsix ([Content_Types].xml + extension/package.json) remain PolicyEligible",
                nupkgEv.PolicyEligible && nupkgEv.RuleId == "TMP-PKGCACHE" && nupkgStreamErr == null
                && vsixEv.PolicyEligible && vsixEv.RuleId == "TMP-APPCACHE" && legitVsixStreamErr == null);

            // F1d: Truncated OPC Central Directory (scanned < totalEntries) & corrupt totalEntries==0 with cdSize>0 fail closed
            string truncOpcZip = Path.Combine(f1Yarn, "truncated_opc.zip");
            WriteCraftedEocdZip(truncOpcZip, "[Content_Types].xml", contentTypesXml, 2, false, false);
            string zeroEntriesCorruptZip = Path.Combine(f1Yarn, "zero_entries_corrupt.zip");
            WriteCraftedEocdZip(zeroEntriesCorruptZip, "entry.txt", Encoding.ASCII.GetBytes("payload"), 0, false, false);

            string truncStreamErr, zeroStreamErr;
            using (FileStream fs = File.OpenRead(truncOpcZip))
                truncStreamErr = CacheRuleRegistry.Find("TMP-PKGCACHE").VerifyStream(truncOpcZip, fs);
            using (FileStream fs = File.OpenRead(zeroEntriesCorruptZip))
                zeroStreamErr = CacheRuleRegistry.Find("TMP-PKGCACHE").VerifyStream(zeroEntriesCorruptZip, fs);
            Check("F1d: Truncated OPC CD (scanned < totalEntries) & corrupt totalEntries==0 (cdSize>0) fail closed at scan & delete",
                !DecideFile(truncOpcZip).PolicyEligible && truncStreamErr != null
                && !DecideFile(zeroEntriesCorruptZip).PolicyEligible && zeroStreamErr != null);

            // F1e: ZIP64 Office fail-closed (even when entry #1 is NOT [Content_Types].xml) vs non-OPC .nupkg allowed
            string zip64Yarn = Path.Combine(f1Yarn, "zip64_doc.zip");
            WriteCraftedEocdZip(zip64Yarn, "doc.bin", Encoding.ASCII.GetBytes("data"), 0xFFFF, true, false);
            string zip64Temp = Path.Combine(f1Inno, "zip64_doc.zip");
            WriteCraftedEocdZip(zip64Temp, "doc.bin", Encoding.ASCII.GetBytes("data"), 0xFFFF, true, false);
            File.SetLastWriteTimeUtc(zip64Temp, DateTime.UtcNow.AddHours(-60));
            string zip64OpcNupkg = Path.Combine(f1Nuget, "zip64_opc.nupkg");
            WriteCraftedEocdZip(zip64OpcNupkg, "[Content_Types].xml", contentTypesXml, 0xFFFF, true, false);
            string zip64LegitNupkg = Path.Combine(f1Nuget, "zip64_legit.nupkg");
            WriteCraftedEocdZip(zip64LegitNupkg, "demo.nuspec", nuspecXml, 0xFFFF, true, false);

            string z64YarnErr, z64TempErr;
            using (FileStream fs = File.OpenRead(zip64Yarn))
                z64YarnErr = CacheRuleRegistry.Find("TMP-PKGCACHE").VerifyStream(zip64Yarn, fs);
            using (FileStream fs = File.OpenRead(zip64Temp))
                z64TempErr = CacheRuleRegistry.Find("TMP-SYSTEMP").VerifyStream(zip64Temp, fs);
            Check("F1e: ZIP64 .zip & OPC ZIP64 .nupkg fail closed while non-OPC ZIP64 .nupkg stays eligible",
                !DecideFile(zip64Yarn).PolicyEligible && z64YarnErr != null
                && !DecideFile(zip64Temp).PolicyEligible && z64TempErr != null
                && !DecideFile(zip64OpcNupkg).PolicyEligible
                && DecideFile(zip64LegitNupkg).PolicyEligible);
        }
        finally
        {
            CacheRoots.ClearInjectedForTest();
        }

        // --- F2 (ENG-01 / RULE-02): Ancestor-Above-ScanRoot Junction & Final-Path Verification ---
        string f2Root = Path.Combine(sandbox, "groupF-f2");
        string f2Protected = Path.Combine(f2Root, "ProtectedTarget");
        string f2ProtectedSub = Path.Combine(f2Protected, "sub");
        string f2Temp = Path.Combine(f2Root, "Temp");
        string f2Junc = Path.Combine(f2Temp, "is-junc1.tmp");
        Directory.CreateDirectory(f2ProtectedSub);
        Directory.CreateDirectory(f2Temp);

        string f2VictimReal = Path.Combine(f2ProtectedSub, "victim.dll");
        WritePeExe(f2VictimReal);
        File.SetLastWriteTimeUtc(f2VictimReal, DateTime.UtcNow.AddHours(-60));

        bool f2JuncCreated = TryCreateJunction(f2Junc, f2Protected);
        Check("F2a: Sandbox junction created for ancestor-above-scanroot test", f2JuncCreated);
        if (f2JuncCreated)
        {
            try
            {
                string f2JuncSub = Path.Combine(f2Junc, "sub");
                string f2JuncVictim = Path.Combine(f2JuncSub, "victim.dll");

                ScanSessionHost scanHost = new ScanSessionHost();
                string startWhy;
                bool started = scanHost.StartTargets(new string[] { f2JuncSub }, new ScanBudget(), out startWhy);
                Check("F2b: ScanSessionHost.StartTargets rejects scan root beneath ancestor junction",
                    !started && !string.IsNullOrEmpty(startWhy));

                CacheRoots.InjectForTest("TMP-SYSTEMP", f2Temp);
                FileInfo victimFi = new FileInfo(f2VictimReal);
                FileIdentity victimId = FileIdentityProbe.Capture(f2VictimReal);

                List<DeleteRequest> f2Reqs = new List<DeleteRequest>();
                f2Reqs.Add(new DeleteRequest
                {
                    Path = f2JuncVictim,
                    WasDirectory = false,
                    BytesAtScan = victimFi.Length,
                    LastWriteUtcAtScan = victimFi.LastWriteTimeUtc,
                    PolicyEligible = true,
                    Risk = EvidenceRules.RiskSafe,
                    IdAtScan = victimId
                });
                string f2Log = Path.Combine(f2Root, "f2-delete-log.txt");
                List<DeleteOutcome> f2Outs = DeleteEngine.Execute(f2Reqs, new string[] { f2JuncSub }, new PermanentDeleteBin(), f2Log);
                Check("F2c: DeleteEngine.Execute refuses to delete victim.dll through ancestor junction",
                    f2Outs.Count == 1
                    && f2Outs[0].Status != DeleteStatus.DeletedVerified
                    && File.Exists(f2VictimReal));

                string directDelErr = PermanentDeleteBin.DeleteVerified(f2JuncVictim, victimId, victimFi.Length, victimFi.LastWriteTimeUtc, null);
                Check("F2d: PermanentDeleteBin.DeleteVerified final-path verification refuses junctioned victim.dll",
                    directDelErr != null && File.Exists(f2VictimReal));

                FileIdentity juncId = FileIdentityProbe.Capture(f2Junc);
                LockState juncLock = LockProbe.Probe(f2Junc);
                Check("F2e: FileIdentityProbe.Capture returns Ok==false & LockProbe.Probe returns LockState.Unknown on junction",
                    !juncId.Ok && juncLock == LockState.Unknown);
            }
            finally
            {
                CacheRoots.ClearInjectedForTest();
                try { if (Directory.Exists(f2Junc)) Directory.Delete(f2Junc, false); } catch { }
            }
        }

        // --- F3 (RULE-04): CanonicalFast ADS & Drive Root ---
        Check("F3a: PathGuard.Canonical preserves drive root C:\\ and IsInside(C:\\, C:\\Windows) is true",
            PathGuard.Canonical("C:\\") == "C:\\"
            && PathGuard.IsInside("C:\\", "C:\\Windows"));

        Check("F3b: PathGuard.Canonical & CanonicalFast reject NTFS ADS (C:\\Temp\\a.tmp:ads)",
            PathGuard.Canonical("C:\\Temp\\a.tmp:ads") == ""
            && PathGuard.CanonicalFast("C:\\Temp\\a.tmp:ads") == "");

        string f3Temp = Path.Combine(sandbox, "groupF-f3", "Temp");
        Directory.CreateDirectory(f3Temp);
        CacheRoots.ClearInjectedForTest();
        try
        {
            CacheRoots.InjectForTest("TMP-SYSTEMP", f3Temp);
            string mRuleAds, mWhyAds, mRuleNorm, mWhyNorm;
            bool adsMatch = CacheRoots.Match(Path.Combine(f3Temp, "a.tmp:ads"), out mRuleAds, out mWhyAds);
            bool normMatch = CacheRoots.Match(Path.Combine(f3Temp, "a.tmp"), out mRuleNorm, out mWhyNorm);
            Check("F3c: CacheRoots.Match rejects NTFS ADS path while matching normal path",
                !adsMatch && normMatch && mRuleNorm == "TMP-SYSTEMP");

            int gen1, gen2;
            CacheRuleRegistry.RefreshRootsCache();
            CacheRoots.Root[] roots1 = CacheRuleRegistry.DiscoverExistingRootsCached(out gen1);
            CacheRuleRegistry.RefreshRootsCache();
            CacheRoots.Root[] roots2 = CacheRuleRegistry.DiscoverExistingRootsCached(out gen2);
            Check("F3d: DiscoverExistingRootsCached advances valid generation (>0) cleanly across RefreshRootsCache",
                roots1 != null && roots2 != null && gen1 > 0 && gen2 > gen1);
        }
        finally
        {
            CacheRoots.ClearInjectedForTest();
        }

        // --- F4 (RULE-05 & RULE-16): Expanded KEEP-* Protection ---
        Evidence wuDsEv = EvidenceRules.Evaluate("DataStore.edb", @"C:\Windows\SoftwareDistribution\DataStore\DataStore.edb", 100);
        Evidence hiberEv = EvidenceRules.Evaluate("hiberfil.sys", @"C:\hiberfil.sys", 100);
        Check("F4a: KEEP-SYSTEM catches SoftwareDistribution\\DataStore\\DataStore.edb & C:\\hiberfil.sys",
            wuDsEv.Risk == EvidenceRules.RiskKeep && wuDsEv.RuleId == "KEEP-SYSTEM" && !wuDsEv.PolicyEligible
            && hiberEv.Risk == EvidenceRules.RiskKeep && hiberEv.RuleId == "KEEP-SYSTEM" && !hiberEv.PolicyEligible);

        Evidence xwDbEv = EvidenceRules.Evaluate("message.db", @"D:\xwechat_files\wxid_1\db_storage\message.db", 100);
        Evidence qqDbEv = EvidenceRules.Evaluate("Msg3.0.db", @"D:\Tencent Files\10001\Msg3.0.db", 100);
        Evidence qqJrnEv = EvidenceRules.Evaluate("Msg3.0.db-journal", @"D:\Tencent Files\10001\Msg3.0.db-journal", 100);
        Evidence wcJrnEv = EvidenceRules.Evaluate("MSG0.db-journal", @"D:\WeChat Files\wxid_1\Msg\MSG0.db-journal", 100);
        Check("F4b: KEEP-CHATDB catches WeChat 4.x db_storage, QQ Msg3.0.db & .db-journal",
            xwDbEv.Risk == EvidenceRules.RiskKeep && xwDbEv.RuleId == "KEEP-CHATDB" && !xwDbEv.PolicyEligible
            && qqDbEv.Risk == EvidenceRules.RiskKeep && qqDbEv.RuleId == "KEEP-CHATDB" && !qqDbEv.PolicyEligible
            && qqJrnEv.Risk == EvidenceRules.RiskKeep && qqJrnEv.RuleId == "KEEP-CHATDB" && !qqJrnEv.PolicyEligible
            && wcJrnEv.Risk == EvidenceRules.RiskKeep && wcJrnEv.RuleId == "KEEP-CHATDB" && !wcJrnEv.PolicyEligible);

        Evidence patchMsiEv = EvidenceRules.Evaluate("x.msi", @"C:\Windows\Installer\$PatchCache$\Managed\x.msi", 100);
        Check("F4c: KEEP-MSICACHE catches Windows\\Installer\\$PatchCache$\\Managed\\x.msi",
            patchMsiEv.Risk == EvidenceRules.RiskKeep && patchMsiEv.RuleId == "KEEP-MSICACHE" && !patchMsiEv.PolicyEligible);

        Evidence singletonEv = EvidenceRules.Evaluate("SingletonLock", @"C:\Temp\SingletonLock", 100);
        Evidence lckEv = EvidenceRules.Evaluate("app.lck", @"C:\Temp\app.lck", 100);
        string chatDbLabel = ScanText.RuleLabel("KEEP-CHATDB");
        Check("F4d: KEEP-LOCK catches SingletonLock & app.lck, and ScanText.RuleLabel maps KEEP-CHATDB",
            singletonEv.Risk == EvidenceRules.RiskKeep && singletonEv.RuleId == "KEEP-LOCK" && !singletonEv.PolicyEligible
            && lckEv.Risk == EvidenceRules.RiskKeep && lckEv.RuleId == "KEEP-LOCK" && !lckEv.PolicyEligible
            && !string.IsNullOrEmpty(chatDbLabel) && chatDbLabel != "KEEP-CHATDB");

        // --- F5 (RULE-03 / RULE-09): Untrusted .ini & Protected Browser/App Paths ---
        string f5Root = Path.Combine(sandbox, "groupF-f5");
        string f5Docs = Path.Combine(f5Root, "Docs");
        string f5Target = Path.Combine(f5Root, "RealTarget");
        string f5Junc = Path.Combine(f5Root, "JuncDir");
        Directory.CreateDirectory(f5Docs);
        Directory.CreateDirectory(f5Target);
        bool f5JuncOk = TryCreateJunction(f5Junc, f5Target);
        try
        {
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string iniWin = ChatStorageLocator.ParseWeChatConfigIniContent(@"C:\Windows", f5Docs);
            string iniWinEnv = ChatStorageLocator.ParseWeChatConfigIniContent(winDir, f5Docs);
            string iniUnc = ChatStorageLocator.ParseWeChatConfigIniContent(@"\\attacker\share\WeChat Files", f5Docs);
            string iniJunc = f5JuncOk ? ChatStorageLocator.ParseWeChatConfigIniContent(f5Junc, f5Docs) : "";
            string iniJuncSub = f5JuncOk ? ChatStorageLocator.ParseWeChatConfigIniContent(Path.Combine(f5Junc, "WeChat Files"), f5Docs) : "";
            Check("F5a: ParseWeChatConfigIniContent rejects C:\\Windows, UNC & junction-containing paths",
                f5JuncOk && iniWin == "" && iniWinEnv == "" && iniUnc == "" && iniJunc == "" && iniJuncSub == "");
        }
        finally
        {
            try { if (Directory.Exists(f5Junc)) Directory.Delete(f5Junc, false); } catch { }
        }

        Check("F5b: CacheRoots.IsBrowserProtectedPath catches Local State, Extension Cookies, Login Data-wal & prefs.js",
            CacheRoots.IsBrowserProtectedPath("Local State", @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Local State")
            && CacheRoots.IsBrowserProtectedPath("Extension Cookies", @"C:\Users\u\AppData\Local\Microsoft\Edge\User Data\Default\Extension Cookies")
            && CacheRoots.IsBrowserProtectedPath("Login Data-wal", @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data-wal")
            && CacheRoots.IsBrowserProtectedPath("prefs.js", @"C:\Users\u\AppData\Roaming\Mozilla\Firefox\Profiles\p.default\prefs.js")
            && CacheRoots.IsAppProtectedPath("settings.json", @"C:\Users\u\AppData\Roaming\Code - Insiders\User\settings.json"));

        MethodInfo skipMethod = typeof(CacheRuleRegistry).GetMethod("ShouldSkipAppTopLevelName", BindingFlags.NonPublic | BindingFlags.Static);
        bool skipTencent = skipMethod != null && (bool)skipMethod.Invoke(null, new object[] { "Tencent" });
        bool skipWeChat = skipMethod != null && (bool)skipMethod.Invoke(null, new object[] { "WeChat" });
        bool skipQq = skipMethod != null && (bool)skipMethod.Invoke(null, new object[] { "QQ" });
        bool skipKeePassXc = skipMethod != null && (bool)skipMethod.Invoke(null, new object[] { "KeePassXC" });
        bool skipBenign = skipMethod != null && (bool)skipMethod.Invoke(null, new object[] { "DemoElectronApp" });
        Check("F5c: ShouldSkipAppTopLevelName excludes Tencent, WeChat, QQ & KeePassXC (while allowing benign app name)",
            skipTencent && skipWeChat && skipQq && skipKeePassXc && !skipBenign);

        // F5d (RULE-03): All Users fallback requires genuine WeChat signature, rejects UserProfile/Documents & non-fixed drives
        string f5FakeAllUsers = Path.Combine(f5Root, "FakeAllUsersDir");
        Directory.CreateDirectory(Path.Combine(Path.Combine(f5FakeAllUsers, "All Users"), "config"));
        string f5RealAllUsers = Path.Combine(f5Root, "RealWeChatAllUsers");
        string f5RealAuConfig = Path.Combine(Path.Combine(f5RealAllUsers, "All Users"), "config");
        Directory.CreateDirectory(f5RealAuConfig);
        File.WriteAllText(Path.Combine(f5RealAuConfig, "config.data"), "wechat-sig");
        string parsedFakeAu = ChatStorageLocator.ParseWeChatConfigIniContent(f5FakeAllUsers, f5Docs);
        string parsedRealAu = ChatStorageLocator.ParseWeChatConfigIniContent(f5RealAllUsers, f5Docs);
        string userProfDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string parsedUserProf = ChatStorageLocator.ParseWeChatConfigIniContent(userProfDir, f5Docs);
        string nonFixedProbe = "";
        for (char drv = 'Z'; drv >= 'F'; drv--)
        {
            string probePath = drv + ":\\WeChatData";
            if (!PathGuard.IsFixedLocalDrive(probePath)) { nonFixedProbe = probePath; break; }
        }
        bool nonFixedRejected = string.IsNullOrEmpty(nonFixedProbe)
            || ChatStorageLocator.ParseWeChatConfigIniContent(nonFixedProbe, f5Docs) == "";
        Check("F5d: ParseWeChatConfigIniContent requires WeChat signature for All Users fallback, never mounts UserProfile directly & rejects non-fixed drives",
            !string.Equals(parsedFakeAu, PathGuard.Canonical(f5FakeAllUsers), StringComparison.OrdinalIgnoreCase)
            && string.Equals(parsedRealAu, PathGuard.Canonical(f5RealAllUsers), StringComparison.OrdinalIgnoreCase)
            && !string.Equals(parsedUserProf, PathGuard.Canonical(userProfDir), StringComparison.OrdinalIgnoreCase)
            && nonFixedRejected);

        // --- F6 (ENG-04 / ENG-05 / ENG-06 / ENG-07 / ENG-10 / ENG-11 / RULE-13) ---
        string f6Root = Path.Combine(sandbox, "groupF-f6");
        Directory.CreateDirectory(f6Root);

        string f6EscapeLog = Path.Combine(f6Root, "escape-log.txt");
        string f6Why;
        string evilOpId = "op_f6\r\nO\top=forged_op\tstatus=DeletedVerified";
        string evilBatchId = "batch_f6\r\n\tinjected";
        string f6Target = Path.Combine(f6Root, "dummy.tmp");
        DeleteRequest f6Req = new DeleteRequest { Path = f6Target, BytesAtScan = 16, PolicyEligible = true, Risk = EvidenceRules.RiskSafe };
        bool wroteEscaped = DeleteLog.WriteIntent(f6EscapeLog, evilOpId, evilBatchId, f6Req, f6Target, out f6Why);
        string[] rawEscLines = File.Exists(f6EscapeLog) ? File.ReadAllLines(f6EscapeLog, Encoding.UTF8) : new string[0];
        bool hasForgedOutcomeLine = false;
        int intentLineCount = 0;
        for (int i = 0; i < rawEscLines.Length; i++)
        {
            string line = rawEscLines[i];
            if (line.StartsWith("O\t", StringComparison.Ordinal)) hasForgedOutcomeLine = true;
            string[] cols = line.Split('\t');
            if (cols.Length >= 2)
            {
                if (cols[1] == DeleteLog.OutcomeMark) hasForgedOutcomeLine = true;
                if (cols[1] == DeleteLog.IntentMark) intentLineCount++;
            }
        }
        bool hasEscapedOpAndBatch = rawEscLines.Length == 1
            && rawEscLines[0].IndexOf("\top=" + DeleteLog.Esc(evilOpId), StringComparison.Ordinal) >= 0
            && rawEscLines[0].IndexOf("\tbatch=" + DeleteLog.Esc(evilBatchId), StringComparison.Ordinal) >= 0;
        List<KeyValuePair<string, string>> escPending = DeleteLog.PendingOps(f6EscapeLog);
        Check("F6a: DeleteLog escapes embedded \\r\\n\\t in opId/batchId (no forged O line, exact round-trip)",
            wroteEscaped && !hasForgedOutcomeLine && intentLineCount == 1 && hasEscapedOpAndBatch
            && escPending.Count == 1 && escPending[0].Key == evilOpId && escPending[0].Value == f6Target);

        string f6RealLogDir = Path.Combine(f6Root, "real-log-dir");
        string f6JuncLogDir = Path.Combine(f6Root, "junc-log-dir");
        Directory.CreateDirectory(f6RealLogDir);
        bool f6JuncOk = TryCreateJunction(f6JuncLogDir, f6RealLogDir);
        try
        {
            string juncLogPath = Path.Combine(f6JuncLogDir, "delete-log.txt");
            string openWhy;
            DeleteLog.WriterSession juncSession = DeleteLog.OpenSession(juncLogPath, out openWhy);
            bool refusedJunc = (juncSession == null && !string.IsNullOrEmpty(openWhy) && !File.Exists(Path.Combine(f6RealLogDir, "delete-log.txt")));
            if (juncSession != null) juncSession.Dispose();
            Check("F6b: DeleteLog.OpenSession refuses junctioned/reparse log target without creating target file",
                f6JuncOk && refusedJunc);

            // F6f (ENG-05): TryPendingOps & DeleteEngine.Reconcile fail closed on unreadable/junctioned/dir log, while fresh missing log stays empty
            List<KeyValuePair<string, string>> juncPending;
            string juncPendingErr;
            bool juncTryOk = DeleteLog.TryPendingOps(juncLogPath, out juncPending, out juncPendingErr);
            List<DeleteOutcome> juncRecon = DeleteEngine.Reconcile(juncLogPath);

            string f6DirAsLog = Path.Combine(f6Root, "dir-as-log");
            Directory.CreateDirectory(f6DirAsLog);
            List<KeyValuePair<string, string>> dirPending;
            string dirPendingErr;
            bool dirTryOk = DeleteLog.TryPendingOps(f6DirAsLog, out dirPending, out dirPendingErr);
            List<DeleteOutcome> dirRecon = DeleteEngine.Reconcile(f6DirAsLog);

            List<DeleteOutcome> freshRecon = DeleteEngine.Reconcile(Path.Combine(f6Root, "never-created-log.txt"));
            Check("F6f: TryPendingOps & Reconcile fail closed on junctioned/directory log (locking cleaning) while fresh missing log stays empty",
                !juncTryOk && !string.IsNullOrEmpty(juncPendingErr)
                && juncRecon.Count == 1 && juncRecon[0].Status == DeleteStatus.PendingReconciliation
                && juncRecon[0].Dispatch == DispatchState.Unknown && juncRecon[0].Detail.StartsWith("审计日志不可读：", StringComparison.Ordinal)
                && !dirTryOk && !string.IsNullOrEmpty(dirPendingErr)
                && dirRecon.Count == 1 && dirRecon[0].Status == DeleteStatus.PendingReconciliation
                && dirRecon[0].Detail.StartsWith("审计日志不可读：", StringComparison.Ordinal)
                && freshRecon.Count == 0);
        }
        finally
        {
            try { if (Directory.Exists(f6JuncLogDir)) Directory.Delete(f6JuncLogDir, false); } catch { }
        }

        bool budgetThrew = false;
        ScanBudget weirdBudget = null;
        try
        {
            weirdBudget = ScanSessionHost.BudgetFromEnvironment("time=NaN;hash=-1");
        }
        catch
        {
            budgetThrew = true;
        }
        bool hashLimited = weirdBudget != null && weirdBudget.MaxHashBytes > 0 && !(new HashBudget(weirdBudget.MaxHashBytes).IsUnlimited);
        Check("F6c: BudgetFromEnvironment(\"time=NaN;hash=-1\") does not throw & does not create unlimited HashBudget",
            !budgetThrew && weirdBudget != null && weirdBudget.MaxDuration > TimeSpan.Zero && hashLimited);

        string[] unconfRules = new string[] { "stale-sentinel" };
        var dumpNoConfMsg = new Dictionary<string, object>
        {
            { "scanSessionId", 9L },
            { "rules", new ArrayList { "TMP-CRASHDUMP" } }
        };
        string dumpNoConfErr = CleanSelection.Validate(dumpNoConfMsg, 9L, out unconfRules);

        string[] zeroSessRules = new string[] { "stale-sentinel" };
        var zeroSessMsg = new Dictionary<string, object>
        {
            { "scanSessionId", 0L },
            { "rules", new ArrayList { "TMP-SYSTEMP" } }
        };
        string zeroSessErr = CleanSelection.Validate(zeroSessMsg, 0L, out zeroSessRules);

        string[] negSessRules = new string[] { "stale-sentinel" };
        var negSessMsg = new Dictionary<string, object>
        {
            { "scanSessionId", -1L },
            { "rules", new ArrayList { "TMP-SYSTEMP" } }
        };
        string negSessErr = CleanSelection.Validate(negSessMsg, -1L, out negSessRules);

        Check("F6d: CleanSelection.Validate leaves out rules==null on unconfirmed TMP-CRASHDUMP & rejects session <= 0",
            dumpNoConfErr != null && unconfRules == null
            && zeroSessErr != null && zeroSessRules == null
            && negSessErr != null && negSessRules == null);

        string rbReason;
        DeleteRefusalKind rbKind;
        bool negBytesOk = RecycleBinProbe.IsSupported(Path.Combine(f6Root, "a.tmp"), -1, true, out rbReason, out rbKind);
        bool longPathOk = RecycleBinProbe.IsSupported("C:\\" + new string('a', 265) + ".tmp", 128, true, out rbReason, out rbKind);
        Check("F6e: RecycleBinProbe.IsSupported rejects negative bytes & >=260-char paths",
            !negBytesOk && !longPathOk);

        // --- F7 (HOST-07 / HOST-10 / HOST-02 / HOST-01) ---
        string f7Root = Path.Combine(sandbox, "groupF-f7");
        string f7Target = Path.Combine(f7Root, "target");
        string f7Junc = Path.Combine(f7Root, "junc");
        Directory.CreateDirectory(f7Target);
        string f7CommaFile = Path.Combine(f7Target, "a,b.txt");
        string f7NormalFile = Path.Combine(f7Target, "normal.txt");
        File.WriteAllText(f7CommaFile, "comma");
        File.WriteAllText(f7NormalFile, "normal");
        bool f7JuncOk = TryCreateJunction(f7Junc, f7Target);
        try
        {
            string rExe, rArgs, rWhy;
            bool uncOk = Program.TryBuildRevealCommand(@"\\attacker\share\a.txt", out rExe, out rArgs, out rWhy);
            bool commaOk = Program.TryBuildRevealCommand(f7CommaFile, out rExe, out rArgs, out rWhy);
            bool juncDirOk = f7JuncOk && Program.TryBuildRevealCommand(f7Junc, out rExe, out rArgs, out rWhy);
            bool juncFileOk = f7JuncOk && Program.TryBuildRevealCommand(Path.Combine(f7Junc, "normal.txt"), out rExe, out rArgs, out rWhy);
            bool normalOk = Program.TryBuildRevealCommand(f7NormalFile, out rExe, out rArgs, out rWhy);
            Check("F7a: TryBuildRevealCommand rejects UNC, commas & reparse points while allowing normal local file",
                f7JuncOk && !uncOk && !commaOk && !juncDirOk && !juncFileOk && normalOk);
        }
        finally
        {
            try { if (Directory.Exists(f7Junc)) Directory.Delete(f7Junc, false); } catch { }
        }

        bool relaunchCancelled;
        string relaunchErr;
        bool evilRelaunchOk = Program.TryRelaunchAsAdmin("--evil", out relaunchCancelled, out relaunchErr);
        Check("F7b: TryRelaunchAsAdmin rejects disallowed args (\"--evil\") without launching",
            !evilRelaunchOk && !relaunchCancelled && !string.IsNullOrEmpty(relaunchErr));

        Assembly badAsm1 = Program.OnAssemblyResolve(null, new ResolveEventArgs("EvilNotAllowed, Version=1.0.0.0"));
        Assembly badAsm2 = Program.OnAssemblyResolve(null, new ResolveEventArgs("System.Data"));
        Check("F7c: OnAssemblyResolve rejects non-allowlisted assembly names",
            badAsm1 == null && badAsm2 == null);

        string prevWvArgs = Environment.GetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
        string prevWvFolder = Environment.GetEnvironmentVariable("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER");
        string prevWvPipe = Environment.GetEnvironmentVariable("WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER");
        string prevWvWait = Environment.GetEnvironmentVariable("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER");
        string prevForcedHost = Environment.GetEnvironmentVariable("COREWEBVIEW2_FORCED_HOSTING_MODE");
        string prevWvUserData = Environment.GetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER");
        try
        {
            Environment.SetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "--remote-debugging-port=9222");
            Environment.SetEnvironmentVariable("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", @"C:\EvilBrowser");
            Environment.SetEnvironmentVariable("WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER", "evil-debugger-pipe");
            Environment.SetEnvironmentVariable("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER", "1");
            Environment.SetEnvironmentVariable("COREWEBVIEW2_FORCED_HOSTING_MODE", "1");
            Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", @"C:\KeepSentinelUserData");
            Program.ClearSensitiveWebView2EnvironmentOverrides();
            Check("F7d: ClearSensitiveWebView2EnvironmentOverrides strips all WEBVIEW2_* (incl. debugger vars) & COREWEBVIEW2_FORCED_HOSTING_MODE while preserving WEBVIEW2_USER_DATA_FOLDER",
                string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"))
                && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER"))
                && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER"))
                && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER"))
                && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("COREWEBVIEW2_FORCED_HOSTING_MODE"))
                && string.Equals(Environment.GetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER"), @"C:\KeepSentinelUserData", StringComparison.Ordinal));
        }
        finally
        {
            Environment.SetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", prevWvArgs);
            Environment.SetEnvironmentVariable("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", prevWvFolder);
            Environment.SetEnvironmentVariable("WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER", prevWvPipe);
            Environment.SetEnvironmentVariable("WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER", prevWvWait);
            Environment.SetEnvironmentVariable("COREWEBVIEW2_FORCED_HOSTING_MODE", prevForcedHost);
            Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", prevWvUserData);
        }
    }

    // =====================================================================
    // Sandbox Helpers & Test Doubles
    // =====================================================================
    private static Evidence DecideFile(string fullPath)
    {
        FileInfo fi = new FileInfo(fullPath);
        int days = 0;
        if (fi.Exists)
        {
            days = (int)(DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays;
            if (days < 0) days = 0;
        }
        ScanItem item = new ScanItem
        {
            Path = fullPath,
            Name = Path.GetFileName(fullPath),
            IsDirectory = false,
            IsReparse = false,
            Bytes = fi.Exists ? fi.Length : 0,
            Days = days,
            LastWriteUtc = fi.Exists ? fi.LastWriteTimeUtc : DateTime.UtcNow,
            SizeComplete = true
        };
        return SafetyPolicy.Decide(item, LockState.Free);
    }

    private static string CreateNpmCacacheFile(string sha512Root, string text)
    {
        byte[] payload = Encoding.UTF8.GetBytes(text);
        byte[] hash;
        using (SHA512 sha = SHA512.Create()) hash = sha.ComputeHash(payload);
        StringBuilder sb = new StringBuilder(128);
        for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
        string hex = sb.ToString();
        string sub = Path.Combine(sha512Root, hex.Substring(0, 2), hex.Substring(2, 2));
        Directory.CreateDirectory(sub);
        string file = Path.Combine(sub, hex.Substring(4));
        File.WriteAllBytes(file, payload);
        return file;
    }

    private static void WriteMinimalZip(string path, string entryName, byte[] content)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(entryName);
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new BinaryWriter(fs))
        {
            // Local file header
            bw.Write((uint)0x04034b50);
            bw.Write((ushort)20);
            bw.Write((ushort)0);
            bw.Write((ushort)0); // store
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((uint)0);
            bw.Write((uint)content.Length);
            bw.Write((uint)content.Length);
            bw.Write((ushort)nameBytes.Length);
            bw.Write((ushort)0);
            bw.Write(nameBytes);
            bw.Write(content);

            uint cdOffset = (uint)fs.Position;
            // Central directory header
            bw.Write((uint)0x02014b50);
            bw.Write((ushort)20);
            bw.Write((ushort)20);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((uint)0);
            bw.Write((uint)content.Length);
            bw.Write((uint)content.Length);
            bw.Write((ushort)nameBytes.Length);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((uint)0);
            bw.Write((uint)0);
            bw.Write(nameBytes);
            uint cdSize = (uint)fs.Position - cdOffset;

            // End of central directory
            bw.Write((uint)0x06054b50);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)1);
            bw.Write((ushort)1);
            bw.Write(cdSize);
            bw.Write(cdOffset);
            bw.Write((ushort)0);
        }
    }

    private static void WriteMultiEntryZip(string path, string[] entryNames, byte[][] contents)
    {
        int count = entryNames.Length;
        byte[][] nameBytesList = new byte[count][];
        uint[] localOffsets = new uint[count];
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new BinaryWriter(fs))
        {
            for (int i = 0; i < count; i++)
            {
                nameBytesList[i] = Encoding.ASCII.GetBytes(entryNames[i]);
                byte[] content = contents[i];
                localOffsets[i] = (uint)fs.Position;
                bw.Write((uint)0x04034b50);
                bw.Write((ushort)20);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((uint)0);
                bw.Write((uint)content.Length);
                bw.Write((uint)content.Length);
                bw.Write((ushort)nameBytesList[i].Length);
                bw.Write((ushort)0);
                bw.Write(nameBytesList[i]);
                bw.Write(content);
            }

            uint cdOffset = (uint)fs.Position;
            for (int i = 0; i < count; i++)
            {
                byte[] nameBytes = nameBytesList[i];
                byte[] content = contents[i];
                bw.Write((uint)0x02014b50);
                bw.Write((ushort)20);
                bw.Write((ushort)20);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((uint)0);
                bw.Write((uint)content.Length);
                bw.Write((uint)content.Length);
                bw.Write((ushort)nameBytes.Length);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((uint)0);
                bw.Write(localOffsets[i]);
                bw.Write(nameBytes);
            }
            uint cdSize = (uint)fs.Position - cdOffset;

            bw.Write((uint)0x06054b50);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)count);
            bw.Write((ushort)count);
            bw.Write(cdSize);
            bw.Write(cdOffset);
            bw.Write((ushort)0);
        }
    }

    private static void WriteCraftedEocdZip(string path, string entryName, byte[] content, ushort eocdEntries, bool zip64Sentinels, bool omitCd)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(entryName);
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new BinaryWriter(fs))
        {
            bw.Write((uint)0x04034b50);
            bw.Write((ushort)20);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write((uint)0);
            bw.Write((uint)content.Length);
            bw.Write((uint)content.Length);
            bw.Write((ushort)nameBytes.Length);
            bw.Write((ushort)0);
            bw.Write(nameBytes);
            bw.Write(content);

            uint cdOffset = (uint)fs.Position;
            uint cdSize = 0;
            if (!omitCd)
            {
                bw.Write((uint)0x02014b50);
                bw.Write((ushort)20);
                bw.Write((ushort)20);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((uint)0);
                bw.Write((uint)content.Length);
                bw.Write((uint)content.Length);
                bw.Write((ushort)nameBytes.Length);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((ushort)0);
                bw.Write((uint)0);
                bw.Write((uint)0);
                bw.Write(nameBytes);
                cdSize = (uint)fs.Position - cdOffset;
            }

            bw.Write((uint)0x06054b50);
            bw.Write((ushort)0);
            bw.Write((ushort)0);
            bw.Write(zip64Sentinels ? (ushort)0xFFFF : eocdEntries);
            bw.Write(zip64Sentinels ? (ushort)0xFFFF : eocdEntries);
            bw.Write(zip64Sentinels ? 0xFFFFFFFFu : cdSize);
            bw.Write(zip64Sentinels ? 0xFFFFFFFFu : cdOffset);
            bw.Write((ushort)0);
        }
    }

    private static void WriteGzipFile(string path, byte[] raw)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (System.IO.Compression.GZipStream gz = new System.IO.Compression.GZipStream(fs, System.IO.Compression.CompressionMode.Compress))
        {
            gz.Write(raw, 0, raw.Length);
        }
    }

    private static void WriteChromiumSimpleCacheFile(string path)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new BinaryWriter(fs))
        {
            bw.Write(0xfcfb6d1ba7725c30UL); // SimpleFileHeader initial magic
            bw.Write((uint)5);              // version 5
            bw.Write((uint)16);             // key_length
            bw.Write((uint)0);              // key_hash
            bw.Write((uint)0);              // padding
            bw.Write(Encoding.ASCII.GetBytes("https://example/"));
            bw.Write(Encoding.ASCII.GetBytes("cached-body-bytes"));
            // SimpleFileEOF (24 bytes)
            bw.Write(0xf4fa6f45970d41d8UL); // final magic
            bw.Write((uint)0);              // flags
            bw.Write((uint)0);              // data_crc32
            bw.Write((uint)17);             // stream_size
            bw.Write((uint)0);              // padding
        }
    }

    private static void WriteChromiumBlockfileHeader(string path, bool isIndex, int totalBytes)
    {
        byte[] buf = new byte[Math.Max(64, totalBytes)];
        uint magic = isIndex ? 0xc103cac3u : 0xc104cac3u;
        BitConverter.GetBytes(magic).CopyTo(buf, 0);
        BitConverter.GetBytes(0x00020000u).CopyTo(buf, 4); // version 2.0
        BitConverter.GetBytes(16u).CopyTo(buf, 8);
        BitConverter.GetBytes(256u).CopyTo(buf, 12);
        File.WriteAllBytes(path, buf);
    }

    private static void WriteChromiumSimpleIndex(string path)
    {
        byte[] buf = new byte[64];
        BitConverter.GetBytes(0xfcfb6d1ba7725c30UL).CopyTo(buf, 0);
        BitConverter.GetBytes(9u).CopyTo(buf, 8);
        File.WriteAllBytes(path, buf);
    }

    private static void WriteV8CodeCacheEntry(string path)
    {
        byte[] buf = new byte[128];
        BitConverter.GetBytes(0xC0DE0001u).CopyTo(buf, 0);
        BitConverter.GetBytes(0x12345678u).CopyTo(buf, 4);
        BitConverter.GetBytes(96u).CopyTo(buf, 8);
        for (int i = 12; i < buf.Length; i++) buf[i] = (byte)((i * 31) & 0xFF);
        File.WriteAllBytes(path, buf);
    }

    private static List<ListRow> PumpUntilDoneHighSpeed(ScanSessionHost host, int timeoutMs)
    {
        List<ListRow> rows = new List<ListRow>();
        Stopwatch sw = Stopwatch.StartNew();
        ScanProgress final;
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            host.Pump(rows, 64, 16384);
            if (host.TryFinalize(out final)) break;
            Thread.Sleep(2);
        }
        host.Pump(rows, 64, 16384);
        return rows;
    }

    private static void WriteValidCmmmThumbcache(string path)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new BinaryWriter(fs))
        {
            bw.Write(Encoding.ASCII.GetBytes("CMMM"));
            bw.Write((uint)21);  // offset 4: format version (Win8/10/11)
            bw.Write((uint)1);   // offset 8: cache type
            bw.Write((uint)24);  // offset 12: header size / first entry value
            bw.Write((uint)24);  // offset 16: first entry offset (>= 24)
            bw.Write((uint)48);  // offset 20: available entry offset (>= first && <= len)
            bw.Write(new byte[64]);
        }
    }

    private static void WriteValidDxbcShader(string path)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new BinaryWriter(fs))
        {
            bw.Write(Encoding.ASCII.GetBytes("DXBC"));
            bw.Write(new byte[16]); // 16-byte checksum
            bw.Write((uint)1);      // version 1
            bw.Write((uint)64);     // total container size == 64 bytes
            bw.Write((uint)1);      // chunk count
            bw.Write((uint)36);     // chunk offset
            bw.Write(Encoding.ASCII.GetBytes("SHDR"));
            bw.Write((uint)20);
            bw.Write(new byte[20]);
        }
    }

    private static void WriteValidMdmp(string path)
    {
        using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write))
        using (BinaryWriter bw = new BinaryWriter(fs))
        {
            bw.Write(Encoding.ASCII.GetBytes("MDMP"));
            bw.Write((ushort)0xA793);
            bw.Write((ushort)0);
            bw.Write((uint)1);   // NumberOfStreams = 1
            bw.Write((uint)32);  // StreamDirectoryRva = 32
            bw.Write((uint)0);   // CheckSum
            bw.Write((uint)0x65000000); // TimeDateStamp
            bw.Write((ulong)0);  // Flags (normal user minidump)
            // Stream directory entry at offset 32 (12 bytes: StreamType=4, DataSize=16, Rva=44)
            bw.Write((uint)4);
            bw.Write((uint)16);
            bw.Write((uint)44);
            // Stream payload at offset 44 (16 bytes -> total 60 bytes)
            bw.Write(new byte[16]);
        }
    }

    private static void WriteBinaryShader(string path, string magic4)
    {
        byte[] buf = new byte[64];
        byte[] m = Encoding.ASCII.GetBytes(magic4);
        Array.Copy(m, 0, buf, 0, Math.Min(4, m.Length));
        buf[4] = 0x01;
        buf[5] = 0x00;
        buf[6] = 0x02;
        buf[7] = 0x00;
        for (int i = 8; i < buf.Length; i++) buf[i] = (byte)((i * 17 + 3) & 0xFF);
        File.WriteAllBytes(path, buf);
    }

    private static void WritePeExe(string path)
    {
        byte[] buf = new byte[128];
        buf[0] = 0x4D; // 'M'
        buf[1] = 0x5A; // 'Z'
        buf[2] = 0x90;
        BitConverter.GetBytes(64u).CopyTo(buf, 0x3C); // e_lfanew = 64
        buf[64] = (byte)'P';
        buf[65] = (byte)'E';
        buf[66] = 0;
        buf[67] = 0;
        for (int i = 68; i < buf.Length; i++) buf[i] = (byte)((i * 7) & 0xFF);
        File.WriteAllBytes(path, buf);
    }

    private static void WriteMscfCab(string path)
    {
        byte[] buf = new byte[64];
        buf[0] = 0x4D; // 'M'
        buf[1] = 0x53; // 'S'
        buf[2] = 0x43; // 'C'
        buf[3] = 0x46; // 'F'
        BitConverter.GetBytes(64u).CopyTo(buf, 8);  // cbCabinet
        BitConverter.GetBytes(36u).CopyTo(buf, 16); // coffFiles
        buf[24] = 3; // versionMinor
        buf[25] = 1; // versionMajor
        BitConverter.GetBytes((ushort)1).CopyTo(buf, 26); // cFolders
        BitConverter.GetBytes((ushort)1).CopyTo(buf, 28); // cFiles
        File.WriteAllBytes(path, buf);
    }

    private static void WriteMswimEsd(string path)
    {
        byte[] buf = new byte[128];
        Encoding.ASCII.GetBytes("MSWIM\0\0\0").CopyTo(buf, 0);
        BitConverter.GetBytes(208u).CopyTo(buf, 8);
        BitConverter.GetBytes(0x00010D00u).CopyTo(buf, 12);
        for (int i = 16; i < buf.Length; i++) buf[i] = (byte)((i * 13 + 7) & 0xFF);
        File.WriteAllBytes(path, buf);
    }

    private static void WriteWxapkg(string path)
    {
        byte[] buf = new byte[128];
        Encoding.ASCII.GetBytes("V1MMWX").CopyTo(buf, 0);
        buf[6] = 0x00;
        buf[7] = 0x01;
        for (int i = 8; i < buf.Length; i++) buf[i] = (byte)((i * 29 + 5) & 0xFF);
        File.WriteAllBytes(path, buf);
    }

    private static void WriteMp4Header(string path, int totalBytes)
    {
        byte[] buf = new byte[Math.Max(64, totalBytes)];
        buf[3] = 0x18;
        Encoding.ASCII.GetBytes("ftypmp42").CopyTo(buf, 4);
        for (int i = 12; i < buf.Length; i++) buf[i] = (byte)((i * 19 + 1) & 0xFF);
        File.WriteAllBytes(path, buf);
    }

    private static void WriteUtf16WerReport(string path)
    {
        string body = "Version=1\r\nEventType=APPCRASH\r\nEventTime=133700000000000000\r\nNsAppName=demo.exe\r\n";
        byte[] textBytes = Encoding.Unicode.GetBytes(body);
        byte[] full = new byte[2 + textBytes.Length];
        full[0] = 0xFF;
        full[1] = 0xFE;
        Array.Copy(textBytes, 0, full, 2, textBytes.Length);
        File.WriteAllBytes(path, full);
    }

    private static bool TryCreateJunction(string linkPath, string targetDir)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c mklink /J \"" + linkPath + "\" \"" + targetDir + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process p = Process.Start(psi))
            {
                p.WaitForExit(3000);
                return p.ExitCode == 0 && Directory.Exists(linkPath);
            }
        }
        catch { return false; }
    }

    private static List<ListRow> PumpUntilDone(ScanSessionHost host, int timeoutMs)
    {
        List<ListRow> rows = new List<ListRow>();
        Stopwatch sw = Stopwatch.StartNew();
        ScanProgress final;
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            host.Pump(rows, 16, 1024);
            if (host.TryFinalize(out final)) break;
            Thread.Sleep(5);
        }
        host.Pump(rows, 64, 4096);
        return rows;
    }

    private static ListRow FindByPath(List<ListRow> rows, string expectedPath)
    {
        string canon = PathGuard.Canonical(expectedPath);
        for (int i = 0; i < rows.Count; i++)
        {
            if (string.Equals(PathGuard.Canonical(rows[i].Path), canon, StringComparison.OrdinalIgnoreCase))
                return rows[i];
        }
        return null;
    }

    private static void DeadlinePumpBridge(AnPingBridge bridge, List<Dictionary<string, object>> posted, object gate, string targetAction, int timeoutMs)
    {
        Stopwatch sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            bridge.PumpForTest();
            if (FindLastAction(posted, gate, targetAction) != null) return;
            Thread.Sleep(10);
        }
    }

    private static Dictionary<string, object> WaitAction(List<Dictionary<string, object>> posted, object gate, string targetAction, int timeoutMs)
    {
        Stopwatch sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            Dictionary<string, object> found = FindLastAction(posted, gate, targetAction);
            if (found != null) return found;
            Application.DoEvents();
            Thread.Sleep(10);
        }
        return FindLastAction(posted, gate, targetAction);
    }

    private static Dictionary<string, object> FindLastAction(List<Dictionary<string, object>> posted, object gate, string action)
    {
        lock (gate)
        {
            for (int i = posted.Count - 1; i >= 0; i--)
            {
                object act;
                if (posted[i] != null && posted[i].TryGetValue("action", out act) && Convert.ToString(act) == action)
                    return posted[i];
            }
        }
        return null;
    }

    private static void TryDeleteSandbox(string sandbox)
    {
        if (!Directory.Exists(sandbox)) return;
        try
        {
            foreach (string sub in Directory.GetDirectories(sandbox, "*", SearchOption.AllDirectories))
            {
                try
                {
                    FileAttributes attr = File.GetAttributes(sub);
                    if ((attr & FileAttributes.ReparsePoint) != 0)
                    {
                        Directory.Delete(sub, false);
                    }
                }
                catch { }
            }
            Directory.Delete(sandbox, true);
        }
        catch { }
    }

    private sealed class SlowFakeEnumerator : IFileEnumerator
    {
        private readonly int count;
        public SlowFakeEnumerator(int count) { this.count = count; }

        public IEnumerable<FsEntry> Enumerate(string rootDir)
        {
            for (int i = 0; i < count; i++)
            {
                Thread.Sleep(5);
                FsEntry e = new FsEntry();
                e.FullName = Path.Combine(rootDir, "fake_" + i + ".bin");
                e.Name = "fake_" + i + ".bin";
                e.IsDirectory = false;
                e.Length = 16;
                e.LastWriteUtc = DateTime.UtcNow;
                e.Attributes = FileAttributes.Normal;
                yield return e;
            }
        }
    }

    private sealed class FakeRecycleBin : IRecycleBin
    {
        public readonly List<string> RecycledPaths = new List<string>();

        public bool IsAvailable(string path, long bytes, bool sizeComplete, out string reason, out DeleteRefusalKind kind)
        {
            reason = "";
            kind = DeleteRefusalKind.None;
            if (!sizeComplete)
            {
                reason = "体积不完整";
                kind = DeleteRefusalKind.DirSizeIncomplete;
                return false;
            }
            return true;
        }

        public RecycleEvidence SendFile(string path)
        {
            RecycledPaths.Add(path);
            File.Delete(path);
            RecycleEvidence ev = new RecycleEvidence();
            ev.HrPerform = 0;
            ev.HrDelete = 0;
            ev.PostDeleteItemFired = true;
            ev.NewlyCreatedPresent = true;
            ev.RecycledTo = "$Recycle.Bin\\$R_FAKE_" + Path.GetFileName(path);
            ev.Aborted = false;
            return ev;
        }
    }
}
