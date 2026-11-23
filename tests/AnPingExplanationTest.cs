using System;
using System.IO;
using System.Linq;

public class ListRow
{
    public string Path = "", Name = "", DirectoryPath = "", RuleId = "", EvidenceDetail = "";
    public string Risk = "", App = "", Reason = "", DenyReason = "";
    public bool IsDirectory, ContentVerified, PolicyEligible, LockedCleanableCache;
}

class ExplanationTest
{
    static void Check(bool x, string label)
    {
        if (!x) throw new Exception("explanation assertion failed: " + label);
    }

    static void Main()
    {
        string[] bannedTerms = new string[] { "释放", "已释放", "可清理", "不需要清理", "放心删", "暂存区" };

        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var row = new ListRow { Path = Path.Combine(windows, "Installer", "6cb1dd.msi"), RuleId = "USER-SCRIPT" };
        var d = AnPingExplanation.For(row);
        Check(d.confidence == "很可能" && d.risk == "可能影响软件运行" && !row.PolicyEligible && row.RuleId == "USER-SCRIPT" && d.sourceUrl.StartsWith("https://learn.microsoft.com/"), "MSI");

        var u = AnPingExplanation.For(new ListRow { Path = @"C:\Users\example\Downloads\9a1c_payload.dat", RuleId = "USER-CONFIG" });
        Check(u.type == "未知文件（.dat）" && u.confidence == "无法确定" && u.risk == "无法判断", "Unknown .dat");

        var wx = AnPingExplanation.For(new ListRow { Path = @"C:\Users\example\Documents\WeChat Files\wxid_demo\FileStorage\MsgAttach\abc\Image\2024-08\原图.jpg" });
        Check(wx.confidence == "很可能" && wx.risk == "可能丢失你的内容" && wx.purpose.Contains("尚未核实"), "WeChat MsgAttach");

        var generic = AnPingExplanation.For(new ListRow { Path = @"C:\Downloads\WeChat Files.jpg" });
        Check(generic.confidence == "无法确定", "Generic photo");

        var lockedChrome = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Local\Google\Chrome\User Data\Profile 4\Cache\Cache_Data\data_2",
            Name = "data_2",
            RuleId = "TMP-BROWSERCACHE",
            Risk = "保留",
            Reason = "正被某个程序占用中",
            DenyReason = "正被某个程序占用",
            LockedCleanableCache = true
        });
        Check(lockedChrome.risk == "影响很小"
            && lockedChrome.type.Contains("Chrome")
            && lockedChrome.summary.Contains("Chrome")
            && !lockedChrome.riskText.Contains("不知道它属于哪个程序")
            && lockedChrome.steps.Any(delegate(string s) { return s.Contains("Chrome") && s.Contains("重新扫描"); }), "Locked Chrome");

        // v0.8.0: VS Code active cache, VS Code occupied cache, VS Code VSIX & protected settings.json
        var vscodeCache = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Roaming\Code\Cache\Cache_Data\f_00001a",
            Name = "f_00001a",
            RuleId = "TMP-APPCACHE",
            Risk = "安全",
            PolicyEligible = true,
            ContentVerified = true,
            EvidenceDetail = "Chromium Blockfile 独立缓存块校验通过"
        });
        Check(vscodeCache.type.Contains("VS Code")
            && vscodeCache.summary == "可随主页「清理」一键清理"
            && vscodeCache.risk == "影响很小"
            && vscodeCache.risk != "无法判断"
            && !vscodeCache.riskText.Contains("不知道它属于哪个程序"), "VS Code active cache");

        var vscodeLocked = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Roaming\Code\Cache\Cache_Data\data_1",
            Name = "data_1",
            RuleId = "TMP-APPCACHE",
            Risk = "保留",
            Reason = "正被某个程序占用中",
            DenyReason = "正被某个程序占用",
            LockedCleanableCache = true
        });
        Check(vscodeLocked.type.Contains("VS Code")
            && vscodeLocked.summary.Contains("VS Code")
            && vscodeLocked.risk == "影响很小"
            && !vscodeLocked.riskText.Contains("不知道它属于哪个程序")
            && vscodeLocked.steps.Any(delegate(string s) { return s.Contains("VS Code") && s.Contains("重新扫描"); }), "VS Code locked cache");

        var vscodeSettings = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Roaming\Code\User\settings.json",
            Name = "settings.json",
            RuleId = "USER-CONFIG",
            Risk = "需复核",
            PolicyEligible = false
        });
        Check(vscodeSettings.type.Contains("VS Code")
            && vscodeSettings.risk == "可能丢失你的内容"
            && vscodeSettings.risk != "无法判断", "VS Code settings.json");

        // v0.8.0: Firefox active cache, locked cache & protected places.sqlite
        var firefoxCache = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Local\Mozilla\Firefox\Profiles\abc.default-release\cache2\entries\0123456789abcdef0123456789abcdef01234567",
            Name = "0123456789abcdef0123456789abcdef01234567",
            RuleId = "TMP-BROWSERCACHE",
            Risk = "安全",
            PolicyEligible = true,
            ContentVerified = true,
            EvidenceDetail = "Firefox cache2 网页缓存条目校验通过"
        });
        Check(firefoxCache.type.Contains("Firefox")
            && firefoxCache.purpose.Contains("Firefox")
            && firefoxCache.risk == "影响很小"
            && !firefoxCache.riskText.Contains("不知道它属于哪个程序"), "Firefox cache2");

        var firefoxPlaces = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Local\Mozilla\Firefox\Profiles\abc.default-release\places.sqlite",
            Name = "places.sqlite",
            RuleId = "USER-CONFIG",
            Risk = "需复核",
            PolicyEligible = false
        });
        Check(firefoxPlaces.type == "浏览器登录与个人数据"
            && firefoxPlaces.risk == "可能丢失你的内容", "Firefox places.sqlite");

        // v0.8.0: NVIDIA DXCache shader
        var nvidiaShader = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Local\NVIDIA\DXCache\shader01.bin",
            Name = "shader01.bin",
            RuleId = "TMP-SHADERCACHE",
            Risk = "安全",
            PolicyEligible = true,
            ContentVerified = true,
            EvidenceDetail = "图形着色器缓存（.bin）二进制结构校验通过"
        });
        Check(nvidiaShader.type.Contains("NVIDIA")
            && nvidiaShader.purpose.Contains("NVIDIA")
            && nvidiaShader.risk == "影响很小"
            && !nvidiaShader.riskText.Contains("不知道它属于哪个程序"), "NVIDIA DXCache");

        // v0.8.0: Under-48h Temp installer file & 7z preview document
        var tempUnder48h = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Local\Temp\is-9A2BC.tmp\setup.exe",
            Name = "setup.exe",
            RuleId = "TMP-SYSTEMP",
            Risk = "需复核",
            PolicyEligible = false,
            Reason = "临时文件修改时间未满 48 小时，可能仍在使用中",
            DenyReason = "临时文件修改时间未满 48 小时，暂不纳入清理"
        });
        Check(tempUnder48h.type == "近期生成的临时文件"
            && tempUnder48h.summary == "近期生成的临时文件 · 暂不清理"
            && tempUnder48h.risk == "可能影响软件运行"
            && tempUnder48h.risk != "无法判断"
            && !tempUnder48h.riskText.Contains("不知道它属于哪个程序"), "Under-48h Temp installer");

        var tempPreviewDoc = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Users\example\AppData\Local\Temp\7zO8899\合同.docx",
            Name = "合同.docx",
            RuleId = "USER-DOC",
            Risk = "需复核",
            PolicyEligible = false
        });
        Check(tempPreviewDoc.type.Contains("压缩包临时预览文件")
            && tempPreviewDoc.risk == "可能丢失你的内容"
            && tempPreviewDoc.risk != "无法判断", "7z preview docx");

        // v0.8.0: Windows\Prefetch
        var prefetch = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Windows\Prefetch\CHROME.EXE-1234ABCD.pf",
            Name = "CHROME.EXE-1234ABCD.pf",
            RuleId = "FALLBACK-UNKNOWN",
            Risk = "需复核",
            PolicyEligible = false
        });
        Check(prefetch.type == "Windows 启动预读取优化文件"
            && prefetch.risk == "不建议删除"
            && prefetch.risk != "无法判断"
            && !prefetch.riskText.Contains("不知道它属于哪个程序"), "Windows Prefetch");

        var iso = AnPingExplanation.For(new ListRow { Path = @"C:\Users\example\Downloads\Win11_24H2.iso", Name = "Win11_24H2.iso", Risk = "需复核" });
        Check(!string.IsNullOrEmpty(iso.summary) && iso.summary.Length <= 30 && iso.purpose.Length <= 40 && iso.riskText.Length <= 40, "ISO");

        Check(AnPingExplanation.Confidence(new[] { new AnPingExplanation.Evidence("y", "a", "强证据"), new AnPingExplanation.Evidence("y", "b", "强证据") }) == "已确认", "Confidence confirmed");
        Check(AnPingExplanation.Confidence(new[] { new AnPingExplanation.Evidence("y", "a", "强证据"), new AnPingExplanation.Evidence("n", "b", "强证据") }) == "无法确定", "Confidence contrary");

        // v0.9.0: WeChat / WXWork / QQ pure caches, KEEP-CHATDB, chat received files & TMP-WINUPDATE
        var wxSnsCache = AnPingExplanation.For(new ListRow
        {
            Path = @"D:\WeChat Files\wxid_demo\FileStorage\Sns\Cache\2026-11\sns_01.jpg",
            Name = "sns_01.jpg",
            RuleId = "TMP-CHATCACHE",
            Risk = "安全",
            PolicyEligible = true,
            ContentVerified = true,
            EvidenceDetail = "朋友圈媒体缓存（JPEG 图像头）结构校验通过"
        });
        Check(wxSnsCache.type == "微信朋友圈缓存" && wxSnsCache.risk == "影响很小", "WeChat Sns Cache");

        var wxAppletCache = AnPingExplanation.For(new ListRow
        {
            Path = @"D:\WeChat Files\All Users\Applet\wx12345\pkg.wxapkg",
            Name = "pkg.wxapkg",
            RuleId = "TMP-CHATCACHE",
            Risk = "安全",
            PolicyEligible = true,
            ContentVerified = true,
            EvidenceDetail = "微信小程序运行包（.wxapkg）结构校验通过"
        });
        Check(wxAppletCache.type == "微信小程序缓存" && wxAppletCache.risk == "影响很小", "WeChat Applet wxapkg");

        var wxWorkCef = AnPingExplanation.For(new ListRow
        {
            Path = @"D:\WXWork\CefCache\Cache\Cache_Data\f_000001",
            Name = "f_000001",
            RuleId = "TMP-CHATCACHE",
            Risk = "安全",
            PolicyEligible = true,
            ContentVerified = true,
            EvidenceDetail = "聊天软件内置网页缓存块（Blockfile）校验通过"
        });
        Check(wxWorkCef.type == "企业微信缓存" && wxWorkCef.risk == "影响很小", "WXWork CefCache");

        var chatDbKeep = AnPingExplanation.For(new ListRow
        {
            Path = @"D:\WeChat Files\wxid_demo\Msg\Multi\MSG0.db",
            Name = "MSG0.db",
            RuleId = "KEEP-CHATDB",
            Risk = "保留",
            PolicyEligible = false
        });
        Check(chatDbKeep.type == "微信/QQ 聊天记录数据库"
            && chatDbKeep.summary == "本地聊天记录库 · 已强制保护"
            && chatDbKeep.risk == "可能丢失你的内容", "KEEP-CHATDB MSG0.db");

        var wxRecvPdf = AnPingExplanation.For(new ListRow
        {
            Path = @"D:\WeChat Files\wxid_demo\FileStorage\File\2026-11\项目合同.pdf",
            Name = "项目合同.pdf",
            RuleId = "USER-DOC",
            Risk = "需复核",
            PolicyEligible = false
        });
        Check(wxRecvPdf.type == "微信聊天接收文件" && wxRecvPdf.risk == "可能丢失你的内容", "WeChat received PDF");

        var wxRecvMp4 = AnPingExplanation.For(new ListRow
        {
            Path = @"D:\WeChat Files\wxid_demo\FileStorage\Video\2026-11\家庭录像.mp4",
            Name = "家庭录像.mp4",
            RuleId = "FALLBACK-UNKNOWN",
            Risk = "需复核",
            PolicyEligible = false
        });
        Check(wxRecvMp4.type == "微信聊天视频" && wxRecvMp4.risk == "可能丢失你的内容", "WeChat received MP4");

        var qqRecvXlsx = AnPingExplanation.For(new ListRow
        {
            Path = @"D:\Tencent Files\10001\FileRecv\报价表.xlsx",
            Name = "报价表.xlsx",
            RuleId = "USER-DOC",
            Risk = "需复核",
            PolicyEligible = false
        });
        Check(qqRecvXlsx.type == "QQ 聊天接收文件" && qqRecvXlsx.risk == "可能丢失你的内容", "QQ FileRecv XLSX");

        var winUpdOk = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Windows\SoftwareDistribution\Download\kb5034441.cab",
            Name = "kb5034441.cab",
            RuleId = "TMP-WINUPDATE",
            Risk = "安全",
            PolicyEligible = true,
            ContentVerified = true,
            EvidenceDetail = "Windows Update Cabinet 安装包（MSCF 头，已满 48 小时）校验通过"
        });
        Check(winUpdOk.type.Contains("Windows 更新") && winUpdOk.risk == "影响很小", "WinUpdate eligible cab");

        var winUpdCooldown = AnPingExplanation.For(new ListRow
        {
            Path = @"C:\Windows\SoftwareDistribution\Download\pending_patch.cab",
            Name = "pending_patch.cab",
            RuleId = "TMP-WINUPDATE",
            Risk = "需复核",
            PolicyEligible = false,
            Reason = "临时文件修改时间未满 48 小时，可能仍在使用中",
            DenyReason = "修改时间未满 48 小时"
        });
        Check(winUpdCooldown.type == "Windows 更新下载缓存"
            && winUpdCooldown.summary == "近期下载的系统更新包 · 未满 48 小时暂不清理", "WinUpdate under-48h cab");

        AnPingExplanation.Detail[] allTested = new AnPingExplanation.Detail[]
        {
            d, u, wx, lockedChrome, vscodeCache, vscodeLocked, vscodeSettings,
            firefoxCache, firefoxPlaces, nvidiaShader, tempUnder48h, tempPreviewDoc, prefetch, iso,
            wxSnsCache, wxAppletCache, wxWorkCef, chatDbKeep, wxRecvPdf, wxRecvMp4, qqRecvXlsx, winUpdOk, winUpdCooldown
        };
        Check(allTested.All(delegate(AnPingExplanation.Detail x)
        {
            if (x.purpose.Length > 40 || x.riskText.Length > 40 || string.IsNullOrEmpty(x.summary) || x.summary.Length > 30)
                return false;
            if (!x.evidence.Any(delegate(AnPingExplanation.Evidence e) { return e.state == "u"; }))
                return false;
            string joined = x.type + "|" + x.purpose + "|" + x.summary + "|" + x.risk + "|" + x.riskText + "|" + string.Join("|", x.steps);
            if (joined.IndexOf("清理…", StringComparison.Ordinal) >= 0 || joined.IndexOf("移入回收站…", StringComparison.Ordinal) >= 0)
                return false;
            for (int b = 0; b < bannedTerms.Length; b++)
            {
                if (joined.IndexOf(bannedTerms[b], StringComparison.Ordinal) >= 0)
                    return false;
            }
            return true;
        }), "All prose length, unexamined fields & zero banned terms");

        Console.WriteLine("PASS MSI/DAT/WeChat/LockedChrome/VSCode/Firefox/NVIDIA/Temp48h/7zPreview/Prefetch/ISO, zero contradiction & zero banned terms");
    }
}
