using System;using System.IO;using System.Linq;using System.Diagnostics;using System.Reflection;using System.Threading;using System.Security.Cryptography;using System.Text;using System.Windows.Forms;using System.Web.Script.Serialization;using Microsoft.Web.WebView2.WinForms;using Microsoft.Web.WebView2.Core;
// 端到端：真实 EXE 界面里点「清理」，只删 .tmp 下自建的 npm cacache 样本。用户真实 npm 缓存不在注入根内，碰不到。
class AnPingCleanProbe {
 static string root=Directory.GetCurrentDirectory(),dir=Environment.GetEnvironmentVariable("CANIDELETE_CHECK_DIR");static JavaScriptSerializer js=new JavaScriptSerializer();static Stopwatch clock=Stopwatch.StartNew();static int checks;
 static void Pump(int n){var end=DateTime.UtcNow.AddMilliseconds(n);while(DateTime.UtcNow<end){if(clock.Elapsed.TotalSeconds>60)throw new Exception("60s deadline");Application.DoEvents();Thread.Sleep(3);}}
 static string Eval(WebView2 w,string code){var t=w.CoreWebView2.ExecuteScriptAsync("typeof window.__auditEval==='function'?window.__auditEval("+js.Serialize(code)+"):eval("+js.Serialize(code)+")");var end=DateTime.UtcNow.AddSeconds(3);while(!t.IsCompleted&&DateTime.UtcNow<end)Pump(5);if(!t.IsCompleted)throw new Exception("script deadline");return t.GetAwaiter().GetResult();}
 static void Wait(WebView2 w,string code){var end=DateTime.UtcNow.AddSeconds(10);while(DateTime.UtcNow<end){if(Eval(w,code)=="true")return;Pump(15);}throw new Exception("wait "+code);}
 static void Check(string n,bool ok){Console.WriteLine((ok?"PASS ":"FAIL ")+n);if(!ok)throw new Exception(n);checks++;}
 static void Shot(WebView2 w,string n){Pump(800);using(var s=File.Create(Path.Combine(dir,n+".png"))){var t=w.CoreWebView2.CapturePreviewAsync(CoreWebView2CapturePreviewImageFormat.Png,s);while(!t.IsCompleted)Pump(10);t.GetAwaiter().GetResult();}}
 static string Cache(string cac,string content){string hex;using(var h=SHA512.Create())hex=BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(content))).Replace("-","").ToLowerInvariant();string d=Path.Combine(cac,hex.Substring(0,2),hex.Substring(2,2));Directory.CreateDirectory(d);string f=Path.Combine(d,hex.Substring(4));File.WriteAllText(f,content);return f;}
 [STAThread]static int Main(){Directory.CreateDirectory(dir);Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER",Path.Combine(dir,"profile"));AppDomain.CurrentDomain.AssemblyResolve+=(s,e)=>{string n=new AssemblyName(e.Name).Name,p=n=="can-i-delete"?Path.Combine(root,"can-i-delete.exe"):Path.Combine(root,"lib",n+".dll");return File.Exists(p)?Assembly.LoadFrom(p):null;};try{return Run();}catch(Exception e){Console.WriteLine(e);return 1;}}
 static int Run(){Application.EnableVisualStyles();
  string fx=Path.Combine(Environment.GetEnvironmentVariable("ANPING_FIXTURE_ROOT")??Path.Combine(root,".tmp"),Environment.GetEnvironmentVariable("ANPING_FIXTURE_LEAF")??"clean-e2e");if(Directory.Exists(fx))Directory.Delete(fx,true);
  string cac=Path.Combine(fx,"npm-cache","_cacache","content-v2","sha512");Directory.CreateDirectory(cac);
  string[] cached=Enumerable.Range(0,6).Select(i=>Cache(cac,"generated npm cache entry "+i+" "+new string('x',4000+i))).ToArray();
  string keep=Path.Combine(fx,"my-notes.txt");File.WriteAllText(keep,"user document must survive");
  string fake=Path.Combine(cac,"aa","aa");Directory.CreateDirectory(fake);string fakeFile=Path.Combine(fake,new string('a',124));File.WriteAllText(fakeFile,"hash does not match name: must survive");
  CacheRoots.InjectForTest("TMP-PKGCACHE",cac);
  // 缩略图缓存：沙箱内建 Microsoft\Windows\Explorer（规则按完整路径认该目录）；崩溃转储：沙箱内 CrashDumps。
  string thumbDir=Path.Combine(fx,"Microsoft","Windows","Explorer");Directory.CreateDirectory(thumbDir);CacheRoots.InjectForTest("TMP-THUMBCACHE",thumbDir);
  byte[] cm=new byte[4096];Encoding.ASCII.GetBytes("CMMM").CopyTo(cm,0);BitConverter.GetBytes(32u).CopyTo(cm,4);BitConverter.GetBytes(4u).CopyTo(cm,8);BitConverter.GetBytes(24u).CopyTo(cm,16);BitConverter.GetBytes(24u).CopyTo(cm,20);
  string thumbOk=Path.Combine(thumbDir,"thumbcache_256.db");File.WriteAllBytes(thumbOk,cm);
  string thumbIdx=Path.Combine(thumbDir,"thumbcache_idx.db");File.WriteAllBytes(thumbIdx,Encoding.ASCII.GetBytes("IMMM"+new string('\0',60)));
  string dumpDir=Path.Combine(fx,"CrashDumps");Directory.CreateDirectory(dumpDir);CacheRoots.InjectForTest("TMP-CRASHDUMP",dumpDir);
  byte[] md=new byte[8192];Encoding.ASCII.GetBytes("MDMP").CopyTo(md,0);BitConverter.GetBytes(0xA793u).CopyTo(md,4);BitConverter.GetBytes(1u).CopyTo(md,8);BitConverter.GetBytes(32u).CopyTo(md,12);BitConverter.GetBytes(7u).CopyTo(md,32);BitConverter.GetBytes(64u).CopyTo(md,36);BitConverter.GetBytes(64u).CopyTo(md,40);
  string dumpOk=Path.Combine(dumpDir,"app.exe.123.dmp");File.WriteAllBytes(dumpOk,md);
  string dumpBad=Path.Combine(dumpDir,"bare.dmp");File.WriteAllBytes(dumpBad,Encoding.ASCII.GetBytes("MDMP"));
  string thumbBusy=Path.Combine(thumbDir,"iconcache_32.db");File.WriteAllBytes(thumbBusy,cm);
  // 审查发现的假文件：只有内核签名、数据流越界、残缺头。都不能被提供清理。
  string dumpKernel=Path.Combine(dumpDir,"kernel.dmp");File.WriteAllBytes(dumpKernel,Encoding.ASCII.GetBytes("PAGEDU64"));
  byte[] oob=(byte[])md.Clone();BitConverter.GetBytes(65535u).CopyTo(oob,36);BitConverter.GetBytes(4096u).CopyTo(oob,40);
  string dumpOob=Path.Combine(dumpDir,"oob.dmp");File.WriteAllBytes(dumpOob,oob);
  byte[] shortCm=new byte[12];Array.Copy(cm,shortCm,12);string thumbShort=Path.Combine(thumbDir,"thumbcache_32.db");File.WriteAllBytes(thumbShort,shortCm);
  string[] fakes={thumbIdx,dumpBad,dumpKernel,dumpOob,thumbShort};
  cached=cached.Concat(new[]{thumbOk,dumpOk}).ToArray();
  string realNpm=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"npm-cache");int realBefore=Directory.Exists(realNpm)?Directory.GetFiles(realNpm,"*",SearchOption.AllDirectories).Length:0;
  string la=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);string realThumb=Path.Combine(la,@"Microsoft\Windows\Explorer"),realDumps=Path.Combine(la,"CrashDumps");
  Func<string,int> count=d=>Directory.Exists(d)?Directory.GetFiles(d).Length:0;int thumbBefore=count(realThumb),dumpsBefore=count(realDumps);
  Check("permanent gate open, recycle gate closed",DeleteEngine.BuildAllowsPermanentDelete&&!DeleteEngine.BuildAllowsRealDeletion);
  using(var f=new AnPingForm()){f.Show();var w=f.Controls.OfType<WebView2>().Single();while(w.CoreWebView2==null)Pump(10);Wait(w,"typeof window.__auditEval==='function'");
   Eval(w,"window.__clean=null;window.__end=null;window.chrome.webview.addEventListener('message',e=>{if(e.data.action==='scanComplete')window.__end=e.data;if(e.data.action==='cleanResult')window.__clean=e.data;});window.chrome.webview.postMessage(JSON.stringify({action:'startScan',targets:["+js.Serialize(fx)+"]}));");
   Wait(w,"window.__end!==null");Eval(w,"if(document.querySelector('#legend').classList.contains('show'))document.querySelector('#legendOk').click();");Pump(300);
   Check("clean button shows v1.3.1 label without dump size",Eval(w,"!!document.querySelector('#cleanBtn')&&document.querySelector('#cleanBtn').textContent==='清理…'")=="true");Shot(w,"01-扫描后-清理按钮");
   Eval(w,"document.querySelector('#cleanBtn').click();");Wait(w,"cleanList!==null&&!!$('cGo')");Pump(300);
   long genuine=cached.Sum(p=>new FileInfo(p).Length)+new FileInfo(thumbBusy).Length;
   Check("eligible total equals exactly the 9 genuine files (fakes excluded)",Eval(w,"(()=>{let c=CATS.reduce((s,x)=>s+x.ok*(S.found[x.id]||0),0);return Math.abs(c*1073741824-"+genuine+")<2;})()")=="true");
   Check("dump defaults unselected and initial focus on cancel",Eval(w,"!document.querySelector('[data-clean-rule=\"TMP-CRASHDUMP\"]').checked&&!document.querySelector('#confirmDumps').checked&&document.activeElement&&document.activeElement.id==='cCancel'") == "true");
   Eval(w,"document.querySelector('[data-clean-rule=\"TMP-CRASHDUMP\"]').click();");
   Check("dump selection requires separate confirmation and excluded from count until confirmed",Eval(w,"$('cGo').disabled&&!$('dumpConfirmRow').hidden&&$('cleanChosen').textContent.includes('已选 8 个文件')") == "true");
   Eval(w,"$('confirmDumps').click();");
   Check("confirm dialog states non-recycle irreversible and unified group names",Eval(w,"(()=>{let t=document.querySelector('#dialog').textContent;return document.querySelector('#dialog').classList.contains('show')&&document.querySelector('#scrim').classList.contains('dialog-dim')&&t.includes('删除后不进回收站，无法恢复')&&t.includes('开发包管理器缓存 · npm')&&t.includes('缩略图与图标缓存')&&t.includes('系统转储与诊断日志 · 崩溃转储')&&$('cGo').textContent==='永久删除 9 个文件';})()")=="true");Shot(w,"02-确认-不可恢复");
   Check("nothing deleted before confirm",cached.All(File.Exists));
   var busy=new FileStream(thumbBusy,FileMode.Open,FileAccess.Read,FileShare.Read);
   Eval(w,"window.__prog=[];window.chrome.webview.addEventListener('message',e=>{if(e.data.action==='cleanProgress')window.__prog.push(e.data.done);});");
   Eval(w,"document.querySelector('#cGo').click();");
   // 后台执行：点击后窗口消息循环仍在跑，页面能立刻应答脚本。
   var t0=DateTime.UtcNow;string alive=Eval(w,"1+1");Check("window stays responsive during cleaning",alive=="2"&&(DateTime.UtcNow-t0).TotalSeconds<3);
   Wait(w,"window.__clean!==null");Pump(400);busy.Dispose();
   Console.WriteLine("CLEAN-DEBUG "+Eval(w,"JSON.stringify(window.__clean)"));
   Check("progress messages were sent",Eval(w,"window.__prog.length>=1")=="true");
   string result=Eval(w,"JSON.stringify(window.__clean)");File.WriteAllText(Path.Combine(dir,"clean-result.json"),result);Console.WriteLine("RESULT "+result.Substring(0,Math.Min(260,result.Length)));
   Check("six npm + one thumbcache + one dump permanently deleted",cached.All(p=>!File.Exists(p))&&Eval(w,"window.__clean.deleted===8&&window.__clean.unknown===0")=="true");
   Check("in-use thumbcache skipped, reported as untouched",File.Exists(thumbBusy)&&Eval(w,"window.__clean.attempted===9&&window.__clean.untouched===1&&window.__clean.changed===0")=="true");
   Check("index, magic-only, kernel, out-of-bounds and truncated fakes never offered",fakes.All(File.Exists));
   Check("user document untouched",File.Exists(keep)&&File.ReadAllText(keep)=="user document must survive");
   Check("hash-mismatch fake cache untouched",File.Exists(fakeFile));
   Console.WriteLine("UI-STATE "+Eval(w,"JSON.stringify({controls:document.querySelector('#controls').textContent,dialogShown:document.querySelector('#dialog').classList.contains('show'),dialog:document.querySelector('#dialog').textContent})"));
   Check("UI result band reports deleted file size sum without claiming disk freed, and details open on demand",Eval(w,"(()=>{let ct=document.querySelector('#controls').textContent;return ct.includes('已永久删除 8 个文件，共 ')&&ct.includes('（文件大小合计）')&&!ct.includes('释放')&&ct.includes('1 个未删除（原文件未动）')&&!!document.querySelector('#cleanDetailBtn');})()")=="true");Shot(w,"03-清理完成");
   Eval(w,"document.querySelector('#cleanDetailBtn').click();");Pump(300);
   Check("clean details list skipped in-use file",Eval(w,"document.querySelector('#dialog').classList.contains('show')&&document.querySelector('#dialog').textContent.includes('iconcache_32.db')&&document.querySelector('#dialog').textContent.includes('占用')")=="true");Shot(w,"04-占用文件已跳过");
   Eval(w,"document.querySelector('#cOk').click();");Pump(300);
   // 问题很多时：弹窗不超出窗口，「知道了」按钮仍可见可点。
   Eval(w,"showCleanProblems({problems:Array.from({length:20},(_, i)=>({name:'很长的文件名-'+'x'.repeat(60)+i+'.db',detail:'执行层重新判定未通过授权：正被某个程序占用，'+'原因说明'.repeat(8)}))},'部分文件没有删除，原因见下方。');");Pump(500);
   Check("long problem list keeps the dialog and its button inside the window",Eval(w,"(()=>{let d=document.querySelector('#dialog').getBoundingClientRect(),b=document.querySelector('#cOk').getBoundingClientRect();return d.top>=0&&d.bottom<=innerHeight&&b.bottom<=innerHeight&&b.top>=d.top;})()")=="true");Shot(w,"05-问题很多-弹窗不溢出");
   Eval(w,"document.querySelector('#cOk').click();");Pump(300);
   Check("audit log records each deletion",File.ReadAllText(DeleteEngine.DefaultLogPath()).Contains("DeletedVerified"));
   // 第二轮只选缩略图：转储保持未选，后端也不能删除它。
   string dumpUnselected=Path.Combine(dumpDir,"unselected.dmp");File.WriteAllBytes(dumpUnselected,md);
   Eval(w,"window.__end=null;window.__clean=null;window.chrome.webview.postMessage(JSON.stringify({action:'startScan',targets:["+js.Serialize(fx)+"]}));");Wait(w,"window.__end!==null");
   Eval(w,"if(legend.classList.contains('show'))$('legendOk').click();$('cleanBtn').click();");Wait(w,"cleanList!==null&&!!$('cGo')");
   Check("second round dump unselected",Eval(w,"!document.querySelector('[data-clean-rule=\"TMP-CRASHDUMP\"]').checked") == "true");
   Eval(w,"$('cGo').click()");Wait(w,"window.__clean!==null");
   Check("unselected dump is not dispatched, selected thumbnail deleted",File.Exists(dumpUnselected)&&!File.Exists(thumbBusy)&&Eval(w,"window.__clean.deleted===1&&window.__clean.attempted===1") == "true");
}
  int realAfter=Directory.Exists(realNpm)?Directory.GetFiles(realNpm,"*",SearchOption.AllDirectories).Length:0;
  Check("real user npm cache untouched ("+realBefore+" files)",realAfter==realBefore);
  Check("real Explorer cache and CrashDumps untouched ("+thumbBefore+"/"+dumpsBefore+" files)",count(realThumb)==thumbBefore&&count(realDumps)==dumpsBefore);
  Directory.Delete(fx,true);Console.WriteLine("RESULT OK "+checks+" end-to-end clean checks");return 0;}
}
