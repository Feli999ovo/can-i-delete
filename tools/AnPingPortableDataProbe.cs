using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Diagnostics;
using System.Windows.Forms;
using Microsoft.Web.WebView2.WinForms;

// Runs beside an isolated copy of the complete product; no hooks added to its UI.
class AnPingPortableDataProbe
{
    static readonly Stopwatch Clock = Stopwatch.StartNew();
    static string mode;
    static void Pump(int ms) { var end = DateTime.UtcNow.AddMilliseconds(ms); while (DateTime.UtcNow < end) { if (Clock.Elapsed.TotalSeconds > 25) throw new Exception("25s limit"); Application.DoEvents(); Thread.Sleep(3); } }
    static string Script(WebView2 w, string text) { var task = w.CoreWebView2.ExecuteScriptAsync(text); while (!task.IsCompleted) Pump(3); return task.GetAwaiter().GetResult(); }
    static void Check(string name, bool value) { if (!value) throw new Exception(name); Console.WriteLine("PASS " + name); }
    [STAThread] static int Main(string[] args)
    {
        mode = args.Length == 0 ? "first" : args[0];
        AppDomain.CurrentDomain.AssemblyResolve += (s,e) => { string p = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"lib",new AssemblyName(e.Name).Name+".dll"); return File.Exists(p) ? Assembly.LoadFrom(p) : null; };
        try { return Run(); } catch (Exception ex) { Console.WriteLine(ex); return 1; }
    }
    static int Run()
    {
        Check("root follows executable", AppDataPaths.Root == Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"data"));
        Check("cwd is different", !String.Equals(Directory.GetCurrentDirectory().TrimEnd('\\'),AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase));
        if (mode == "blocked")
        {
            bool refused = false;
            try { AppDataPaths.Prepare(); }
            catch (IOException) { refused = true; }
            catch (UnauthorizedAccessException) { refused = true; }
            Check("unwritable data is refused without GUI or sound", refused);
            Check("no profile override on failed setup", Environment.GetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER") == Environment.GetEnvironmentVariable("PORTABLE_FORBIDDEN_PROFILE"));
            return 0;
        }
        Application.EnableVisualStyles();
        using (var f = new AnPingForm())
        {
            f.Show(); var w = f.Controls.OfType<WebView2>().Single();
            while (w.CoreWebView2 == null) Pump(10);
            while (Script(w,"document.readyState==='complete' && !!document.querySelector('#soundBtn')") != "true") Pump(10);
            Check("WebView2 uses executable data directory", String.Equals(w.CoreWebView2.Environment.UserDataFolder,AppDataPaths.WebView,StringComparison.OrdinalIgnoreCase));
            Check("external profile env overridden", Environment.GetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER") == AppDataPaths.WebView);
            if (mode == "first")
            {
                Check("new directory starts with sound off", Script(w,"localStorage.getItem('anping.sound.enabled')") == "null");
                Script(w,"document.querySelector('#soundBtn').click()");
                Check("sound choice saved", Script(w,"localStorage.getItem('anping.sound.enabled')") == "\"true\"");
            }
            else Check("sound choice survives restart or relocation", Script(w,"localStorage.getItem('anping.sound.enabled')") == "\"true\"");
            string why;
            Check("delete log is beside executable and writable", DeleteEngine.DefaultLogPath() == AppDataPaths.DeleteLog && DeleteLog.EnsureWritable(AppDataPaths.DeleteLog,out why));
            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            var bridge = typeof(AnPingForm).GetField("bridge",flags).GetValue(f);
            typeof(AnPingBridge).GetMethod("WriteDiagnostic",flags).Invoke(bridge,new object[] { "portable-fixture","verify",null });
            Check("diagnostic log is beside executable", File.Exists(AppDataPaths.Diagnostics));
            Check("no leftover write probe", Directory.GetFiles(AppDataPaths.Root,".write-*").Length == 0 && Directory.GetFiles(AppDataPaths.WebView,".write-*").Length == 0);
            f.Close(); Pump(200);
        }
        return 0;
    }
}
