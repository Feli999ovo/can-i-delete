using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using Microsoft.Win32;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Web.WebView2.Core;

public class AnPingForm : Form
{
    private WebView2 webView;
    private AnPingBridge bridge;
    private Icon ownedFormIcon;
    private bool isFormClosingInProgress;
    private long lastActivateTicks;
    private readonly Timer preferencesTimer = new Timer { Interval = 500 };
    private bool? lastMotion, lastContrast;

    private const int CS_DROPSHADOW = 0x00020000;
    private const int SW_RESTORE = 9;
    private const uint MSGFLT_ALLOW = 1;
    private const string ZipExtractHint =
        "提示：如果你是直接在压缩软件（ZIP）窗口里双击打开的，请先将整个压缩包完整解压到普通文件夹（如桌面或 D 盘）后再运行。";

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hWnd, uint message, uint action, IntPtr pChangeFilterStruct);

    protected override CreateParams CreateParams
    {
        get
        {
            CreateParams cp = base.CreateParams;
            cp.ClassStyle |= CS_DROPSHADOW;
            return cp;
        }
    }

    public AnPingForm()
    {
        this.Text = "按平";
        float dpiScale = 1.0f;
        try
        {
            using (Graphics g = this.CreateGraphics())
            {
                dpiScale = g.DpiX / 96.0f;
            }
        }
        catch { }

        int w = (int)Math.Round(960 * dpiScale);
        int h = (int)Math.Round(640 * dpiScale);
        this.ClientSize = new Size(w, h);
        this.MinimumSize = GetScaledMinimumSize(dpiScale);
        this.StartPosition = FormStartPosition.CenterScreen;
        this.FormBorderStyle = FormBorderStyle.None;
        this.BackColor = Color.FromArgb(244, 242, 238);

        try
        {
            string exePath = Application.ExecutablePath;
            if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
            {
                Icon extracted = Icon.ExtractAssociatedIcon(exePath);
                if (extracted != null)
                {
                    ownedFormIcon = extracted;
                    this.Icon = ownedFormIcon;
                }
            }
        }
        catch { }

        if (ownedFormIcon == null)
        {
            try
            {
                using (Stream s = typeof(AnPingForm).Assembly.GetManifestResourceStream("AppLogo"))
                {
                    if (s != null)
                    {
                        using (Bitmap bmp = new Bitmap(s))
                        {
                            IntPtr hIcon = IntPtr.Zero;
                            try
                            {
                                hIcon = bmp.GetHicon();
                                using (Icon tmp = Icon.FromHandle(hIcon))
                                {
                                    ownedFormIcon = (Icon)tmp.Clone();
                                    this.Icon = ownedFormIcon;
                                }
                            }
                            finally
                            {
                                if (hIcon != IntPtr.Zero)
                                {
                                    DestroyIcon(hIcon);
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        webView = new WebView2();
        webView.Dock = DockStyle.Fill;
        this.Controls.Add(webView);

        bridge = new AnPingBridge(this, webView);
        this.FormClosed += delegate(object s, FormClosedEventArgs e)
        {
            preferencesTimer.Dispose();
            SystemEvents.UserPreferenceChanged -= OnSystemPreferencesChanged;
            if (bridge != null) bridge.Dispose();
            if (ownedFormIcon != null)
            {
                try { ownedFormIcon.Dispose(); } catch { }
                ownedFormIcon = null;
            }
        };

        preferencesTimer.Tick += delegate(object s, EventArgs e)
        {
            bool animation;
            if (SystemParametersInfo(0x1042, 0, out animation, 0)
                && (lastMotion != !animation || lastContrast != SystemInformation.HighContrast || lastTextScale != ReadTextScale()))
            {
                PublishSystemPreferences();
            }
        };
        preferencesTimer.Start();
        SystemEvents.UserPreferenceChanged += OnSystemPreferencesChanged;
        this.Shown += delegate(object s, EventArgs e) { InitWebViewAsync(); };
    }

    private Size GetScaledMinimumSize(double dpiScale)
    {
        return new Size(
            (int)Math.Round(760 * dpiScale),
            (int)Math.Round(520 * dpiScale));
    }

    private static bool IsAllowedAppUri(string rawUri, bool mainDocOnly)
    {
        if (string.IsNullOrEmpty(rawUri)) return false;
        Uri uri;
        if (!Uri.TryCreate(rawUri, UriKind.Absolute, out uri) || uri == null) return false;
        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(uri.Host, "anping.local", StringComparison.OrdinalIgnoreCase)) return false;
        if (!uri.IsDefaultPort) return false;
        if (!string.IsNullOrEmpty(uri.UserInfo)) return false;
        if (mainDocOnly)
        {
            return string.Equals(uri.AbsolutePath, "/index.html", StringComparison.OrdinalIgnoreCase);
        }
        return true;
    }

    private async void InitWebViewAsync()
    {
        try { AppDataPaths.Prepare(); }
        catch (Exception ex)
        {
            MessageBox.Show(this,
                "无法在程序旁创建或写入 data 文件夹。\n\n" + AppDataPaths.Root +
                "\n\n请把完整程序文件夹放到有写入权限的位置后重试。没有改用 C 盘 AppData。\n" +
                ZipExtractHint + "\n\n" + ex.Message,
                "按平 · 数据目录不可用", MessageBoxButtons.OK, MessageBoxIcon.Error);
            Close();
            return;
        }
        try
        {
            Program.ClearSensitiveWebView2EnvironmentOverrides();

            string ver = null;
            try
            {
                ver = CoreWebView2Environment.GetAvailableBrowserVersionString();
            }
            catch (WebView2RuntimeNotFoundException)
            {
                ver = null;
            }
            if (string.IsNullOrEmpty(ver))
            {
                ShowRuntimeMissingPrompt();
                return;
            }

            string userDataDir = AppDataPaths.WebView;
            var options = new CoreWebView2EnvironmentOptions();
            options.AdditionalBrowserArguments = "";
            int maxInitAttempts = !string.IsNullOrEmpty(Program.StartupAutoAction) ? 6 : 1;
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    var env = await CoreWebView2Environment.CreateAsync(null, userDataDir, options);
                    await webView.EnsureCoreWebView2Async(env);
                    break;
                }
                catch
                {
                    if (attempt >= maxInitAttempts || IsDisposed) throw;
                }
                await System.Threading.Tasks.Task.Delay(220);
            }

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string uiDir = Path.Combine(baseDir, "ui");
            string indexFile = Path.Combine(uiDir, "index.html");
            if (string.IsNullOrEmpty(baseDir)
                || !PathGuard.IsLocalDrivePath(baseDir)
                || PathGuard.HasAnyReparseComponent(baseDir)
                || !Directory.Exists(uiDir)
                || PathGuard.HasAnyReparseComponent(uiDir)
                || !File.Exists(indexFile)
                || PathGuard.HasAnyReparseComponent(indexFile))
            {
                MessageBox.Show(this,
                    "未找到有效的 UI 界面资源目录：\n" + uiDir +
                    "\n\n请确保 ui 文件夹与 can-i-delete.exe 位于同一目录且不是符号链接。\n\n" + ZipExtractHint,
                    "按平 · 资源缺失", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Close();
                return;
            }

            webView.CoreWebView2.SetVirtualHostNameToFolderMapping(
                "anping.local", uiDir, CoreWebView2HostResourceAccessKind.Deny);

            CoreWebView2Settings st = webView.CoreWebView2.Settings;
            st.IsWebMessageEnabled = true;
            st.AreDevToolsEnabled = false;
            st.AreDefaultContextMenusEnabled = false;
            st.AreDefaultScriptDialogsEnabled = false;
            st.AreHostObjectsAllowed = false;
            st.AreBrowserAcceleratorKeysEnabled = false;
            st.IsStatusBarEnabled = false;
            st.IsZoomControlEnabled = false;
            st.IsPinchZoomEnabled = false;
            st.IsSwipeNavigationEnabled = false;
            st.IsBuiltInErrorPageEnabled = false;
            st.IsGeneralAutofillEnabled = false;
            st.IsPasswordAutosaveEnabled = false;

            webView.CoreWebView2.NavigationStarting += delegate(object s, CoreWebView2NavigationStartingEventArgs e)
            {
                if (!IsAllowedAppUri(e.Uri, true))
                {
                    e.Cancel = true;
                }
            };

            webView.CoreWebView2.FrameNavigationStarting += delegate(object s, CoreWebView2NavigationStartingEventArgs e)
            {
                e.Cancel = true;
            };

            webView.CoreWebView2.NewWindowRequested += delegate(object s, CoreWebView2NewWindowRequestedEventArgs e)
            {
                e.Handled = true;
            };

            webView.CoreWebView2.PermissionRequested += delegate(object s, CoreWebView2PermissionRequestedEventArgs e)
            {
                e.State = CoreWebView2PermissionState.Deny;
            };

            webView.CoreWebView2.DownloadStarting += delegate(object s, CoreWebView2DownloadStartingEventArgs e)
            {
                e.Cancel = true;
            };

            webView.CoreWebView2.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);
            webView.CoreWebView2.WebResourceRequested += delegate(object s, CoreWebView2WebResourceRequestedEventArgs e)
            {
                string reqUri = e.Request != null ? e.Request.Uri : "";
                if (!IsAllowedAppUri(reqUri, false) && !reqUri.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                {
                    e.Response = webView.CoreWebView2.Environment.CreateWebResourceResponse(null, 403, "Forbidden", "");
                }
            };

            webView.CoreWebView2.WebMessageReceived += delegate(object s, CoreWebView2WebMessageReceivedEventArgs e)
            {
                try
                {
                    if (!IsAllowedAppUri(e.Source, false)) return;
                    string raw = e.TryGetWebMessageAsString();
                    if (string.IsNullOrEmpty(raw))
                    {
                        raw = e.WebMessageAsJson;
                    }
                    if (!string.IsNullOrEmpty(raw))
                    {
                        bridge.HandleWebMessage(raw);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[CoreWebView2 Message Error] " + ex.GetType().Name);
                }
            };

            webView.CoreWebView2.DOMContentLoaded += delegate(object s, CoreWebView2DOMContentLoadedEventArgs e)
            {
                string consoleHook = @"
                    (function() {
                        var oldLog = console.log;
                        var oldErr = console.error;
                        console.log = function() {
                            var args = Array.prototype.slice.call(arguments);
                            window.chrome.webview.postMessage(JSON.stringify({ action: 'log', level: 'info', msg: args.join(' ') }));
                            oldLog.apply(console, arguments);
                        };
                        console.error = function() {
                            var args = Array.prototype.slice.call(arguments);
                            window.chrome.webview.postMessage(JSON.stringify({ action: 'log', level: 'error', msg: args.join(' ') }));
                            oldErr.apply(console, arguments);
                        };
                        window.onerror = function(msg, url, line) {
                            window.chrome.webview.postMessage(JSON.stringify({ action: 'log', level: 'fatal', msg: msg + ' at ' + url + ':' + line }));
                        };
                    })();
                ";
                webView.CoreWebView2.ExecuteScriptAsync(consoleHook);
            };

            webView.CoreWebView2.Navigate("https://anping.local/index.html");
        }
        catch (Exception ex)
        {
            ShowInitFailedPrompt(ex);
        }
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        Region old = Region;
        if (WindowState == FormWindowState.Maximized || Width < 2 || Height < 2) Region = null;
        else
        {
            float d = 16f * DeviceDpi / 96f;
            using (var p = new GraphicsPath())
            {
                p.AddArc(0, 0, d, d, 180, 90);
                p.AddArc(Width - d, 0, d, d, 270, 90);
                p.AddArc(Width - d, Height - d, d, d, 0, 90);
                p.AddArc(0, Height - d, d, d, 90, 90);
                p.CloseFigure();
                Region = new Region(p);
            }
        }
        if (old != null) old.Dispose();
        MaximizedBounds = Screen.FromControl(this).WorkingArea;
        if (webView != null && webView.CoreWebView2 != null)
        {
            webView.CoreWebView2.PostWebMessageAsJson("{\"action\":\"windowState\",\"maximized\":" + (WindowState == FormWindowState.Maximized ? "true" : "false") + "}");
        }
    }

    private void ShowRuntimeMissingPrompt()
    {
        Program.ShowWebView2MissingDialog(null);
        this.Close();
    }

    private void ShowInitFailedPrompt(Exception ex)
    {
        MessageBox.Show(this,
            "WebView2 界面组件初始化失败，程序将安全退出（未执行任何扫描或文件修改）：\n\n" +
            ex.Message + "\n\n" +
            "请确认系统已安装最新版 Microsoft Edge WebView2 Runtime，并保留程序同目录下的 WebView2Loader.dll 与 lib、ui 文件夹。",
            "按平 · 启动异常",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);
        this.Close();
    }

    [DllImport("user32.dll")]
    private static extern bool SystemParametersInfo(uint action, uint param, out bool value, uint flags);

    private int lastTextScale = 100;

    private static int ReadTextScale()
    {
        try
        {
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Accessibility"))
            {
                object value = key == null ? null : key.GetValue("TextScaleFactor");
                return value is int ? Math.Max(100, Math.Min(225, (int)value)) : 100;
            }
        }
        catch (System.Security.SecurityException) { return 100; }
    }

    public void PublishSystemPreferences()
    {
        if (IsDisposed || webView == null || webView.IsDisposed || webView.CoreWebView2 == null) return;
        bool animation;
        bool known = SystemParametersInfo(0x1042, 0, out animation, 0);
        lastMotion = known && !animation;
        lastContrast = SystemInformation.HighContrast;
        lastTextScale = ReadTextScale();
        webView.CoreWebView2.PostWebMessageAsJson(new JavaScriptSerializer().Serialize(new
        {
            action = "systemPreferences",
            reduceMotion = lastMotion.Value,
            highContrast = lastContrast.Value,
            textScale = lastTextScale / 100.0
        }));
    }

    private void OnSystemPreferencesChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        try { BeginInvoke(new Action(PublishSystemPreferences)); }
        catch (InvalidOperationException) { }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        uint activateMsg = Program.ActivateWindowMessageId;
        if (activateMsg != 0)
        {
            try { ChangeWindowMessageFilterEx(this.Handle, activateMsg, MSGFLT_ALLOW, IntPtr.Zero); } catch { }
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (isFormClosingInProgress)
        {
            e.Cancel = true;
            return;
        }
        isFormClosingInProgress = true;
        try
        {
            base.OnFormClosing(e);
            if (e.Cancel) return;
            if (bridge != null)
            {
                bridge.StopFileOpGracefully(1500);
            }
        }
        finally
        {
            isFormClosingInProgress = false;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DpiRect { public int Left, Top, Right, Bottom; }

    protected override void WndProc(ref Message m)
    {
        uint activateMsg = Program.ActivateWindowMessageId;
        if (activateMsg != 0 && (uint)m.Msg == activateMsg)
        {
            long nowTicks = Stopwatch.GetTimestamp();
            long minIntervalTicks = Math.Max(1L, Stopwatch.Frequency / 2L);
            if (lastActivateTicks == 0L || (nowTicks - lastActivateTicks) >= minIntervalTicks)
            {
                lastActivateTicks = nowTicks;
                if (this.WindowState == FormWindowState.Minimized || (this.IsHandleCreated && IsIconic(this.Handle)))
                {
                    if (this.IsHandleCreated)
                    {
                        ShowWindow(this.Handle, SW_RESTORE);
                    }
                    this.WindowState = FormWindowState.Normal;
                }
                this.Show();
                this.Activate();
                this.BringToFront();
                if (this.IsHandleCreated)
                {
                    SetForegroundWindow(this.Handle);
                }
            }
            m.Result = IntPtr.Zero;
            return;
        }

        const int WM_NCHITTEST = 0x84;
        const int HTCLIENT = 1;
        const int HTLEFT = 10;
        const int HTRIGHT = 11;
        const int HTTOP = 12;
        const int HTTOPLEFT = 13;
        const int HTTOPRIGHT = 14;
        const int HTBOTTOM = 15;
        const int HTBOTTOMLEFT = 16;
        const int HTBOTTOMRIGHT = 17;

        base.WndProc(ref m);

        if (m.Msg == 0x001A && webView != null) OnSystemPreferencesChanged(this, null);

        if (m.Msg == 0x02E0 && m.LParam != IntPtr.Zero)
        {
            int dpi = (int)(m.WParam.ToInt64() & 0xFFFFL);
            if (dpi > 0)
            {
                MinimumSize = GetScaledMinimumSize(dpi / 96.0);
            }
            var rect = (DpiRect)Marshal.PtrToStructure(m.LParam, typeof(DpiRect));
            Bounds = Rectangle.FromLTRB(rect.Left, rect.Top, rect.Right, rect.Bottom);
        }

        if (m.Msg == WM_NCHITTEST && m.Result == (IntPtr)HTCLIENT)
        {
            long lp = m.LParam.ToInt64();
            int x = (short)(lp & 0xFFFFL);
            int y = (short)((lp >> 16) & 0xFFFFL);
            Point p = PointToClient(new Point(x, y));
            int b;
            using (Graphics g = CreateGraphics()) b = Math.Max(6, (int)(6 * g.DpiX / 96));
            bool left = p.X <= b;
            bool right = p.X >= ClientSize.Width - b;
            bool top = p.Y <= b;
            bool bottom = p.Y >= ClientSize.Height - b;

            if (top && left) m.Result = (IntPtr)HTTOPLEFT;
            else if (top && right) m.Result = (IntPtr)HTTOPRIGHT;
            else if (bottom && left) m.Result = (IntPtr)HTBOTTOMLEFT;
            else if (bottom && right) m.Result = (IntPtr)HTBOTTOMRIGHT;
            else if (left) m.Result = (IntPtr)HTLEFT;
            else if (right) m.Result = (IntPtr)HTRIGHT;
            else if (top) m.Result = (IntPtr)HTTOP;
            else if (bottom) m.Result = (IntPtr)HTBOTTOM;
        }
    }
}
