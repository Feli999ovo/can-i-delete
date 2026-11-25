@echo off
rem Build can-i-delete.exe (modular 4-tier architecture, .NET Framework 4.x, C# 5).
rem Usage: run this file (double-click or from cmd). Must be run from the repo root.
setlocal
cd /d "%~dp0"

set CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe

rem Verify SHA-256 of vendored Microsoft WebView2 binaries (v1.0.2903.40) before compilation.
powershell -NoProfile -Command "$expected = @{ 'WebView2Loader.dll' = '462B36FD1BE6CA9F7563466A89E57C41EF4A4DEF3E0A84FA885D203AEA4A3AAF'; 'lib\Microsoft.Web.WebView2.Core.dll' = '88A3B62F45225A811CDB85DF6DFD95C2BFF9A0E43E3B04F813B125EACA56CC9F'; 'lib\Microsoft.Web.WebView2.WinForms.dll' = '29FC954C3FDE1749817D158F3DD5EBE9EFD3B3CE9708D86092FB1E9F023A1CB0' }; $sha = [System.Security.Cryptography.SHA256]::Create(); try { foreach ($kv in $expected.GetEnumerator()) { if (-not [System.IO.File]::Exists($kv.Key)) { [Console]::Error.WriteLine('[VERIFY FAILED] Missing vendored binary: ' + $kv.Key); exit 1 }; $fs = [System.IO.File]::OpenRead($kv.Key); try { $actual = [System.BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '') } finally { $fs.Dispose() }; if ($actual -ne $kv.Value) { [Console]::Error.WriteLine('[VERIFY FAILED] SHA-256 mismatch for ' + $kv.Key + ' (expected ' + $kv.Value + ', got ' + $actual + ')'); exit 1 } } } finally { $sha.Dispose() }"
if errorlevel 1 (
  echo.
  echo [BUILD FAILED] Vendored WebView2 binary integrity check failed.
  exit /b 1
)

set OUT=can-i-delete.exe
set SRC_HOST=Host\AssemblyInfo.cs Host\Program.cs Host\AppDataPaths.cs Host\AnPingForm.cs Host\AnPingBridge.cs
set SRC_ENGINE=Engine\ScanEngine.cs Engine\ScanSession.cs Engine\ListRow.cs Engine\DirectorySummary.cs Engine\DeleteEngine.cs Engine\DeleteLog.cs Engine\PermanentDelete.cs Engine\RecycleBin.cs Engine\RecycleBackend.cs Engine\FileDetailProbe.cs
set SRC_RULES=Rules\ChatStorageLocator.cs Rules\CacheRuleRegistry.cs Rules\Rules.cs Rules\Safety.cs Rules\ContentEvidence.cs Rules\CleanSelection.cs Rules\ScanText.cs Rules\AnPingExplanation.cs

"%CSC%" -nologo -langversion:5 -warnaserror -platform:x64 -highentropyva+ -optimize+ -codepage:65001 -target:winexe -out:%OUT% -win32manifest:app.manifest -win32icon:assets\app.ico ^
  -resource:assets/logo.png,AppLogo ^
  -r:System.Windows.Forms.dll -r:System.Drawing.dll -r:System.Web.Extensions.dll ^
  -r:lib\Microsoft.Web.WebView2.Core.dll -r:lib\Microsoft.Web.WebView2.WinForms.dll ^
  %SRC_HOST% %SRC_ENGINE% %SRC_RULES%

if errorlevel 1 (
  echo.
  echo [BUILD FAILED]
  exit /b 1
)

echo [BUILT] %OUT%
exit /b 0
