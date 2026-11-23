@echo off
rem Build can-i-delete.exe (modular 4-tier architecture, .NET Framework 4.x, C# 5).
rem Usage: run this file (double-click or from cmd). Must be run from the repo root.
setlocal
cd /d "%~dp0"

set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe

set OUT=can-i-delete.exe
set SRC_HOST=Host\AssemblyInfo.cs Host\Program.cs Host\AppDataPaths.cs Host\AnPingForm.cs Host\AnPingBridge.cs
set SRC_ENGINE=Engine\ScanEngine.cs Engine\ScanSession.cs Engine\ListRow.cs Engine\DirectorySummary.cs Engine\DeleteEngine.cs Engine\DeleteLog.cs Engine\PermanentDelete.cs Engine\RecycleBin.cs Engine\RecycleBackend.cs Engine\FileDetailProbe.cs
set SRC_RULES=Rules\ChatStorageLocator.cs Rules\CacheRuleRegistry.cs Rules\Rules.cs Rules\Safety.cs Rules\ContentEvidence.cs Rules\CleanSelection.cs Rules\ScanText.cs Rules\AnPingExplanation.cs

"%CSC%" -nologo -langversion:5 -warnaserror -codepage:65001 -target:winexe -out:%OUT% -win32manifest:app.manifest -win32icon:assets\app.ico ^
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
