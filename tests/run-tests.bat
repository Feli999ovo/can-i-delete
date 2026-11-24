@echo off
rem Modular v1.0.0 safety & architecture regression tests.
rem   1) LegacyRepro            - audited S1/S2 false-positive & content-verification repros (17 checks)
rem   2) SelfTest               - 6-group high-SNR suite (Groups A-F, incl. security regressions)
rem   3) AnPingExplanationTest  - human-guide explanation & prose contract test
rem Runs strictly in %TEMP% sandbox; zero real user files or Windows settings touched.
setlocal
cd /d "%~dp0"
chcp 65001 >nul

set CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe
set FAIL=0

echo ============================================================
echo [1/3] legacy defect reproduction (17 checks)
echo ============================================================
"%CSC%" -nologo -langversion:5 -warnaserror -codepage:65001 -target:exe -out:LegacyRepro.exe ^
  LegacyRepro.cs ..\Rules\ChatStorageLocator.cs ..\Rules\CacheRuleRegistry.cs ..\Rules\Rules.cs ..\Rules\Safety.cs ..\Rules\ContentEvidence.cs
if errorlevel 1 (
  echo [BUILD FAILED] LegacyRepro
  exit /b 2
)
LegacyRepro.exe
if not "%ERRORLEVEL%"=="0" set FAIL=1
del /q LegacyRepro.exe >nul 2>&1

echo.
echo ============================================================
echo [2/3] modular v1.0.0 core self test (Groups A-F)
echo ============================================================
"%CSC%" -nologo -langversion:5 -warnaserror -codepage:65001 -target:exe -main:SelfTest -out:SelfTest.exe ^
  -r:System.Windows.Forms.dll -r:System.Drawing.dll -r:System.Web.Extensions.dll ^
  -r:..\lib\Microsoft.Web.WebView2.Core.dll -r:..\lib\Microsoft.Web.WebView2.WinForms.dll ^
  SelfTest.cs ^
  ..\Host\AssemblyInfo.cs ..\Host\Program.cs ..\Host\AppDataPaths.cs ..\Host\AnPingForm.cs ..\Host\AnPingBridge.cs ^
  ..\Engine\ScanEngine.cs ..\Engine\ScanSession.cs ..\Engine\ListRow.cs ..\Engine\DirectorySummary.cs ..\Engine\DeleteEngine.cs ..\Engine\DeleteLog.cs ..\Engine\PermanentDelete.cs ..\Engine\RecycleBin.cs ..\Engine\RecycleBackend.cs ..\Engine\FileDetailProbe.cs ^
  ..\Rules\ChatStorageLocator.cs ..\Rules\CacheRuleRegistry.cs ..\Rules\Rules.cs ..\Rules\Safety.cs ..\Rules\ContentEvidence.cs ..\Rules\CleanSelection.cs ..\Rules\ScanText.cs ..\Rules\AnPingExplanation.cs
if errorlevel 1 (
  echo [BUILD FAILED] SelfTest
  exit /b 2
)
SelfTest.exe
if not "%ERRORLEVEL%"=="0" set FAIL=1
del /q SelfTest.exe >nul 2>&1

echo.
echo ============================================================
echo [3/3] human-guide explanation standalone test
echo ============================================================
"%CSC%" -nologo -langversion:5 -warnaserror -codepage:65001 -target:exe -out:AnPingExplanationTest.exe ^
  AnPingExplanationTest.cs ..\Rules\ChatStorageLocator.cs ..\Rules\CacheRuleRegistry.cs ..\Rules\Rules.cs ..\Rules\Safety.cs ..\Rules\ContentEvidence.cs ..\Rules\AnPingExplanation.cs
if errorlevel 1 (
  echo [BUILD FAILED] AnPingExplanationTest
  exit /b 2
)
AnPingExplanationTest.exe
if not "%ERRORLEVEL%"=="0" set FAIL=1
del /q AnPingExplanationTest.exe >nul 2>&1

echo.
if "%FAIL%"=="1" (
  echo [TESTS FAILED]
) else (
  echo [TESTS PASSED]
)
exit /b %FAIL%
