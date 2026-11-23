# 仓库目录结构说明

本仓库（`can-i-delete`）采用无外部构建器依赖的四模块源码组织方式，克隆仓库根目录（`repo root`）后即可直接编译与运行全套沙盒回归测试。

| 目录 / 文件 | 职责说明 |
| --- | --- |
| `Host/` | WinForms + WebView2 宿主窗体、原生多尺寸图标、目录级单实例唤醒与 UAC 交接、前后端消息桥接及便携 `data/` 隔离（`Program.cs`、`AnPingForm.cs`、`AnPingBridge.cs`、`AppDataPaths.cs`） |
| `Engine/` | 多根并发扫描、`PathPool` 前缀驻留池、目录汇总、同句柄永久删除、单文件 `IFileOperation` 系统回收站引擎、`5 MB` 审计日志轮转与 Restart Manager 占用探测 |
| `Rules/` | `CacheRuleRegistry` 十大受控缓存声明注册表、`ChatStorageLocator` 微信/企微/QQ 跨盘寻址、二进制魔数与结构证据校验、安全策略与通俗人话解释 |
| `ui/` | 白瓷浮雕前端界面（`index.html`、`styles.css`、`app.js`）与合成提示音模块（`anping-audio.js`） |
| `assets/` | 应用程序多尺寸原生图标（`app.ico`）与内嵌品牌徽标（`logo.png`、`favicon-32.png`） |
| `lib/`、`WebView2Loader.dll` | 开箱即编译与本地运行所需的 `Microsoft.Web.WebView2` 互操作组件与原生加载器 |
| `docs/` | 仓库结构说明与实机界面截图（`docs/screenshots/01..04.png`） |
| `tests/` | 隔离沙盒自动化回归套件（`run-tests.bat`、`LegacyRepro.cs`、`SelfTest.cs`、`AnPingExplanationTest.cs` 及 10 个前端与便携契约 `*.cjs` 测试） |
| `tools/` | 端到端原生宿主与便携数据目录自检探针源码（如 `AnPingPortableDataProbe.cs`） |
| `build.bat`、`can-i-delete.csproj` | 根目录一键编译脚本（直接调用系统内置 `.NET Framework 4.x csc.exe`）与 SDK 工程定义 |

## 本地构建与测试指引

- **编译主程序**：在仓库根目录（`repo root`）执行 `cmd /c build.bat`，生成 `can-i-delete.exe`。
- **运行 C# 安全回归套件**：执行 `cmd /c tests\run-tests.bat`（全程在 `%TEMP%` 隔离沙盒内运行，不触碰真实用户文件）。
- **运行前端与便携契约测试**：依次执行 `node tests\<test-name>.cjs`。
