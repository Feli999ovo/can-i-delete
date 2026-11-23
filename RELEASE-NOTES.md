# 按平（can-i-delete）`v1.0.0` 正式版发布说明

- **版本号**：`v1.0.0`（PE 文件版本 / 程序集版本：`1.0.0.0`）
- **开源仓库**：[https://github.com/Feli999ovo/can-i-delete](https://github.com/Feli999ovo/can-i-delete)
- **适用系统**：Windows 10 / Windows 11 x64（需系统自带 `.NET Framework 4.8` 及 `Microsoft Edge WebView2 Runtime`）
- **发行形态**：纯净绿色免安装便携包 `按平-v1.0.0-win-x64-portable.zip`

---

## 一、首次使用必读

1. **请先完整解压再运行**：请将 `按平-v1.0.0-win-x64-portable.zip` **完整解压到普通文件夹**（例如桌面或 `D:\Tools\按平\`），然后双击目录内的 `can-i-delete.exe` 启动。切勿直接在压缩软件预览窗口内双击运行。
2. **绿色便携不留注册表垃圾**：首次启动后，程序会在 `can-i-delete.exe` 同级目录自动创建 `data\` 文件夹，用于保存本地界面缓存、提示音偏好与删除审计日志（`data\delete-log.txt`），不向系统 `AppData` 或注册表写入残留。
3. **SmartScreen 首次运行与 SHA-256 核对**：因未附带商业代码签名证书，首次启动若遇 Windows Defender SmartScreen 蓝色提示窗，请先用 `Get-FileHash .\按平-v1.0.0-win-x64-portable.zip -Algorithm SHA256` 对照 `SHA256SUMS.txt` 校验一致，再点击「更多信息」→「仍要运行」。

---

## 二、`v1.0.0` 正式版核心能力

### 1. 打开即见系统盘实时容量与三路直达首屏
- 首屏直观展示系统盘当前可用容量与总空间，未扫描前自动收起空视图顶栏，界面清爽克制、切换零跳动。
- 当本机检测到微信、企业微信或 QQ 存储目录时，首屏底部直接露出「微信 / QQ 专向扫描」快捷入口，配合「选择位置」与「快速扫描常见缓存」一键直达。

### 2. 十大受控缓存规则与句柄级防误删清理
点击主界面「清理」，仅针对位于受控缓存根目录内、且逐个通过正向魔数/哈希/结构校验的十类缓存执行批量永久删除（单一规则注册表 `CacheRuleRegistry`）：
- `TMP-PKGCACHE`：开发包管理器与编译缓存（npm / pip / NuGet / Yarn / pnpm / Go / uv）
- `TMP-BROWSERCACHE`：浏览器网页与渲染缓存（Edge / Chrome / Firefox / Brave / Vivaldi / Opera，硬排除 Cookie、密码与书签）
- `TMP-CHATCACHE`：微信 / 企业微信 / QQ 纯缓存（朋友圈媒体缓存、小程序包、内置网页缓存）
- `TMP-APPCACHE`：桌面软件与组件缓存（VS Code / Cursor / Electron / WebView2）
- `TMP-THUMBCACHE`：Windows 资源管理器缩略图与图标缓存（`CMMM` 结构校验）
- `TMP-SHADERCACHE`：显卡与 DirectX 着色器编译缓存（DirectX / NVIDIA / AMD / Intel）
- `TMP-SYSTEMP`：系统与软件过期临时残留（普通临时项满 24h、安装解包残留满 48h，排除 Office 草稿与重要文档头）
- `TMP-WER`：Windows 错误报告历史归档（`ReportArchive` / `ReportQueue`）
- `TMP-WINUPDATE`：Windows 更新下载缓存（`SoftwareDistribution\Download` 满 48h 补丁包，严禁触碰 `DataStore`）
- `TMP-CRASHDUMP`：程序崩溃转储（`CrashDumps` 用户态 `MDMP`，默认不勾选，须单独勾选确认）

### 3. 微信 / 企业微信 / QQ 跨盘寻址与三轨安全隔离
- 自动跨盘识别默认位置或迁移至其他分区的微信、企业微信、QQ 存储目录，支持首屏与「选择位置」一键发起专向扫描。
- **核心数据库只读保护（`KEEP-CHATDB`）**：`Msg\*.db`、`nt_db` 等聊天记录数据库强制标为 `○ 建议保留`，严禁批量清理与单文件回收。
- **聊天接收文件专向透视**：聊天收发的 PDF、视频、压缩包等原件绝不进入自动清理，可在「大文件 → 聊天接收文件」胶囊下集中核对来源与体积。

### 4. 单文件详情透视与「移入回收站」
- 点击任意文件可在右侧抽屉查看人话用途解释、时间戳属性及 Windows Restart Manager 实时占用进程探测。
- 对确认不再需要的普通文件（非 `○ 建议保留`），可手动点击「移入回收站」经系统 `IFileOperation` 安全送入桌面回收站（支持还原，绝不静默降级为永久删除）。

### 5. 正式版宿主稳定性与工程加固
- **原生多尺寸图标**：EXE 内嵌 `16x16`、`32x32`、`48x48`、`256x256` 高清多尺寸图标资源。
- **便携目录级单实例锁与前台唤醒**：同一目录重复双击自动唤醒并置顶已运行窗口，杜绝多进程争抢同一 `data\` 目录。
- **关窗优雅收尾与 5 MB 审计日志轮转**：清理途中若关闭窗口，自动等待当前单文件写完审计结果落盘后再退出；`data\delete-log.txt` 超过 5 MB 且无未决记录时自动轮转为单份 `delete-log.old.txt`。

---

## 三、安全边界承诺

- **先写意图再执行**：每一笔文件删除或回收都遵循 `Intent -> Action -> Outcome` 落盘审计契约；日志不可写时整批拒绝派发。
- **二次句柄身份复核**：批量删除前在独占句柄上核对 `VolumeSerial + FileIndex`、文件大小、修改时间并重跑流式内容头校验，防止扫描后文件被掉包（TOCTOU 防护）。
- **重解析点零穿透**：扫描与清理全程拦截符号链接（Symlink）与目录联接（Junction），绝不越界追踪。
