# MAS 核心分析与 Rust 迁移记录

本记录针对固定上游 `6401d2f36975dc07bcb6d22ea823a8498a75ec01`（MAS 3.12）和 KMS38 最后保留版本 `c9789e9aa34145b6608204dba8d8f5f3e71c6d86`。

## 当前故障分析

旧版本把上游脚本释放到 `tempfile::tempdir()` 创建的用户 Temp 子目录。MAS_AIO 的启动代码明确检测 `%USERPROFILE%\AppData\Local\Temp` 下的子目录并拒绝执行，认为脚本仍在压缩包临时提取目录中。KMS38 历史版本也有相同检查。

旧启动器使用相对 `call engine.cmd`。上游首先 `cd /d %SysPath%`，随后从 `%~f0` 获取自身文件路径；相对调用不能可靠地保留原来的绝对路径。后续读取脚本自身嵌入的 PowerShell 段会受影响。

用户报告的 `Some(1)` 只说明进程退出码为 1，不能单凭它确认具体失败分支或 PowerShell 环境损坏。两项启动缺陷已修正：

- 兼容引擎释放到 `%LOCALAPPDATA%\MAS-Rust\engine-runs\run-*`，不在 Temp 子目录中。
- 使用 `call "%~dp0engine.cmd"`，在上游切换工作目录前传入绝对路径。
- 非交互功能将 stdout/stderr 写入文件，由 Rust 增量读取到日志页；完整日志保存在 `%LOCALAPPDATA%\MAS-Rust\logs`。
- 交互菜单保留独立控制台，不将输入输出重定向为不可交互的管道。

## 上游核心分解

| 模块 | 上游主要入口 | 核心工作 | 当前 Rust 状态 |
| --- | --- | --- | --- |
| 通用许可证管理 | `dk_actids`、`dk_inskey`、`dk_refresh`、`dk_act` | WMI 查询、安装密钥、刷新状态、激活、配置 KMS | 使用 COM/WMI 直接调用，不运行 PowerShell / WMIC / cscript |
| HWID | `HWIDActivation`、`hwiddata`、`sign` | 匹配 SKU/Activation ID、生成并签名 GenuineTicket、ClipSVC 导入、联机激活 | 主要流程已迁移 Rust；未移植所有修复分支 |
| KMS38 | 历史文件 `k_menu2`、`kms38data`、`sign` | GVLK、2038 票据、专用 KMS 主机、SKU rearm、宽限期检查 | 主要流程已迁移 Rust；新构建在任何密钥修改前拒绝 |
| Ohook | `OhookActivation`、`oh_process`、`oh_hookinstall` | 检测 Office C2R/MSI 和架构、安装许可、部署 hook DLL、处理订阅许可与卸载 | 尚未迁移，显式兼容后端 |
| TSforge | `TSforgeActivation`、`tsforge` | 嵌入约 5,000 行 C#；SPP API、密钥配置、物理许可存储、密码学、SCID/ZCID/KMS4k | 尚未迁移，显式兼容后端 |
| Online KMS | `KMSActivation`、`_taskact`、`_act` | 版本/通道转换、GVLK、服务器重试、续期任务、卸载 | Windows / 已安装 Office KMSCLIENT 的激活、重试和续期已迁移；Office 通道转换仍为兼容后端 |
| 高级工具 | 版本切换、排障、OEM 提取 | 组件修复、Office 安装器、系统版本切换、生成部署脚本 | 保留上游交互菜单 |

### HWID / KMS38

`src/native/catalog.rs` 使用从上游提取的 TSV。匹配同时要求 SKU 与系统实际存在的 Activation ID，避免把 LTSC 不同版本当成同一种产品。回退版本使用上游表，受“不自动更改版本”选项控制。

`src/native/ticket.rs` 对应上游 `:sign`：

1. 按上游格式构建 SessionId 字符串。
2. 以 UTF-16LE 编码并追加 NUL，进行 Base64 编码。
3. 按原始字段顺序构建 Properties。
4. 解析上游公开的 CSP RSA key blob，用 Rust 计算 SHA-256 / RSA PKCS#1 v1.5 签名。
5. 输出 GenuineTicket XML。

两个固定测试向量由独立的 Python cryptography / OpenSSL 实现生成，分别覆盖 KMS38 和 Windows Pro HWID，Rust 输出逐字节一致。向量验证的是格式和签名兼容性，不验证 Windows 是否接受票据。

`src/native/platform.rs` 直接调用服务控制 API、注册表 API 和 `SLGetWindowsInformationDWORD`。票据导入仍调用 Windows 自带 `clipup.exe`；它是系统授权组件，不是 PowerShell 包装器。

`src/native/activation.rs` 只报告实际查询到的许可状态：HWID 要求 `LicenseStatus=1` 且宽限期为 0；KMS38 要求 `LicenseStatus=1` 且宽限期大于 180 天。已有待处理票据不会被覆盖；服务停止后在导入成功或失败路径均尝试恢复。密钥安装失败与 HRESULT 原样显示，不能把进程退出码当成激活成功。

### Online KMS（v0.3.0）

`src/native/kms.rs` 使用固定上游 `ksdata` / `kmsfallback` 表选择 Windows 密钥，保留已激活的永久许可和 KMS38，并按上游规则区分 Enterprise G。`src/native/online.rs` 直接通过 SPP/OSPP WMI 设置产品专用服务器、激活、重新查询状态；仅在授权且宽限期有效时报告成功。自定义服务器不回退到公共列表；全部失败时尝试还原主机和端口，但不回滚已安装的产品密钥。

`src/native/renewal.rs` 通过 Task Scheduler COM 注册 SYSTEM 任务，无 PowerShell / cmd / schtasks。任务每 6 小时运行 `%ProgramFiles%\MAS-Rust\Renewal` 中按内容哈希命名的程序副本，使用 `--kms-renew` 无界面入口；只续期已有 KMSCLIENT 许可，不安装密钥。注册/删除前检查任务来源标记，避免覆盖同名无关任务。卸载保留可能仍在运行的副本和日志。

当前未迁移 Office Retail → Volume 转换、未安装的 Office 批量许可部署、上游旧任务清理及全部故障修复分支，保留完整兼容菜单。GUI 与后台任务属于不同进程，运行手动激活时应避免同时运行续期任务。此版本尚无 Windows 实机验收结果。

### 尚未达到上游等价覆盖的地方

- HWID 未迁移地区临时调整、订阅版基础 SKU 纠正、IdentityCRL 清理、损坏许可证修复与网络排障重试。
- KMS38 未迁移 ACL 解锁/保护修复、Server Core 缺失系统组件处理等分支；仅支持保守判定的旧构建，不恢复系统已删除的许可机制。
- Office 多版本并存时，密钥安装按有相应许可证的提供程序选择；复杂并存场景需要实测。
- 原生“设置/清除 KMS”作用于所选 Windows / Office 已安装许可证的专用设置，不清除其他产品或全局 KMS 默认值。
- Ohook、TSforge、Office Retail 转换和高级菜单仍依赖 Windows PowerShell；界面按钮标注为“兼容”。**当前不是完整的纯 Rust MAS。**

### TSforge 后续迁移依赖

不能仅把调用 PowerShell 的启动器换成 Rust 就认为 TSforge 已迁移。上游的 `SLApi`、`PKeyConfig`、`ProductKey`、`PhysStoreCrypto`、`TokenStoreModern`、`ModernBlock`、`VistaBlock`、`Win7Block`、`VariableBag`、`ZeroCID`、`KMS4k` 等需要分别实现。进入写入许可存储之前，需要覆盖真实存储样本的解析、重序列化一致性、校验和与加密测试，以及备份恢复流程。

Ohook 还包括独立 hook DLL，完整 Rust 实现需要兼容 DLL 导出与转发行为，并验证 Office x86/x64、C2R/MSI 的路径和卸载恢复。现阶段未将原始 DLL 的解码部署伪称为 Rust 重写。

## 验证与实机验收

自动验证包含窗口尺寸回归、输入校验、SKU/Activation ID 匹配、回退选项、KMS38 构建边界、启动器路径/日志、原生路由及票据向量。Linux GUI 截图确认滚动条位于右侧；Windows 代码进行交叉编译和 Clippy 检查。

仍需在可恢复的 Windows 测试环境验证 COM/WMI 返回、服务启动/恢复、ClipSVC 导入、联机结果及各 Office 版本。此开发环境没有 Windows 实机，未执行激活。

参考：[WMI SoftwareLicensingProduct](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct)、[SoftwareLicensingService](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingservice)。

## 用户验证反馈

2026-10-24：用户反馈 v0.2.0 测试工作正常。未提供具体系统构建号、激活方式及 Office 版本，因此保留未验证组合的说明。
