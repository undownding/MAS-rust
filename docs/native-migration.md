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
| Ohook | `OhookActivation`、`oh_process`、`oh_hookinstall` | 检测 Office C2R/MSI 和架构、安装许可、部署 hook DLL、处理订阅许可与卸载 | Rust DLL 源码构建、许可准备、部署及卸载已接入；边缘修复分支与实机验收仍待完成 |
| TSforge | `TSforgeActivation`、`tsforge` | 嵌入约 5,000 行 C#；SPP API、密钥配置、物理许可存储、密码学、SCID/ZCID/KMS4k | Windows/Office/Project/Visio/ESU/KMS Host/APPX 与组合的现代存储入口及重置已接入 Rust；旧存储仍兼容 |
| Online KMS | `KMSActivation`、`_taskact`、`_act` | 版本/通道转换、GVLK、服务器重试、续期任务、卸载 | Windows / 已安装 Office KMSCLIENT 的激活、重试和续期已迁移；新增 C2R 许可转换与 MSI 批量许可准备；清理/修复分支仍有缺口 |
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

v0.4.0-dev 新增 `office.rs` / `office_catalog.rs` / `registry.rs`：原生读取两种注册表视图中的 C2R 产品信息，按上游表转换许可产品，直接通过 WMI 导入缺失的 XRM 文件并安装密钥，维护 OSPPReady 和旧 Office 的 ProductReleaseIds。导入前读取并解码整组文件，安装顺序为发行证书、产品许可、pkeyconfig。MSI 根据注册信息及 InstalledPackages 识别产品，只安装原生受支持的批量许可密钥。

Office 订阅缓存/屏蔽清理已接入原生 API；仍未迁移冲突旧密钥清理、UWP 许可准备、上游旧任务清理及全部故障修复分支，保留完整兼容菜单。`session.rs` 用 Windows 全局命名互斥量串行化 GUI、许可证操作和后台续期；后台任务遇到占用会记录错误并等候下一次计划触发。此版本尚无 Windows 实机验收结果。

### 尚未达到上游等价覆盖的地方

- HWID 未迁移地区临时调整、订阅版基础 SKU 纠正、IdentityCRL 清理、损坏许可证修复与网络排障重试。
- KMS38 未迁移 ACL 解锁/保护修复、Server Core 缺失系统组件处理等分支；仅支持保守判定的旧构建，不恢复系统已删除的许可机制。
- Office 多版本并存时，密钥安装按有相应许可证的提供程序选择；复杂并存场景需要实测。
- 原生“设置/清除 KMS”作用于所选 Windows / Office 已安装许可证的专用设置，不清除其他产品或全局 KMS 默认值。
- TSforge 的旧版存储 Windows，以及 Office 部分修复分支和高级菜单仍依赖 Windows PowerShell；入口明确标注。**当前不是完整的纯 Rust MAS。**

### TSforge 后续迁移依赖

不能仅把调用 PowerShell 的启动器换成 Rust 就认为 TSforge 已迁移。上游的 `SLApi`、`PKeyConfig`、`ProductKey`、`PhysStoreCrypto`、`TokenStoreModern`、`ModernBlock`、`VistaBlock`、`Win7Block`、`VariableBag`、`ZeroCID`、`KMS4k` 等需要分别实现。进入写入许可存储之前，需要覆盖真实存储样本的解析、重序列化一致性、校验和与加密测试，以及备份恢复流程。

Ohook 从 v0.5.0-dev 起直接从固定 `ohook-rs` 源码构建两种架构的 DLL；Office x86/x64、C2R/MSI 的真实安装与卸载仍需实测。

## 验证与实机验收

自动验证包含窗口尺寸回归、输入校验、SKU/Activation ID 匹配、回退选项、KMS38 构建边界、启动器路径/日志、原生路由及票据向量。Linux GUI 截图确认滚动条位于右侧；Windows 代码进行交叉编译和 Clippy 检查。

仍需在可恢复的 Windows 测试环境验证 COM/WMI 返回、服务启动/恢复、ClipSVC 导入、联机结果及各 Office 版本。此开发环境没有 Windows 实机，未执行激活。

参考：[WMI SoftwareLicensingProduct](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct)、[SoftwareLicensingService](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingservice)。

## 用户验证反馈

2026-10-24：用户反馈 v0.2.0 测试工作正常。未提供具体系统构建号、激活方式及 Office 版本，因此保留未验证组合的说明。


## 完整迁移验收清单（目标保持进行中）

以下缺口均属于目标范围，不能以已有原生路由或编译通过代替完成：

- [ ] HWID：地区、订阅 SKU、IdentityCRL、修复及重试分支；票据导入实测。
- [ ] KMS38：ACL、Server Core、保护与卸载完整流程；兼容构建实测。
- [ ] Online KMS：UWP、订阅/旧密钥清理、免费产品状态处理、旧任务迁移/清理、跨进程互斥；转换与续期实测。
- [ ] Ohook：完整检测、密钥/许可、Rust hook DLL（x86/x64）、注册表/订阅处理、安装与卸载恢复；各安装布局实测。
- [ ] TSforge：SL API、产品密钥配置、物理存储/令牌解析与序列化、密码学、备份恢复、SCID/ZCID/KMS4k；覆盖现有全部按钮及故障恢复。
- [ ] 高级工具：状态、Windows/Office 版本切换、组件排障与修复、OEM 导出和帮助入口，逐项替代完整脚本菜单。
- [ ] 删除已无必要的运行时脚本后端；查明剩余外部程序属于系统组件还是尚未迁移的代码。
- [ ] 更新 README、截图、构建产物与来源记录，并用与上述范围一致的测试和 Windows 实测验收。

2026-10-24：本轮接入 Office 转换及 MSI 许可准备。25 项本地单元测试通过，Linux/Windows Clippy 通过；尚无新增路径的 Windows 实机证据。


### v0.4.0-dev.2：Ohook 卸载与 Office 清理

`ohook.rs` / `hook_files.rs` 接管 `/Ohook-Uninstall`，覆盖注册表安装路径与标准 Office 目录、SPP hook 清理、OSPP 原 DLL 恢复。文件锁与冲突原 DLL 会保留并报错，重跑可继续；不跟随目录重解析点递归删除。保留原始备份冲突的处理与上游强制覆盖不同，避免静默覆盖未知文件。

`office_cleanup.rs` 实现用户/机器许可缓存、共享/设备/OEM 设置清理，并在卸载时移除用户和默认配置的 Resiliency。离线用户配置使用 RegLoadKey、临时挂载名称及权限恢复，显式关闭句柄并卸载；失败逐项报告。没有将 RegLoadAppKey 当作通用 NTUSER 加载器，其安全描述符限制见 [Microsoft 文档](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeyw)。

新增临时文件测试覆盖 DLL 恢复、冲突备份保护及符号链接边界；Windows CI 另测独立 HKCU 测试树的删除边界和互斥锁的竞争/释放。自动检查不等价于已安装 Office 的卸载和离线用户配置实测。上方总清单仍未完成。


### v0.5.0-dev：Ohook DLL 与安装路径

- 固定 `massgravel/ohook-rs` 提交 `044af0e99d40a449c855d989feb7ad8ff042783f`，保留 MIT 许可。构建时直接调用 Rust 编译器和自带 LLD，源码及本地改动见 `vendor/ohook-rs/NOTICE.md`。
- 去掉上游空导出桩后，以原始 DEF 文件生成系统函数转发；构建阶段核对机器类型及每项转发，防止“DLL 编译成功，但实际调用空函数”。修正 Grace 检索的字节/UTF-16 长度边界。
- C2R/MSI 从上游 Ohook 表选择原产品许可，保持订阅产品 ID；设置 ProductReleaseIds、必要的服务器共享许可、Resiliency；清理可安全区分的旧密钥。Office 2010 使用 OSPP 服务和原 DLL 备份。
- 文件替换前暂存新文件及链接，出现失败按逆序恢复；回滚失败保留备份路径。不同安装目标间不是一次整体事务，失败结果会报告部分完成。
- Windows 隔离测试用真实 x86/x64 hook、模拟 SPP DLL 和独立测试进程验证错误透传、未授权/Grace 产品保留、状态字段修改，不调用真实许可服务。还需要 Office 实机验收、旧预览许可修复、Insider 许可刷新及完整故障分支。
- DLL 不做随机时间戳/哈希修改，便于核对构建产物。当前仍非完整纯 Rust MAS，TSforge 和高级菜单仍须继续迁移。

2026-10-25：Windows CI 运行 40109316569 已通过包括 x86/x64 隔离 DLL 加载在内的测试；后续 Clippy 因 Rust 1.99 新检查指出冗余闭包借用而失败，已修正。该结果证明模拟提供程序下的 DLL 行为，不等同于 Office 安装实测。

### TSforge 底层迁移（进行中）

2026-10-25：`src/native/tsforge` 新增 Vista/现代 VariableBag、Vista/Windows 7/现代物理存储的编解码，以及物理存储加密封装。依据仓库固定 MAS 源码中的同名 C# 类移植，没有使用候选 Rust 项目内嵌的 .NET 程序。

- 使用上游 CRC-32/BZIP2 算法。保留未知类型、标记、原始键字节、重复键顺序、现代存储分组及头部；读长度时先检查边界再分配内存。拒绝截断记录、异常计数和非零对齐填充，避免重写时静默丢弃未识别数据。当前仅接受已实现的规范格式，需要真实样本补充兼容性验证。
- 加密封装实现 RSA PKCS#1 v1.5/SHA-1、AES-CBC/PKCS7（读取 128/192/256 位密钥）、Vista 盐化 SHA-1 和后续版本 HMAC-SHA1。生产/测试 RSA blob 来自固定上游公开常量；复用已验证的 CSP blob 解析器。新封装使用系统随机源，私钥解密使用 RSA blinding。
- 封装解析检查版本、`UNTRUSTSTORE` 标记、RSA 签名及完整性校验；当前拒绝未知头部或非零保留字段。未知格式必须显式扩展后才可写入，不自动猜测。
- `tools/tsforge_codec_vectors.py` 用独立多项式除法生成格式向量；`tools/tsforge_crypto_vectors.py` 用 Python cryptography/OpenSSL 生成确定性的加密样本，覆盖两套公开密钥、三种 AES 长度及两种完整性算法。样本完全合成，不包含机器许可数据。固定 RSA 填充仅用于测试向量。
- **此阶段模块仅在测试构建中启用；v0.6.0-dev 已将重置所需模块和依赖转入运行时，见下文。** 还需真实 TokenStore 布局兼容性验证、SL API、产品密钥配置、备份/恢复和写入事务，之后逐项接入 SCID/ZCID/KMS4k。未宣称 TSforge 激活已原生化。

上一轮 Ohook 修复的 Windows CI [40109703595](https://github.com/undownding/MAS-rust/actions/runs/40109703595) 已全部通过。

同日继续迁移 `TokenStoreModern` 和 `TokenMeta`：实现目录块链接、固定 UTF-16 字段、内容记录和元数据编解码，并核对文件/块/内容 SHA-256。合成双块样本包含中文、代理对、具名未填充项、零字节内容及重复元数据键。测试覆盖循环链、错误偏移、篡改、截断、字段超长，以及 103 项块边界的重复序列化稳定性。

当前 TokenStore 解析器只接受完整、无间隙、分配长度等于内容长度的规范布局；对于未识别的空闲空间、孤立内容、字段尾部、非规范未填充项或未知版本明确拒绝。此限制是避免静默丢弃未知数据，**不能据此宣称已支持真实系统的所有 tokens.dat**。序列化不重复添加多余空块，保留已有完整槽位数量；对应上游每次在整块边界附加一个空块的行为差异已通过稳定性测试。尚未对系统 tokens.dat 执行读取或写入。

### TSforge SL API 封装（进行中）

2026-10-25：新增 `tsforge/sl.rs`，使用 `windows-sys` 的 SDK 绑定实现 SLC 上下文、状态/ID 枚举、SKU/产品密钥属性、许可证读取、IID/CID、密钥安装/卸载/选择及状态事件。上层包含默认激活 ID、附加组件/电话属性判断、产品密钥配置文件 ID 解析和按应用卸载密钥；实际写操作尚未接入 GUI。

使用 RAII 关闭 SLC 上下文，并释放 API 返回的 LocalAlloc 内存；先核对分配长度再读取返回数组，字符串按分配边界查找结束符。保留调用名称与原始 HRESULT，只把 `SL_E_VALUE_NOT_FOUND` 识别为属性不存在；其他查询错误不再被误认为“支持电话激活”或无附加组件。使用 SDK 的 `SL_DATA_DWORD = 4`，不沿用上游手写枚举的连续编号。密钥批量卸载先完成枚举和筛选，执行阶段出错停止并保留错误；它不是整体事务，调用方仍须持有全局许可操作锁。

依据 Microsoft 文档核对 [SKU 属性与 LocalFree](https://learn.microsoft.com/en-us/windows/win32/api/slpublic/nf-slpublic-slgetproductskuinformation)、[IID 返回内存](https://learn.microsoft.com/en-us/windows/win32/api/slpublic/nf-slpublic-slgenerateofflineinstallationid) 和 [状态结构查询](https://learn.microsoft.com/en-us/windows/win32/api/slpublic/nf-slpublic-slgetlicensingstatusinformation)。新增 Windows 测试覆盖 SDK 数据类型、错误保留、内存边界/字符串终止和真实只读 SLC 状态查询，不执行密钥安装、CID 导入或状态刷新。此阶段模块仅参与测试构建；v0.6.0-dev 已用于重置流程，完整激活调用链和实机验收仍待完成。非公开 `SLConsumeWindowsRight` 按固定上游 ABI 动态解析，缺少导出时显式报错；它不是稳定 SDK API，测试不会调用。`SLActivateProduct` 使用 SDK 的正确参数类型封装，尚未执行联机调用。

### TSforge 存储备份、回滚与服务协调（进行中）

2026-10-25：新增 `transaction.rs` 与 `service.rs`。文件修改前打开全部目标，Windows 使用独占句柄；在持有句柄时解析/转换原始内容，避免读取与写入之间的更新被覆盖。保留原文件并原位写入，以保留 ACL；拒绝重复路径、硬链接和检查到的重解析路径。当前最多处理 16 个文件，原始内容与替换内容总量限制为 256 MiB，超限明确报错。

首次修改前，在首个存储文件的父目录创建独立备份目录，写入各文件原始/替换字节、SHA-256 清单和日志并刷新文件缓冲区。修改失败时逆序恢复已经触碰的文件，恢复后逐字节核对；回滚失败报告具体文件并保留备份。显式恢复要求调用方提供与清单一致的目标路径，校验全部备份后才开始恢复；恢复操作也先备份当前状态。仅准备或丢弃事务不会写入存储。

这不是跨文件原子提交。断电或进程终止可能留下部分修改，持久备份与日志供后续显式恢复；GUI 的恢复入口和启动时发现未完成事务仍未接入。Windows 刷新每个备份/日志文件，尚未证明所有文件系统和断电场景下的持久性。目标路径应处于受保护的系统目录；路径预检并不构成针对管理员并发替换父目录的安全边界。

服务协调保存初始运行状态，停止失败时不执行存储回调，并尝试恢复原本运行的服务；操作失败与恢复失败同时发生时保留两条错误。正常返回显式恢复，展开栈时提供 best-effort 恢复。原本停止的服务保持停止；后续激活流程仍需显式刷新许可状态。测试使用模拟服务，不改变开发机或 CI 的真实 SPP 服务状态。

本轮文件测试覆盖成功写入/恢复、部分写入失败、多文件回滚、回滚失败后的显式恢复、损坏备份、目标不匹配、硬链接、重复/缺失路径、仅准备时不写入、转换验证失败；Windows 另验证独占句柄阻止并发写入。此阶段新增模块仍在测试构建中；随后 v0.6.0-dev 接入了重置路由。

上一轮 SL API 的 Windows CI [40111353095](https://github.com/undownding/MAS-rust/actions/runs/40111353095) 已通过测试和 Clippy，包括真实只读 SLC 状态查询；检查时 release 构建仍在执行。


### v0.6.0-dev：TSforge 重置入口接入 Rust

`/Z-Reset` 现在由 Rust 直接执行，GUI 将该按钮标为 Rust；其余 TSforge 激活按钮继续标为兼容。当前运行时支持现代存储布局（Windows build 9600 及更新版本），Vista/7/8 的字段规则已有单元测试，但旧版系统的存储文件发现、双文件同步和服务布局尚未接入，明确报错而不静默切回脚本。

流程遵循上游顺序：清理 tamper 标记并刷新许可状态；在一次服务停止期间重置 rearm 计数与宽限/评估计时器，再刷新；最后清理密钥变更锁。运行前检查权限、架构、系统构建及刷新 API 可用性。按注册表 TokenStore 和上游标准路径查找 data.dat；根据 RSA 签名及解密完整性验证选择生产/测试密钥，不猜测首个 WPA 注册表项。

每阶段持有独占文件句柄后解析、修改、序列化并重新解析，再加密及解密核对；写入前记录持久备份路径。没有对应记录时不重写存储。失败会说明已完成阶段数量；先前已完成阶段不自动撤销。服务恢复保留初始运行状态。此路径不调用 PowerShell，也不修改 tokens.dat。

新增字段规则测试覆盖版本差异、大小写敏感子串匹配、未知字段保留、幂等性；加密集成测试覆盖两套密钥下的重置及损坏存储拒绝。重置不代表激活成功。尚无真实 Windows 许可存储重置的实机证据，严格解析可能拒绝未覆盖布局；仍需补充真实样本、显式恢复 GUI 与中断恢复入口，继续迁移 SCID/ZCID/KMS4k 等激活流程。原来的总体迁移清单保持未完成。

本轮验证：63 项本地测试通过，Linux 与 Windows GNU 交叉 Clippy 通过；实际 Linux GUI 截图已更新。前两轮 Windows CI 40111353095（SL API）和 40111877322（事务/服务协调）均已全部成功。这些结果不能代替在真实 Windows 许可存储上执行本轮重置的验收。


### v0.6.0-dev.2：GUI 备份恢复

TSforge 面板新增备份目录输入与恢复按钮，沿用后台执行、进度日志和操作确认。恢复操作持有同一全局互斥锁，按本机当前路径定位 data.dat；清单不能指定其他写入目标。全部备份通过校验和、RSA/AES 完整性及物理存储格式检查后，才建立恢复事务，先备份当前数据再写入，并恢复服务初始状态、刷新许可状态。操作失败会区分存储是否已经完整恢复；回滚错误和备份目录保留在日志。

新增测试验证即使 SHA-256 正确，只要任意文件未通过格式验证，所有目标都不会被恢复写入。64 项本地测试与 Linux/Windows 交叉 Clippy 通过；没有执行真实系统许可恢复。当前只恢复物理存储，不回退其他组件。GUI 显式恢复已完成，启动时发现中断事务、旧版布局和完整 TSforge 激活流程仍待继续迁移。

### TSforge PKEY2009 数据编码（进行中）

新增 `product_key.rs`，移植 20 位组号、30 位序列号、53 位安全字段、升级位和 CRC-32 校验位的组合、24 进制文本与 N 标记、产品密钥绑定 VariableBag/SHA-256 ID、现代/Windows 7 电话数据，以及 PID3/PID4 和 Extended PID。PID4 使用调用方明确传入的 MPC、地区、系统构建和日期，避免测试依赖运行机器。固定字符串字段按 UTF-16 字节长度验证，越界、嵌入 NUL 和非法字段值报错，不截断数据。

`tools/tsforge_key_vectors.py` 使用上游逐字节除法生成文本，而 Rust 使用 u128 除法；CRC 复用独立多项式除法参考实现。五组向量包含零值、所有位宽上限、上游两组 SCID 参数及跨位边界值；逐字节核对密钥、绑定数据/ID、两种电话数据及 PID3/PID4。样本只用于数据编码验证，不安装密钥、不调用许可服务。

该模块暂在测试构建中，尚未接入安装流程。PKEY2005 需要兼容上游使用的 .NET Framework Random(int seed) 五字符后缀，以及 PID2；随机数规则已核对 [Microsoft Reference Source](https://raw.githubusercontent.com/microsoft/referencesource/main/mscorlib/system/random.cs)，后续需用实际 .NET 向量交叉验证。PKeyConfig XML 的算法/产品/范围映射及运行时集成也仍待完成，TSforge 激活按钮保持兼容路由。

### TSforge PKEY2005 与旧版随机数兼容（进行中）

新增 `Key2005` 数据编码，复用已验证的字段布局、绑定 VariableBag 和 PID 固定字段写入，实现上游五字符后缀、算法 URI、绑定 ID、两种电话数据，以及 OEM/非 OEM PID2 与对应 PID3/PID4。PID2 的非 OEM 随机尾数改为由调用方显式提供 0..999 的值，便于后续用系统随机源及固定测试值；尚未接入安装流程。

`legacy_random.rs` 实现上游依赖的 .NET Framework 有种子减法随机数算法，包括 Int32 溢出、负种子及 Int32.MinValue 特例。依据 Microsoft Reference Source 固定提交 `ec9fa9ae770d522a5b5f0607898044b7478574a3`，源码与 MIT 许可保存在 `vendor/dotnet-reference`。该随机数只用于重现 PKEY2005 文本后缀，不用于密码学。

新增五组密钥/PID 向量与 11 组种子的各 128 个随机输出。本地 Rust 与 Python 参考实现匹配，Windows CI 通过 `tools/verify_pkey2005.ps1` 额外调用真实 .NET Framework System.Random 校验随机序列和密钥后缀；该脚本仅为测试用，不随应用运行，也不调用许可 API。68 项本地测试和双平台 Clippy 已通过，实际 Framework 核验结果以本次 CI 为准。接下来仍需 PKeyConfig 配置解析、产品/范围选择、运行时安装与完整激活流程。

### TSforge PKeyConfig 解析与范围选择（进行中）

新增 `pkey_config.rs`：按 XrML 命名空间与固定路径提取 `pkeyConfigData`，解码 Base64/UTF-8 后解析算法、产品、配置 ID 与密钥范围。GUID 统一为规范值，不依赖原 XML 的大小写或大括号形式；保留范围原始部件号，使用时按上游冒号/分号规则取首段。加载按许可证文件 ID 缓存，解析完整成功后再合并；重复产品保留首次加载项，失败不会留下半份配置。

保留上游 `Contains` 的闭区间，以及 `Random.Next` 通常排除终点、起终点相同时返回该点的区别。PKEY2009 排除 EULA 含大小写敏感 `WAU` 的范围，PKEY2005 保留；`IsValid` 作为元数据保留，上游未用于选择过滤。随机选择使用系统随机源与拒绝采样。`Randomized` 按固定上游的 ProductKeyType 字段派生，未赋予额外选择语义。

解析器拒绝缺失/冲突的算法、超出编码位宽或反向区间、重复标量、嵌套标量和未知命名空间，不把未知组默认当作 PKEY2005。禁用 DTD，限制 XML 为 64 MiB/一百万节点；这些限制可能拒绝未覆盖格式，必须明确扩展而非静默猜测。新增合成 XML 测试覆盖命名空间别名、Unicode/CDATA/注释、实体转义、范围边界、WAU、缓存、重复产品及失败事务。

Windows 测试新增经原生 SLC API 读取真实 Windows 许可证内配置并解析的只读验证，不安装密钥、不输出许可证全文。当前配置模块仍在测试构建中，尚未接入 TSforge 激活。72 项本地测试和双平台 Clippy 已通过；真实许可证及前一轮 .NET 核验的结果继续以对应 CI 为准。


### TSforge PKEY2005 安装数据计划（进行中）

新增 `key_install.rs`，按上游 GenPKeyInstall 构造九项安装 VariableBag；该数据不同于计算密钥 ID 的三项绑定数据。使用同一 PID 随机尾数生成 PID2/PID3，输出与存储内容一致的注册表数据计划。处理现代物理存储的密钥记录、产品/算法 URI/Windows 版本令牌元数据，保留无关记录及未知字段。Windows 基础产品与附加产品由调用方明确区分；附加产品不生成 Windows 版本令牌或注册表计划。

当前仅接受 Windows 8/8.1/现代布局；按版本选择物理记录标志 2 或 0x402。遵循上游仅移除首个 pkeyId_ 元数据键、仅替换首个已填充令牌、清除对应未填充 XML 令牌的规则。目标元数据有重复键、目标物理键有歧义时明确拒绝，未涉及的数据继续原样保留。所有操作在借用输入的副本上完成，完整序列化和重新解析成功后才返回结果，失败不会修改输入文件。

新增五项测试，覆盖安装袋/PID/注册表数据一致性、令牌更新语义、无关数据保留、重复执行、版本标志、非 Windows 基础产品分支、损坏元数据和超长名称拒绝。77 项本地测试及 Linux/Windows GNU Clippy 通过。前一轮 .NET Framework 随机数及 PKEY2005 后缀的 Windows 核验已成功（40113907032）；PKeyConfig 的真实许可证读取验证（40114626605）已成功。

此模块仍限于测试构建，不写系统许可、注册表或缓存。下一步需接入服务协调、双存储事务、注册表备份恢复、许可 API 及 PKEY2009 安装，再推进完整激活路径；GUI 激活入口仍标为兼容。本轮没有界面或运行时变化，因此保留现有截图和测试包。


### 原生注册表精确备份接口（进行中）

注册表封装新增原始值查询、写入与恢复回读：保存 Windows 类型编号和完整原始字节，区分不存在与零字节值，不展开 REG_EXPAND_SZ，也不修补 REG_SZ 的终止符。读取期间遇到值增长会重新查询，最多八次；单值限制 16 MiB，含 NUL 的名称被拒绝。现有字符串和 DWORD 写入复用原始写入接口。

新增 Windows 专用测试使用独立 HKCU 临时键，覆盖二进制、空值、REG_NONE、未终止/奇数字节字符串、环境变量字符串、多字符串、DWORD/QWORD、默认值、原本不存在的值、只读句柄失败和输入限制。测试不触碰系统许可注册表。77 项本地测试及 Linux/Windows GNU Clippy 已通过；原生注册表测试需要本次 Windows CI 执行。

该接口只完成值级精确恢复，不是多值原子事务，也未提供持久注册表备份。TSforge 安装尚需将这些原始值加入持久清单，与双存储写入、失败回滚和中断恢复协调；不能据此宣称安装流程已经接入。


### 存储与注册表联合事务（进行中）

文件事务增加外部状态参与接口：全部存储仍保持独占句柄；注册表原值与替换值在任何写入前保存到同一备份目录。先提交存储，再提交注册表；注册表部分失败时先尝试恢复注册表，再恢复存储。任一回滚失败不阻断其他恢复，错误分别记录并标记 recovery-required。外部状态备份带有显式标记，当前文件恢复 GUI 会拒绝这类备份，避免只恢复 data.dat 却宣称完整恢复；联合恢复入口仍待实现。

`registry_backup.rs` 实现原生注册表参与者：捕获原值、检测准备/提交之间的变化，保存带 SHA-256 校验文件的版本化 JSON 清单，按逆序恢复已触及的值。清单使用调用方定义的逻辑 ID，不携带可控制写入位置的注册表路径。限制最多 32 个值、原值及替换值合计 16 MiB；写入与恢复均刷新注册表并回读验证。该参与者尚未接入激活 GUI，不能视为跨文件/注册表原子提交，也不承诺断电原子性。

新增五项联合事务故障测试覆盖预备失败、文件失败、注册表部分失败、回滚失败和拒绝部分恢复；82 项本地测试及双平台 Clippy 通过。另增两项 Windows HKCU 测试验证真实注册表备份/恢复与并发变化拒绝，结果待本次 CI。

前一轮 Windows CI 40115308409 发现未终止 REG_SZ 写入会被 Win32 补终止符，原来的“任意原始字符串均可精确写回”假设不成立。根据 [RegSetValueExW 文档](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw)，已在写入及事务捕获阶段检查字符串终止和偶数字节长度，无法保证精确写回的异常值在修改前拒绝；原始读取仍不展开或修补内容。测试改为验证明确拒绝及原值不变，而不是接受归一化结果。此失败尚不能被本地交叉检查代替，修复需新的 Windows CI 验证。


### 联合备份恢复后端（进行中）

新增 `RegistryValues::from_backup`：有界读取注册表 JSON 和 SHA-256，检查版本、值类型、Base64、必需字段及完整目标集合。使用调用方提供的逻辑 ID → 已打开注册表键/值映射，拒绝缺失、额外或重复目标；不从备份推导注册表路径。整个清单（包括不用于恢复的 replacement 字段）先校验完成，再读取当前注册表状态作为本次恢复的撤销依据。

`restore_participating` 在校验所有文件备份、格式、目标路径和外部状态标记后，通过原有联合事务执行恢复。恢复备份保存当前真实状态，不能假定上次安装已完整成功。失败回滚恢复到本次操作前的状态，文件恢复接口仍拒绝带外部状态的备份。

新增两项跨平台测试验证第二个文件校验失败时注册表参与者尚未准备，以及注册表恢复失败时文件回退到恢复前状态；84 项本地测试和双平台 Clippy 通过。新增两项 Windows HKCU 测试覆盖双文件/注册表恢复与再次撤销、校验和损坏、错误版本/ID/类型/Base64、缺失字段和非法字符串；Windows 验证待 CI。前一轮安装数据计划的 Windows CI 40115113327 已成功，联合事务及字符串边界修复的 40115772766 仍在运行。

联合恢复目前是内部后端，GUI 尚未绑定具体注册表目标及双存储路径；安装流程接入仍未完成。本轮不改变界面，保留现有截图。


### v0.6.0-dev.3：GUI 联合恢复接入运行时

现有备份恢复按钮现在识别联合状态标记：普通重置备份继续只恢复 data.dat；联合备份恢复本机 data.dat、tokens.dat 与产品注册表值。两个存储分别按 TokenStore/固定系统目录定位，清单只能匹配这些本机目标；恢复前校验物理存储签名/加密格式和令牌文件的哈希/偏移结构。成功后清除派生 cache.dat，服务恢复与许可状态刷新仍按原有流程执行。缓存清理失败会明确报告数据已恢复，且提前输出恢复前备份路径。

新增固定注册表映射与完整组校验：Windows ProductId/DigitalProductId/DigitalProductId4 三项必需；IE Registration 三项可整组出现；NetworkService KmsHostConfig 可选。拒绝未知、重复或不完整组，不创建缺失的目标键。备份在校验后保持为内存快照，选择目标与恢复使用同一份数据，避免重复读取不同清单。令牌解码器已进入 Windows 运行时。

85 项本地测试及 Linux/Windows GNU Clippy 通过，新增完整组合与拒绝规则测试；实际 Windows CI 继续单独核验。GUI 确认文案、README 和本地 Windows 包同步更新；重新截取并核对真实 Linux 界面，默认折叠状态下截图内容未变化。联合恢复尚无真实系统许可存储的实机验收，安装流程仍未生成联合备份；下一步接入 PKEY2005/PKEY2009 安装及后续激活逻辑，不能将本轮视为 TSforge 完整迁移。


### 生成密钥准备与 PKEY2009 原生 API 安装（进行中）

新增 `generated_key.rs`，将原生 SLC 读取、PKeyConfig 查找、范围选择与密钥编码串联。先读取所选 SKU 的配置；找不到对应产品时枚举同一应用的 SKU，按上游 LoadAllConfigs 跳过无关的不可读取配置，最终仍必须解析到目标产品。PKEY2005/PKEY2009 均生成安全字段为零、升级位关闭的密钥，并保留所选范围元数据。配置解析、VariableBag 和密钥编码模块现已纳入 Windows 构建。

PKEY2009 安装按上游先卸载当前产品密钥、再调用 SLInstallProofOfPurchase，并增加所选 SKU 的密钥映射回读。多个已有密钥或空 ID 的歧义映射在卸载前拒绝；PKEY2005 明确留给存储/注册表安装路径。错误区分尚未完成变更、旧密钥已卸载、新密钥已安装但未验证的阶段。SLC 调用不具备事务回滚，不能宣称安装失败后旧密钥自动还原。

新增四项本地编排测试覆盖无旧密钥、正常顺序、卸载/安装失败、映射不一致、错误算法和零 SKU；89 项本地测试及双平台 Clippy 通过。另增 Windows 只读测试，从真实 Windows SKU 配置准备生成密钥，但不调用安装 API。此前联合事务和字符串边界修复 CI 40115772766、联合恢复后端 CI 40115978732 均成功。

当前模块是后续 TSforge 激活流程的内部组件，GUI 激活按钮尚未改用它；PKEY2005 系统元数据收集、双存储/注册表安装及完整激活流程仍待接入。本轮没有界面或已启用入口变化，不更新截图或测试包。


### PKEY2005 原生安装协调器（进行中）

新增 `key_runtime.rs`：读取系统构建、地区、当地日期和 MPC（含 setup.cfg 覆盖规则），取得应用 ID、附加产品标志及 Windows Family，构造已验证的安装计划。先暂停 SPP、独占读取双存储、验证并生成替换数据、检查注册表可写目标，然后保存不修改实时数据的卸载前检查点；释放存储句柄后执行原生 SLC 卸载，再暂停服务并用联合事务提交双存储与产品注册表。完成后清理派生缓存、刷新可信时间并核对所选 SKU 的密钥 ID 映射。

非 Windows 基础产品采用空注册表参与者，仍保持同样的双存储备份与恢复格式。基础产品保存固定的 Windows/可选 IE/可选 KMS Host 产品值；目标键缺失时在卸载前报错，目前不创建缺失的 KMS Host 注册表键。检查点覆盖许可存储和这些产品值，不承诺覆盖 SLC 的全部系统副作用；卸载 API 不自动回滚，失败消息保留阶段及卸载前备份位置。该协调器尚未由激活 GUI 调用。

新增 MPC 构建边界、setup 覆盖及日期闰年规则测试，以及检查点无实时写入测试；92 项本地测试和双平台 Clippy 通过。Windows 专用测试新增生产/测试密钥下的加密安装计划、损坏令牌拒绝、setup 编码及空注册表恢复测试，不执行真实许可安装。

Windows CI 40116625651 的只读准备测试发现某些 SKU 没有密钥映射时返回 `SL_E_VALUE_NOT_FOUND`。按 [SLGetSLIDList 官方文档](https://learn.microsoft.com/en-us/windows/win32/api/slpublic/nf-slpublic-slgetslidlist)，将这一精确状态映射为空列表，访问拒绝/不支持等错误继续保留；新增针对性回归测试。修复仍待新 Windows CI。GUI 联合恢复 CI 40116291401 已成功。后续继续连接完整 TSforge 激活流程；本轮没有新增可点击安装入口，不更新截图或测试包。


### IID 参数、Unique ID 与 ZeroCID（进行中）

新增 `phone.rs` 和 `phone_runtime.rs`：移植现代存储的 SetIIDParams、UniqueIdDelete 与 ZeroCID 缓存结构。IID 参数复用 PKEY2005/PKEY2009 电话数据编码，保持升级位关闭；Unique ID/Virtual 字段只删除首条，保留其他字段。ZeroCID 使用 UTF-16 的 IID、NUL 分隔符、48 位零 CID 和最终 NUL 计算 SHA-256，再构造带长度的 HWID/PKeyInfo 缓存记录。公共 38 字节 UniversalHWIDBlock 从固定上游原样提取，来源及复现工具已记录。

修改先在副本完成并重新解析校验；缺失/歧义目标、缺少电话数据、无效 IID 或超出字段位宽时拒绝，不静默报告完成。原生运行层先检查产品电话许可和唯一已安装密钥，通过独占文件事务保存备份、改写并验证加密，随后提交确认 ID、刷新许可状态、触发状态事件并核对所选产品是否已许可。后续 API 失败明确报告存储已修改及备份路径。

`tools/tsforge_phone_vectors.py` 独立生成缓存向量，三项新增本地测试覆盖二进制布局、未知字段保留、重复执行、目标歧义和无副作用拒绝；95 项本地测试及双平台 Clippy 通过。当前仅支持现代存储布局（运行时 build 9600+），Vista/7 分支仍待迁移。SCID Web 服务、KMS4k 和激活产品选择尚待接入，GUI 激活按钮仍走兼容路径；本轮没有运行真实系统的 ZeroCID 激活。


### SCID SOAP、WinHTTP 与执行顺序（进行中）

新增 `activation_ws.rs`，移植 BatchActivation 请求的 UTF-16LE 编码、Base64 和 HMAC-SHA256，支持确认 ID 与剩余次数请求。使用紧凑 XML，对实际发送的原始 UTF-16 字节计算签名；不依赖 .NET 的缩进格式。公共 MacKey 从固定上游提取，独立 Python 向量验证 Unicode、实体转义、CR 和签名。响应按命名空间解析，保留服务错误码及其含义；拒绝 SOAP Fault、歧义字段、非法 CID/次数、DTD 和超限 XML，支持 UTF-8/带 BOM 的 UTF-16。

新增原生 WinHTTP 客户端，固定连接 activation.sls.microsoft.com 的 HTTPS BatchActivation 路径，使用系统自动代理、TLS 1.2 和默认服务器证书验证，禁止重定向。设置各阶段 30 秒超时、读取循环 120 秒期限和 1 MiB 响应上限；阻塞调用按阶段超时结束，并非硬实时总期限。Windows 测试只创建配置好的会话，不连接激活服务。

`static_cid.rs` 串联固定上游两组 IID 参数、原生 IID 获取、SOAP 请求、CID 提交与最终许可状态校验。按上游语义，仅 CID 提交失败时尝试第二组参数；网络或解析失败直接报告。错误附带当前阶段和最近一次 IID 修改备份，不把已完成的存储修改描述为未发生。

99 项本地测试及双平台 Clippy 通过；安装协调器/SLC 空映射修复的 Windows CI 40117088106 已成功。新 SOAP/WinHTTP 路径未向真实激活服务发送请求，GUI 仍未切换；接下来继续 KMS4k、产品选择及完整激活流程接入。本轮无已启用入口或界面变化，保留现有测试包与截图。


### 现代 KMS4k 存储与原生执行后端（进行中）

新增 `kms4k.rs`，按上游读取全局创建时间、uptime 和产品 delta，保留 C# unchecked 的有符号加法/无符号转换语义；正确区分 FILETIME 的 100ns 单位与现代计时器的毫秒单位。构造五项现代 VariableBag、固定 KMSv6/HWID 数据及 32 字节计时器，按类型与标志替换首个对应绑定/计时器记录，保留其他数据。计时器期限为上游的 2^31−8 分钟，缺失或截断计数器、歧义产品键会在写入前拒绝。

`kms4k_runtime.rs` 使用原生 SLC 验证唯一已安装密钥和 Volume:GVLK 通道，暂停服务并通过备份事务修改存储、加密与回读验证，随后刷新许可、触发状态事件，并通过原生 WMI 查询所选产品的 GracePeriodRemaining。按上游 build 26100 前后的不同规则验证宽限期；使用本地日历计算到期年份，未达到规则不会报告成功。任何写入后失败均保留备份路径。

独立 Python 多项式 CRC 与 struct 向量逐字节验证绑定和计时器；新增三项本地测试覆盖溢出、单位、未知字段、重复执行、无副作用拒绝和版本阈值。102 项本地测试及双平台 Clippy 通过；新增 Windows 日历转换测试不修改许可。ZeroCID/IID 后端 Windows CI 40117430777 已成功，SCID CI 40117804715 仍在运行。

当前运行层仍只支持现代布局（build 9600+），Vista/7/8 的 KMS4k 分支未接入；提取的 v4/v5 常量仅供后续迁移。激活产品选择、KMS Host Charge 及 GUI 路由仍待连接，本轮没有执行真实系统的 KMS4k 激活。


### KMS Host Charge 与激活后处理（进行中）

新增 `host_charge.rs`，移植现代 KMS Host 应用级计数记录：50 个客户端容量、25 个当前客户端、上游固定期限字段、40 字节请求计数结构，以及按 Windows GUID 字节序排列的 25 组时间戳/CMID。时间戳逐项减去 10 个 FILETIME 单位，保留 C# 的整数溢出语义。只替换首个目标计数记录，保留其他字段；缺失应用键时按上游创建存储内的键组，歧义键、空或重复 CMID 在修改前拒绝。

`host_runtime.rs` 以系统随机源生成 25 个不同的 v4 GUID，使用 SLC 验证 CSVLK 通道，通过备份事务暂停服务、写入并回读加密存储，再刷新许可。已连接到 SCID 和 ZeroCID 的许可状态验证之后，非 CSVLK 产品不修改计数。后处理失败明确说明此前激活状态已验证，不将部分完成描述为全部成功。KMS4k 的 GVLK 路径不执行 Host Charge。

独立 Python 向量使用各 GUID 字段均非零的固定样本，逐字节核对字节序、时间戳和六项 VariableBag。新增三项本地测试覆盖完整结构、未知字段保留、重复执行、时间戳溢出及无副作用拒绝；105 项本地测试及双平台 Clippy 通过。Windows 专用测试只验证随机 GUID 的版本、变体和唯一性，不修改许可。SCID/WinHTTP Windows CI 40117804715 已成功，KMS4k CI 40118152173 仍在运行。

当前仍为 build 9600+ 的内部后端，Vista/7/8 Host Charge 分支和激活产品选择仍待迁移，GUI 入口尚未切换。本轮未执行真实 KMS Host 修改，没有界面或已启用入口变化。


### Windows 产品选择与原生只读采集（进行中）

新增 `product_selection.rs` 和 `selection_runtime.rs`，迁移固定上游 `:wintsid:` 的 Windows-ActID 选择：按 EditionID 与 OEM/MAK/Retail、KMS Client、AVMA 或 KMS Host 通道筛选，经原生 WMI/SLC 读取许可策略，再结合两种 SKU 目录的非 Beta/Test 文件和 PKeyConfig 排除条件选择产品。KMS Host 优先按 KmsCountedIdList 数量降序；相同数量固定保留 WMI 顺序，避免依赖 PowerShell 哈希表的不稳定顺序。该采集过程只读，不停服务、不安装密钥。

选择配置解析与密钥生成解析分开：没有可生成密钥范围的配置仍保留描述和排除信息；只有 PKEY2009 范围应用 WAU 排除。保留上游 Beta/RC/Next/Test/Pre 回退顺序及两处字面比较语义（`CountrySpecific` 的标量比较、单引号 `$edition`），不悄悄改成子串或变量比较。无法解析策略、重复产品 ID、无效目录名及过大文件明确报错；许可文件支持 UTF-8 与带 BOM 的 UTF-16，PKeyConfig 不受网络响应的 1 MiB 限制。

110 项本地测试及双平台 Clippy 通过，新增通道排序、文件交集、语言锁定、Host 优先级、Beta 回退、WAU 排除、缺少密钥范围及 XML 策略作用域测试。Windows 专用测试覆盖文件匹配/编码并从真实系统执行只读选择；新测试仍待 Windows CI。前两轮 KMS4k CI 40118152173、Host Charge CI 40118416497 均已成功。

此选择器尚未接入 GUI 激活入口；Windows 版本/订阅与永久激活判断、ESU/Office 选择及完整安装激活编排仍待连接，不能视为完整迁移。本轮没有界面变化，沿用现有截图和测试包；未运行真实激活操作。


### 生成密钥到激活后端的执行链（进行中）

新增 `activation_flow.rs`，连接原生预检查、生成密钥准备、PKEY2005 联合存储安装/PKEY2009 SLC 安装、Office 无电话许可状态判断和 SCID/ZeroCID/KMS4k 后端。所选 SKU 与生成结果不一致、KMS4k 非 GVLK 通道在安装前拒绝；Office 特例按上游在密钥安装后检查。后端负责激活结果验证和 CSVLK 后处理，执行链保留错误详情及备份位置，区分准备/安装失败与“密钥已安装、后续失败”，不在失败后自动换方法或声称回滚。

同时移植 Windows 单项操作的 Auto 方法选择及 build 26100/UBR 4188 永久激活跳过边界。新增 `windows_edition.rs` 与可复现提取的 `tsforge-editions.tsv`，保持 SKU 对照表、旧名称候选顺序及“必须存在于已安装基础许可证”的限制；订阅处于激活状态且 SLC/注册表 SKU 不同时才选择基础 SKU，否则保持 SLC→WMI→注册表的回退顺序。未知 SKU 可接收 pkeyhelper 名称，但仍必须匹配已安装家族。

116 项本地测试、Linux 与 Windows GNU Clippy 通过。新增失败阶段截断测试，覆盖预检查、准备、安装、安装后检查和激活失败；另验证 Office 安装后跳过、SKU/通道不匹配、方法/UBR 边界、订阅与缺失来源以及完整提取表的旧名称选择。没有调用真实安装或激活 API。

原生执行链尚未由 GUI 调度：系统订阅状态/pkeyhelper 的原生读取、Windows 操作准备与 KMS 缓存清理、ESU/Office 选择仍待连接；现代分支以外的存储布局也未完成。产品选择只读 Windows CI 40119071973 仍在运行。此轮无界面变更，不更新截图和测试包。


### Windows 系统上下文与只读操作准备（进行中）

新增 `windows_context.rs`，通过原生 WMI、SLC、注册表和系统 DLL 收集构建/UBR、SKU 来源、订阅状态、已安装基础许可家族及永久激活状态。使用固定上游 `PrintSubscriptionStatus` 的三 DWORD 布局与 LocalAlloc/LocalFree 约定调用 ClipGetSubscriptionStatus；兼容 API 原地填写和替换输出指针，错误路径释放相应缓冲区，成功后先验证分配长度。订阅查询失败保留诊断并按上游采用普通 SKU 回退，不把两个 SKU 不同直接当作订阅已激活。

SKU 表未命中时，从 System32 加载 pkeyhelper.dll 调用 GetEditionNameFromId。返回名称在 DLL 存活期间复制：识别该模块映像内字符串或经过 LocalSize 验证的本地分配，不猜测未知指针的释放方式；限定可读范围、名称长度与字符，之后仍要求名称匹配已安装基础许可证。永久激活判断保留上游非 KMS、Windows 名称、状态 1、宽限期 0、已安装密钥及非附加许可条件。

只读准备连接了前两轮的 Edition/方法规则和产品选择器，显式返回评估版、已永久激活、旧版存储或现代待激活 SKU/方法，避免将评估版直接送入生成密钥安装。GUI 调度和 KMS 缓存清理仍待接入，此轮不执行安装或激活。

116 项本地测试及双平台 Clippy 通过；新增 Windows 专用测试覆盖订阅指针替换/错误/空结果、真实系统上下文、真实 pkeyhelper 名称查询和评估/永久/旧版准备分支，待本次 Windows CI 验证。产品选择迁移 CI 40119071973 已成功，执行链 CI 40119405069 仍在运行。界面及测试包未改变。


### Windows 原生 GUI 入口与 KMS 配置清理（v0.6.0-dev.4）

Windows 单项按钮现已接入系统上下文、产品选择、密钥安装和三种激活后端；build 9600+ 非评估版走 Rust，旧版/评估版明确转入兼容入口。原生错误不会触发第二次兼容激活。已有永久许可按上游 UBR 例外规则处理；跳过时不清理 KMS 配置。其他 TSforge 范围仍使用兼容入口。

新增 `kms_cleanup.rs` 迁移 `_taskclear-cache` 的 32/64 位全局值、应用子项、NetworkService 配置以及三个固定 IFEO 子项，并保留 Vista/7/8/8.1 的构建分支。KMS4k 在只读准备成功后、安装密钥之前执行；预先打开全部已有父项，缺失项跳过，权限错误报告，删除后逐项回读验证。删除失败明确报告已完成数量，不静默继续或声称配置已恢复。这些配置删除不在存储/产品注册表备份范围内。

117 项本地测试和双平台 Clippy 通过，新增清理目标构建/视图边界测试及 Windows 临时 HKCU 的嵌套删除、幂等与无关数据保留测试。执行链 Windows CI 40119405069 已成功；系统上下文 CI 40119757455 中真实上下文和订阅内存测试通过，pkeyhelper 测试因返回小写 `professional` 而失败；运行时本就忽略大小写，本轮将测试改为相同语义，并补充大小写回退测试，待新 CI。原生激活未进行真实系统验收。

GUI 范围标签、README、版本号同步至 dev.4；更新真实 Linux 预览截图并构建 Windows 本地测试包。此轮只启用 Windows 单项现代分支，不代表 ESU/Office、旧存储、修复及高级菜单已经完成迁移。


### ESU 产品筛选与现代执行后端（进行中）

新增 `esu.rs` 与可复现提取的 17 行 ESU 目录，保留许可证 GUID/版本交集、目录顺序、ThinPC 排除、Embedded POS/Standard 优先顺序、LTSC 排除名单和缺失许可证诊断。Windows 10 后加入版本严格要求 build 19045，并分别检查 ServerRdsh 5552、Core 系列/IoTEnterprise 6156、PPIPro 6388 的 UBR 门槛。按上游以本机已安装 GUID 筛选，不把目录注释中的系统名称误当成额外构建限制。

`esu_runtime.rs` 使用原生 SLC 枚举 Windows SKU，以系统包文件识别 Server/Embedded 标志，连接现代 PKEY 安装和 SCID/ZeroCID 执行链。明确拒绝 KMS4k，旧存储返回兼容准备结果；多产品逐项执行并保留每项错误和已完成数量，不将部分成功报告成全部成功。全部成功且包含 Windows 10 Year3/Year6 时，调用系统自带 ClipESUConsumer/ClipESU 后处理（文件不存在则跳过），使用受控参数、无 shell、60 秒超时与退出码检查；未移植这些闭源系统组件本身。

121 项本地测试及双平台 Clippy 通过，新增 ESU UBR 边界、目录交集/顺序、LTSC/Embedded 特例以及批量失败继续与后处理条件测试。Windows 专用测试只读取实际系统包和 SLC 许可证，不执行激活或后处理程序。当前 GUI ESU 按钮仍为兼容入口：Auto 模式的联网/离线判断和公共 SPP 任务重评估尚待接入后再启用。没有界面或测试包变化；本地 dev.4 仍对应上一轮已启用的 Windows 单项流程。


### 联网预检查、SPP 重评估与 ESU GUI 入口（v0.6.0-dev.5）

新增 `connectivity.rs`：对应上游从 ping 标题提取解析地址的语义，使用 Rust DNS 解析四个固定域名，不启动 ping/PowerShell；未解析到地址时查询 Network List Manager。DNS 工作线程等待上限为 30 秒，系统解析调用可能在后台稍后结束，不声称能够取消系统 DNS 查询。预检查不是激活服务可达性保证。只有 StaticCID 检查联网；Auto 离线回退 KMS4k，ESU 随即拒绝不支持的 KMS4k，显式 StaticCID 离线直接报错，均在安装密钥前停止。

新增 `reevaluation.rs`：预先从系统 sppc.dll 解析 SLpTriggerServiceWorker，清除 NetworkService 的 PersistedSystemState 下 State/SuppressRulesEngine 两个固定值、回读验证，暂停 SPP 后提交 reeval 请求，并复用服务恢复协调器。请求是异步的，不用它宣称激活成功；无论之前的激活结果成功或失败，都保留原结果/备份信息，重评估错误另行合并。此处清理不在许可存储备份范围内。

ESU 按钮现已接入现代原生后端，旧存储仍明确转兼容；Windows/ESU 的原生失败不会自动再运行兼容激活。更新版本、README 和真实预览截图，构建 dev.5 Windows 本地测试包。新增联网决策、错误合并测试，以及 Windows 专用的只读 NLM 查询/系统导出加载测试；不执行真实重评估或激活。123 项本地测试及双平台 Clippy 通过。Windows 入口/清理 CI 40120110681 已成功，ESU 发现 CI 40120508435 仍在运行，新联网/SPP 调用还待本次 Windows CI 验证。


### Windows KMS Host 许可准备与执行后端（进行中）

新增 `host_licenses.rs`：build 10586+ 从当前版本 SKU 目录读取 CSVLK 文件，先完整读取/解码并解析校验所有文件，再允许调用 InstallLicense。保持签名 XML 原文，不重写命名空间或空白；支持 UTF-8/UTF-16，拒绝无效目录、DTD、损坏 XML、超出 256 文件或合计 64 MiB 的输入。按文件名排序，仅处理当前版本目录的 CSVLK XRM 文件，较旧构建不额外导入。

新增 `windows_host.rs`，连接现代系统上下文、Auto 联网判断、CSVLK 许可导入、KMS Host 产品选择和既有原生安装/SCID/ZeroCID/Host Charge 后端。KMS4k 明确拒绝；旧存储保留兼容准备结果。生成密钥准备增加可选的通道约束，Host 必须为 Volume:CSVLK 才能安装，Windows/ESU 路径不额外限制。导入失败保留已导入数量，后续失败说明许可准备已发生，不声称撤销已安装的 XRM 许可。最终复用 SPP 重评估与错误合并。

126 项本地测试和双平台 Clippy 通过，新增当前版本文件选择、顺序/编码保留、整组损坏拒绝、导入失败阶段测试。Windows 专用测试只读取本机 CSVLK 文件，不调用导入、激活或 Host Charge。ESU 后端 CI 40120508435 已成功；dev.5 联网/SPP CI 40120868061 仍在运行。Host GUI 入口尚未切换，本轮无界面或测试包变化。


### Windows KMS Host GUI 接入（v0.6.0-dev.6）

Windows KMS Host 按钮接到现代原生后端，旧存储明确转兼容，原生错误不触发兼容重试。确认窗口说明 CSVLK 主机许可不同于客户端、导入/安装不自动撤销、服务持续运行及系统版本名称可能变化。Windows/ESU/Host 的混合范围标签同步，Office KMS Host 仍为兼容。

126 项本地测试及双平台 Clippy 通过，显式入口分派测试现覆盖 `/Z-WinHost`。README 与实际 Linux 预览截图更新，构建 dev.6 Windows 本地测试包。新增 GUI 路由不代表实际主机激活已经验收；真实许可证导入、主机激活和计数仍需实机验证。dev.5 联网/SPP CI 40120868061 已成功，包含只读 NLM 查询和系统 SPP 导出加载；Host 后端 CI 40121163362 仍在运行。


### Office KMS Host / APPX 目录与 GUI 接入（v0.6.0-dev.7）

从固定上游提取 6 项 Office Host 和 4 项 APPX 目录，保留顺序并只选择本机已有 GUID。Office Host 分别通过原生 WMI 查询两个 Office Application ID，与上游 dk_actids 的 SoftwareLicensingProduct 查询一致；未安装的应用自然返回空列表。APPX 保留 build 9200–9600 限制，其他系统直接跳过，旧存储明确兼容，现代存储走原生安装/SCID/ZeroCID。两种范围均拒绝 KMS4k；Office Host 要求生成配置通道为 Volume:CSVLK。

新增 `auxiliary.rs`/`auxiliary_runtime.rs`，串联目录筛选、Auto 联网判断、逐产品安装/激活/结果验证与公共 SPP 重评估。部分失败继续处理后续产品并保留身份、数量与错误；没有许可证时不下载安装包。两个 GUI 按钮切换为明确的 Rust/兼容范围，Office Host 确认窗口说明它不是 Office 客户端激活及服务持续运行影响。

129 项本地测试及双平台 Clippy 通过；新增系统构建边界、目录交集/顺序、部分失败继续测试，Windows 专用测试只查询实际安装的许可证，不运行激活。README、截图和本地 Windows 包同步更新至 dev.7。Windows KMS Host 后端 CI 40121163362 与 GUI CI 40121347942 仍在运行；新入口没有真实激活验收。Office 客户端、Project/Visio、组合、旧存储及修复/高级工具仍有待迁移。


### TSforge Office 产品转换与激活 ID 选择（进行中）

新增 `office_selection.rs` 与独立提取的 `tsforge-office-conversion.tsv`，对应上游 ts_process/tsksdata/offtsid，不复用 Online KMS 的不同产品映射。保留 Office 15/16 的 O365 差异、非 MSI ARM→MondoRetail、KMS4k Retail→Volume/未知产品→MondoVolume、免费 Retail 保留、MSI Retail 跳过、Project/Visio 专用范围及 O365/Mondo 覆盖时的重复产品跳过规则。

Office 激活 ID 按 OEM:NONSLP→Volume:MAK→Retail 或单独 Volume:GVLK 的顺序选择，忽略大小写，排除 demo/MSDN/PIN；有非 preview/C2R 配置时优先正式配置，否则保留预览回退。PKeyConfig 选择元数据增加可选 ProductKeyType，不影响不依赖该字段的 Windows 选择；仍保留没有密钥范围的配置，实际可安装性由后续生成密钥阶段检查。

135 项本地测试及双平台 Clippy 通过，新增完整转换别名覆盖、O365/ARM/MSI/免费 Retail、Project/Visio、通道优先级与 XML 元数据到选择结果的测试。Windows KMS Host 后端 CI 40121163362 已成功，GUI CI 40121347942 与辅助入口 CI 40121694619 仍在运行。

Office GUI 尚未切换；C2R/MSI/UWP 产品发现、许可导入和配置清理仍需连接。已确认 KMS4k 模式下的免费 Retail 产品需要在安装后先检查已许可状态，不能直接套用通用入口的 GVLK 安装前限制，后续会在 Office 编排中处理。本轮无界面或已启用入口变化，不更新截图和测试包。


### Office 许可证准备与免费 Retail 顺序修正（进行中）

新增 `office_preparation.rs` 和 `office_runtime.rs`，复用原生 C2R/MSI 安装发现，读取对应 Office PKeyConfig，将产品转换规则连接到缺失许可文件选择、OSPPReady、ProductReleaseIds 和 Server Retail 的 SharedComputerLicensing 配置。先读取所有可准备的产品，再逐项修改；同一安装内重复 Mondo ID 去重。缺失 MSI 许可提示修复安装，产品失败保留错误并继续其他产品；导入后通过 WMI 验证目标 Activation ID，未验证的产品不进入后续密钥安装。

共享 Office 许可加载支持动态产品名，保留 client-issuance → 产品文件 → pkeyconfig 顺序和 UTF-16 原文，先完整解析所有 XML，拒绝 DTD、损坏 XML、超过 256 文件或合计 64 MiB 的导入组。导入中途失败报告已导入数量，不声称已撤销配置或许可导入；这些操作不属于 SPP 存储备份。

修正共享激活执行链的 KMS4k 免费 Office Retail 特例：非 GVLK 产品须先验证 Office 身份、非 KMS 描述及无电话许可，再允许安装；安装后必须确认已许可才能成功返回。未许可时明确报告密钥已安装并停止，不调用 KMS4k；其他非 GVLK 产品仍在安装前拒绝。

141 项本地测试与 Linux/Windows 双目标 Clippy 通过。新增 Mondo 去重、MSI 缺失许可、2024 Preview 文件、动态产品 UTF-16、损坏/DTD/数量限制和导入失败阶段测试；Windows 专用测试只读实际 Office 安装与许可 ID，不执行配置、导入或激活。前两轮 Office Host/APPX CI 40121694619、产品选择 CI 40121947342 均已成功，本轮 Windows CI 待推送验证。

Office GUI 尚未切换：UWP 发现、ClickToRun 服务检查、KMS 横幅配置、最终密钥/订阅缓存清理及激活调度仍需连接，未宣称完整客户端流程或实机验收完成。界面和 dev.7 测试包未改变，未重新生成相同截图。


### Office UWP 原生安装发现（进行中）

新增 `office_uwp.rs`，使用 WinRT PackageManager 枚举当前用户的 Microsoft.Office.Desktop，读取 InstalledLocation 与依赖包完整名称，按 Integration/Integrator.exe 判断桌面载荷，不启动 PowerShell。普通 Office 应用归并为 O365HomePremRetail；Project/Visio 分别根据本机许可文件按 2024 → 2021 → 2019 → 无年份选择产品，保持上游依赖匹配语义。

Office 准备适配器新增 UWP 分支，使用包目录中的 Office16/pkeyconfig-office.xrm-ms 和 Licenses16，连接现有转换、许可导入及 ID 验证；没有 C2R 配置注册表的 UWP 不写 OSPPReady。顺序为 UWP → C2R → MSI，build 10240 以下不调用包 API。

WinRT 使用空 SID 查询当前用户，逐项检查迭代 HRESULT；每次成功初始化（包括 S_FALSE）均匹配清理，并保留 WMI 已有的线程模型。接口语义参考 [FindPackagesForUser](https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.packagemanager.findpackagesforuser) 和 [RoInitialize](https://learn.microsoft.com/windows/win32/api/roapi/nf-roapi-roinitialize)。增加 Windows SDK crate 的 ApplicationModel、Management_Deployment、Storage_Search 与 WinRT 特性，无新增 crate 版本。

143 项本地测试和双目标 Clippy 通过；新增依赖归并、大小写、独立 Project/Visio 版本优先级、无依赖/预览文件回退测试。Windows 专用测试只枚举实际包，并在 WinRT 清理后检查已有 WMI 连接仍可查询；实际包 API 执行待本次 Windows CI。上一轮 Office 准备 CI 40122613303 仍在运行。Office GUI、截图和 dev.7 测试包入口未改变；服务检查、最终清理、激活调度仍在迁移。


### Office 服务检查、清理与激活编排后端（进行中）

C2R 在许可准备前直接查询 SCM：Office 16 要求 ClickToRunSvc，Office 15 允许 ClickToRunSvc 或 OfficeSvc；只读权限，服务缺失与权限/API 失败分开报告。新增 `office_finalization.rs`，连接已有用户许可缓存清理，仅在无准备错误、无 MSI 且有已准备 C2R/UWP 产品时卸载冲突 Office 密钥，Project/Visio 范围保留其他产品家族；卸载后重新查询验证。KMS4k 的 Office 16 C2R 准备成功后重建两个注册表视图中的 Office 专用 KMS 项，并回读验证。

新增 `license_reinstall.rs`，对应 Insider tokens.dat 检测与 ReinstallLicenses：从系统 oem、licensing、spp/tokens 三个目录递归准备 XRM 文件，完整读取/解析后再导入，保留 XML 原文，限制深度、数量及总大小，拒绝重解析路径。使用既有 SPP 服务协调器执行导入，错误记录已导入数量；不会自动重跑整个导入或宣称已恢复先前许可。

新增 `office_client.rs`，串起 Auto 方法/联网判定、现代存储预检、C2R/MSI/UWP 准备、KMS 配置清理、Office 最终清理、生成密钥和 SCID/ZeroCID/KMS4k 执行链，最后触发 SPP 重评估。无目标不清理；清理失败不继续安装密钥；产品激活失败继续其他产品并保留准备错误，最终只在全部成功时报告成功。旧存储仍明确返回兼容准备结果，原生失败不回退脚本。

147 项本地测试与双目标 Clippy 通过。新增固定目录递归/损坏 XML、导入失败数量、Project/Visio 保留规则、Office Auto 边界和清理失败停止测试；Windows 专用测试仅查询服务和操作临时 HKCU 横幅配置，不清理真实 Office、不重新导入许可或执行激活。许可准备 CI 40122613303、UWP CI 40122867640 仍在运行。GUI 尚未切换，实际激活未验收；截图及 dev.7 测试包没有变化。


### Office / Project / Visio GUI 接入（v0.6.0-dev.8）

两个单项按钮已接入 Office 原生编排：build 9600+ 使用 Rust，旧存储明确转兼容；原生错误不重跑脚本。界面范围标签、关于页及确认说明同步更新，说明产品转换、用户缓存、冲突密钥和部分修改不自动撤销。组合入口仍兼容，不将单项迁移等同于整个 TSforge 完成。

147 项本地测试与双目标 Clippy 通过，入口分派测试新增两个单项范围。更新 README、实际 Linux 预览截图，并构建 Windows dev.8 本地测试包。Office 许可准备 CI 40122613303 已成功；UWP CI 40122867640 的实际包查询测试及 Clippy 已通过，发布构建尚在运行；清理/编排 CI 40123221959 仍在运行。真实 Office 激活和清理仍需实机验收。


### Windows + ESU + Office 组合入口（v0.6.0-dev.9）

新增 `combined.rs`，统一方法/联网判断、KMS 配置清理及 SPP 重评估，依次调用 Windows、ESU、Office 原生后端。组合默认遵循上游 StaticCID（build 26100+）/ZeroCID 规则，而非 Windows 单项的 KMS4k 默认；离线 Auto 回退 KMS4k 后明确跳过 ESU。单项后端增加组合调用路径，使用已选方法，不重复联网判断、全局 KMS 清理和重评估。

全部请求的旧存储/评估版兼容决策在修改前完成；执行中某个范围返回新的兼容请求，视为带说明的失败，不在部分修改后自动运行脚本。各范围出错仍继续其他范围，结果保留成功、失败与跳过原因；已永久激活 Windows 的提示区分组合共享配置清理。原生错误不会使引擎再次激活。

GUI 组合按钮、确认说明、README、真实预览截图和 Windows 本地包更新至 dev.9。150 项本地测试与双目标 Clippy 通过，新增方法一致性、KMS4k 跳过 ESU、错误继续、意外兼容返回禁止回退、共享清理失败停止，以及入口分派覆盖。UWP CI 40122867640 已成功；清理后端 CI 40123221959 与 Office GUI CI 40123486597 仍在运行。组合实际激活尚未进行实机验收；旧存储、评估版、修复与高级工具仍待迁移，目标未完成。


### Windows 评估版目录与原生执行后端（进行中）

从固定上游 ts_wineval 提取 29 行评估 Activation ID/密钥/Edition/版本目录及 NoAct 标记，加入可复现提取脚本与版权说明。`evaluation.rs` 按版本名和本机安装 ID 交集、目录顺序选择，不把普通非评估版送入评估重置。

`evaluation_runtime.rs` 连接现代存储预检、原生 WMI 产品发现、联网检查、已有三阶段备份重置、评估密钥安装及目标产品的 Activate/RefreshLicenseStatus。安装后验证 Activation ID 和密钥末五位，随后读取该基础许可的 LicenseStatus 与 GracePeriodRemaining，避免误把另一个产品的期限当成成功。90/180 天按上游向上取整；另外要求已许可状态和成功的激活 HRESULT，不能仅凭计时器被重置就宣称激活成功。NoAct 产品保留上游已知故障提示。

153 项本地测试和双目标 Clippy 通过，覆盖目录完整性/去重/本机 ID 交集、版本顺序、90/180 天边界、整数溢出、许可状态，以及每个失败阶段停止并保留备份错误。Windows 专用测试仅读取实际评估许可证，不重置计时器、不安装密钥或请求激活。Office 清理后端 CI 40123221959 与 UWP CI 40122867640 已成功；Office GUI CI 40123486597 与组合 CI 40123891475 仍在运行。

此轮尚未切换 Windows 单项/组合中的评估版分支；当前 GUI、截图和 dev.9 测试包行为保持一致。后续将接入评估版确认说明和原生路由，旧存储仍须继续迁移。


### 评估版 Windows 单项与组合 GUI 接入（v0.6.0-dev.10）

现代 Windows 评估版直接调用 `evaluation_runtime`，不再启动兼容脚本。计划选择明确区分 build 9200 的旧存储与 build 9600+ 评估版，先判断评估分支，避免误用永久激活跳过或普通生成密钥流程。组合入口仅在旧存储时整体转兼容，评估版作为 Windows 范围独立执行联网激活，其他范围沿用组合方法；原生错误不会触发脚本重试。

确认窗口明确说明评估计时器、备份、联网激活和 90/180 天期限，SCID/ZCID/KMS4k 不能替代评估分支的联网请求。README、范围说明、截图和 Windows 本地包同步至 dev.10。

153 项本地测试及双目标 Clippy 通过；扩展 Windows 专用计划测试覆盖评估版在 9200/9600 边界和优先于永久许可跳过的行为。Office GUI CI 40123486597、清理后端 CI 40123221959 已成功；组合 CI 40123891475 和评估后端 CI 40124164663 仍在运行。实际计时器重置/评估激活仍未实机验收；旧存储和修复/高级工具继续迁移。


### 旧版加密重置与双文件镜像转换（进行中）

将 reset 的认证解密、格式解析、字段修改、重序列化与重新加密扩展为版本参数化实现，现代入口保留原来的明确 Modern 包装。版本识别对应固定上游：6000–6003 Vista、7600–7602 Win7、9200 Win8、9600+ Modern；中间未知构建拒绝。Win8/WinBlue 使用现代容器，但加密信封版本不同；9600 自动识别为 Modern，不误选 WinBlue。

新增 Vista/7 的双文件转换：只读取主文件作为修改来源，不将损坏主文件静默换成副本；输出将主文件的结果镜像到两个目标。即使记录修改数为零，副本仍可能需要同步，因此后续运行时不能仅凭记录计数省略写入。两份原始字节由同一事务分别备份，不能以主文件覆盖副本备份。

156 项本地测试与双目标 Clippy 通过。覆盖构建边界、四种旧信封/生产与测试密钥的重置、布局保持、损坏主文件拒绝、无记录变更时的镜像同步，以及临时双文件事务中备份和最终字节的一致性。组合入口 CI 40123891475 已成功；评估后端 CI 40124164663 与评估 GUI CI 40124365113 仍在运行。

旧版系统服务/文件定位、缺失副本创建及恢复校验仍待接入；当前运行时预检继续限制现代写入，不宣称旧版激活已经可用。此次没有 GUI、截图或 dev.10 测试包入口变化。


### 存储文件定位与许可服务布局（进行中）

新增 `storage_layout.rs`，根据已有版本识别区分 Vista 的 slsvc、Win7 及之后的 sppsvc；Vista/7 明确定位固定 -0 主文件及 -1 镜像文件，不依赖目录枚举顺序。缺失主文件报错，缺失副本作为独立状态返回，定位阶段不创建文件。旧版令牌分别位于 NetworkService 的 SoftwareLicensing / SoftwareProtectionPlatform 目录。

现代及 Win8 文件定位保留 TokenStore 优先、spp/store → spp/store/2.0 → spp/store_test → spp/store_test/2.0 的后备顺序，分别解析 data.dat 和 tokens.dat。现有运行时 store_path 已复用该实现；只允许两个固定文件名，错误路径、非普通文件和重解析路径明确报错，不把权限/API 失败当成文件不存在。

161 项 Linux 测试及双目标 Clippy 通过，覆盖配置优先级/所有后备目录、主副文件顺序、缺失副本只读状态、不同系统的令牌目录、非普通文件及符号链接拒绝；Windows 专用测试只读实际 data.dat 定位。评估后端 CI 40124164663 与 GUI CI 40124365113 已成功，旧版加密转换 CI 40124731440 仍在运行。

旧版写入/恢复尚未启用，缺失副本的事务创建和恢复语义仍待连接；GUI、截图与 dev.10 测试包入口未变。此实现不改变 GUI 当前支持的最低 Windows 版本。

### 旧版副本创建与恢复事务（进行中）

新增 `paired_store.rs`，在主文件事务中加入镜像参与者。备份分别保存主文件和副本原始内容，并记录副本原本存在或不存在；提交时使用主文件转换结果写入两者。缺失副本通过排他创建生成，准备期间被其他进程创建时拒绝覆盖。Windows 使用持有的独占句柄执行写入与删除，恢复失败时取消待删除状态并还原原始内容。

恢复先校验固定目标、清单版本和副本 SHA-256，再生成当前状态的撤销备份。原始副本不存在时，恢复将移除本次创建的副本；再次恢复撤销备份可还原两份文件。副本准备失败不修改主文件，提交失败会尝试同时回滚两者，错误保留备份位置。

167 项 Linux 测试及双目标 Clippy 通过。新增测试覆盖副本缺失/存在、恢复与撤销恢复、创建后失败、删除后失败、竞争创建、目标篡改和备份损坏。旧版加密转换 CI 40124731440、存储定位 CI 40124957118 已成功。本轮双文件事务的 Windows 实际句柄测试交由推送后的 CI 验证；没有执行真实许可存储修改。

当前仍是未接入运行时的后端模块，旧版重置、服务控制与恢复分派仍需继续连接。GUI 和 dev.10 测试包入口未变，因此本轮不更新截图或重新打包。

### 版本化重置与恢复运行时接入（v0.6.0-dev.11）

将重置/恢复预检与激活预检分离：重置按实际构建号选择 Vista/Win7 主副文件或 Win8/现代 data.dat，使用对应加密版本与 slsvc/sppsvc；激活后端继续要求现代布局，不误将旧版存储送入现代密钥安装流程。刷新调用仍按固定上游使用 SLConsumeWindowsRight，修改前检查导出是否可用。Vista 按上游跳过标记与密钥锁阶段，先刷新再处理 rearm/计时器，阶段数按实际流程报告。

双文件重置接入 paired_store 事务，即使记录数为零也提交镜像，确保缺失或不同的副本被同步。恢复先识别 paired-store.json，再区分普通文件与产品注册表联合备份；版本/文件布局不符时拒绝，旧版不接受现代产品注册表联合备份。主文件备份按实际加密版本认证、解析，副本按其独立原始字节和存在状态恢复。

169 项 Linux 测试及双目标 Clippy 通过，新增加密存储集成测试覆盖 Vista/Win7 的零记录修改仍创建副本、恢复后副本重新缺失，以及错误加密版本在任何写入前拒绝。双文件句柄事务 Windows CI 40125813195 仍在运行。未修改真实系统许可存储，旧版后端未完成实机验收；当前 GUI/工具链最低 Windows 要求不变，不能将后端格式支持等同于 GUI 能在 Vista/7/8 上运行。

更新 README、确认说明与 dev.11 截图/本地 Windows 包。旧版激活、修复及高级工具仍须继续迁移，整体目标尚未完成。

### Win7 电话许可存储修改（进行中）

扩展 `phone.rs`，按物理容器格式处理 Win7 扁平键/值记录和现代分组记录。Win7 必须同时匹配 SPPSVC 产品路径与密钥 ID；同名但不同产品的记录保留，目标密钥重复则报错。IID 参数按上游写入 SppPkeyShortAuthenticator，并使用已有 PKEY2005/PKEY2009 的 Win7 电话数据编码；Unique ID 删除保留其他记录及未知字段。

Win7 ZeroCID 缓存使用 UTF-16 终止的安装 ID 计算 SHA-256，不追加现代格式的确认 ID；短认证数据、HWID 与哈希按固定长度字段封装，缓存条目带原产品路径。现代流程继续使用独立字段与安装 ID/确认 ID 哈希输入。

172 项 Linux 测试及双目标 Clippy 通过。Python 独立向量脚本新增 phone-win7.json，核对两个缓存的精确字节；测试覆盖两个密钥算法、字段保留、幂等、容器回读、跨产品隔离和重复密钥拒绝。Windows 双文件事务 CI 40125813195 与 dev.11 CI 40126071956 仍在运行。

此轮只迁移存储修改后端；Vista 的 PKeyBasicInfo 提取、旧版先提交确认 ID 再修改存储的顺序，以及密钥安装/激活分派仍需连接。旧版激活入口继续兼容路径，GUI/截图和 dev.11 测试包未变。

### Vista 电话缓存格式（进行中）

扩展 `phone.rs` 的 ZeroCID 存储修改至 Vista：使用 Vista variable-bag CRC/保留字段格式，从 PKeyBasicInfo 的 0x120 与 0x1a0 定长 UTF-16 区域读取 Unique ID 和 Extended PID；校验组号和 Base64 后合成 8 字节短认证数据。Vista 按上游只取安装 ID 哈希的前 16 字节，缓存名称采用 6.0 与 Activation ID，不误用 Win7/现代的密钥 ID；Vista 容器不存储产品路径字段。

新增 Python 独立 phone-vista.json 向量，精确核对基本数据、认证结果和两种缓存字节。175 项 Linux 测试及双目标 Clippy 通过，覆盖保留字段/未知记录、幂等与容器回读，以及截断、非法 UTF-16、零/溢出组号、损坏/过短 Base64、CRC 错误和重复密钥拒绝。Vista 的 IID 参数和 Unique ID 修改按上游明确不支持，提前返回错误。

Windows 双文件事务 CI 40125813195、dev.11 CI 40126071956 与 Win7 电话记录 CI 40126263402 仍在运行。此轮没有真实激活或许可存储写入；旧版先提交确认 ID 再修改存储的执行顺序、原生密钥安装和入口分派仍待连接。GUI、截图与 dev.11 测试包未变。

### 电话确认 ID 顺序与版本化存储执行（进行中）

新增 `phone_flow.rs`，按固定上游顺序编排：Vista/Win7 先提交确认 ID，再写存储；Win8/WinBlue/Modern 先写存储，再提交。两者均在最后刷新、发出状态变化通知并验证所选 SKU 的已许可状态。任一步失败停止后续步骤，不重试、不自动回退脚本；错误明确区分是否已提交确认 ID、是否已修改存储，并保留已取得的备份路径。SLC 提交不声称可由文件事务回滚。

`phone_runtime.rs` 已使用该编排及版本化预检、认证解密/加密、许可服务选择和双文件事务。IID/Unique ID 修改也复用版本化写入。旧版 CSVLK 的 KMS Host 计数后处理尚未迁移，因此在确认 ID 提交和存储修改之前明确拒绝；现代 Host 分支继续原有后处理，并在失败消息保留电话存储备份。

176 项 Linux 测试及双目标 Clippy 通过，编排测试逐一覆盖五种版本的成功顺序及每个失败阶段，验证停止执行、部分提交说明与备份保留。Windows 双文件事务 CI 40125813195 已成功；dev.11、Win7 和 Vista 电话记录 CI 40126071956/40126263402/40126423074 仍在运行。

低层电话执行后端已连接旧格式，但 Windows/Office 产品入口仍通过原有旧版兼容分派；旧版密钥准备、KMS Host 计数及激活入口尚待迁移。未执行真实确认 ID 提交或系统存储修改，本轮 GUI、截图及 dev.11 本地包未更新。

### 旧版 KMS Host 计数后处理（进行中）

将 `host_charge.rs` 扩展为显式版本参数：Vista 使用 44 字节原始头部，记录 50/43200/32、两个 25 计数字节，并按 GUID → FILETIME 顺序写入客户端；固定计数记录名为 C8F6FFF1-79CE-404C-B150-F97991273DF1。Win7 使用带 SPPSVC 应用路径的扁平记录；Win8/WinBlue 使用现代容器，但标志为 0，仅 Modern 标志为 0x400。非 Vista 的 variable-bag 内容保留现有独立向量。

Host 原生后端已复用版本化预检、服务、加密信封及主副文件事务，写入失败保留事务错误，刷新失败包含计数备份路径。电话执行后端移除此前针对旧版 CSVLK 后处理缺失的拒绝；仍只在所选 SKU 验证已许可后执行 Host 后处理，非 CSVLK 不写计数。

178 项 Linux 测试及双目标 Clippy 通过，新增 Vista Python 独立向量，逐一验证五种版本的记录标志、名称/路径、幂等、生产/测试加密回读、跨产品记录保留、重复计数拒绝和格式不匹配拒绝。dev.11 Windows CI 40126071956 与双文件事务 CI 40125813195 已成功；电话后端相关 CI 40126263402/40126423074/40126567464 仍在运行。

本轮未执行真实计数修改或激活。旧版产品入口仍走兼容分派，密钥准备/安装及其他旧版激活方法继续迁移；GUI、截图与 dev.11 本地包未更新。
