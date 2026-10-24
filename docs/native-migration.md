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
| TSforge | `TSforgeActivation`、`tsforge` | 嵌入约 5,000 行 C#；SPP API、密钥配置、物理许可存储、密码学、SCID/ZCID/KMS4k | 重置已接入 Rust；SCID/ZCID/KMS4k 等激活仍为兼容后端 |
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
- TSforge 激活方法、Office 的部分修复分支和高级菜单仍依赖 Windows PowerShell；界面按钮标注为“兼容”。**当前不是完整的纯 Rust MAS。**

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
