<p align="center">
  <img src="assets/app.png" alt="MAS Rust 图标" width="96" />
</p>

# MAS Rust

使用 **Rust + egui** 构建的 Windows / Office 激活与许可证管理桌面前端，内嵌固定版本的 [Microsoft Activation Scripts（MAS）](https://github.com/massgravel/Microsoft-Activation-Scripts)，提供中文界面和独立应用图标。

[![Windows build](https://github.com/undownding/MAS-rust/actions/workflows/build.yml/badge.svg)](https://github.com/undownding/MAS-rust/actions/workflows/build.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

[功能](#功能) · [界面预览](#界面预览) · [获取与使用](#获取与使用) · [构建与运行](#构建与运行) · [验证范围](#验证范围)

**v0.6.0-dev.2：TSforge 重置与备份恢复入口接入 Rust；Ohook 安装、卸载及 x86/x64 DLL 均使用 Rust。**
原生路径直接调用 COM/WMI、Windows 服务与许可 API，不启动 PowerShell；票据签名由 Rust 实现，导入使用 Windows 自带的 `clipup.exe`。

TSforge 的重置入口已接入 Rust 存储解析、加密、备份回滚和服务控制，当前支持 build 9600 及更新版本，尚待 Windows 实机验证。TSforge 激活方法、Office 的部分修复分支及高级工具仍使用固定版本的上游兼容引擎，界面明确标注“Rust / 兼容”。PKEY2005/PKEY2009 编码及绑定数据已加入独立向量测试，尚未接入激活。**这还不是完整的纯 Rust MAS**，各模块的实现范围与剩余工作见 [核心分析与迁移记录](docs/native-migration.md)。

## 界面预览

![MAS Rust 激活页实际运行截图](screenshots/mas-rust-preview.png)

截图来自 Linux 下的实际运行画面。Linux 为预览模式，因此执行按钮置灰；激活和许可证操作需要在 Windows 上运行。图中 TSforge 已展开，重置按钮标注 Rust；Online KMS 和高级选项处于折叠状态。内容区随窗口宽度展开，滚动条固定在右侧。

![MAS Rust 许可证管理页](screenshots/mas-rust-license.png)

### 恢复 TSforge 备份

在“激活 → TSforge → 恢复本机 TSforge 备份”中粘贴日志里的备份目录（包含 `manifest.json`），点击“恢复备份 · Rust”并核对确认信息。只使用本机生成的备份。

重置按阶段生成备份；若要恢复到本轮重置前的物理存储，应选择本轮**第一个阶段**的备份，而不是最后一个。恢复会校验目标路径、SHA-256、加密完整性及存储格式，先保存当前文件，再写入所选备份。它只恢复 `data.dat`，不回退注册表、tokens.dat 或其他许可组件；可能覆盖备份后发生的许可变化。原生重置和恢复仍待 Windows 实机验收。

## 功能

| 功能 | 入口 |
| --- | --- |
| HWID | 原生 Rust 主流程，支持禁止自动更改版本 |
| Ohook / 卸载 | Rust 许可准备、DLL 构建/部署、用户配置和卸载恢复 |
| TSforge Windows / Office / ESU / Project / Visio / KMS Host / APPX | 兼容引擎，支持默认、SCID、ZCID、KMS4k 方法 |
| TSforge 重置 / 备份恢复 | Rust：标记、rearm 计数、宽限/评估计时器、密钥变更锁；分阶段备份与校验恢复 |
| Online KMS Windows / Office / Project / Visio / 卸载 | Rust 主流程；Office 支持 C2R 转换及 MSI 批量许可；支持自定义主机、端口与原生续期 |
| KMS38 | 原生 Rust 主流程；历史菜单仍为兼容引擎 |
| 激活状态、Windows / Office 版本切换、排障、OEM 提取、其他高级选项 | 工具箱 → 完整 MAS 菜单 |
| 密钥安装 / 卸载、联机激活、自定义 KMS 主机与端口 | 许可证页，Rust 直接调用 COM/WMI |

上游 MAS 当前版本已移除 KMS38。这里保留移除前的固定版本；上游注明 **build 26100.7019 起 CLiP KMS 许可机制被废弃**。历史引擎不能恢复新系统已删除的能力，不能承诺所有 Windows 版本均可使用 KMS38。
参考：[移除提交](https://github.com/massgravel/Microsoft-Activation-Scripts/commit/470d3b900e6aebfba224fde3ea7957308dd61230)。

## 获取与使用

### 获取 Windows 程序

前往 [GitHub Actions](https://github.com/undownding/MAS-rust/actions/workflows/build.yml)，选择成功的 `Windows build` 运行，在 Artifacts 中下载 `mas-rust-windows-x64`，解压后运行 `mas-rust.exe`。下载 Actions 构建产物通常需要登录 GitHub；也可以按下方说明自行编译。

2026-10-24，用户反馈 v0.2.0 测试工作正常。尚未记录具体 Windows 构建号和所测功能组合，这一反馈不代表全部激活方式及 Office 版本均已验证。

### 操作步骤

1. 运行 EXE 并接受 Windows 管理员提示。
2. 在“激活”选择方法和参数，确认后在日志页查看执行进度与错误。
3. 工具箱中的完整菜单包含上游的版本切换、排障和 OEM 等交互流程。
4. 非交互任务完成后到“许可证”查询状态；完整交互菜单仍在独立窗口运行。
5. “日志”页可复制进度与任务结果。兼容引擎非交互日志保存在 `%LOCALAPPDATA%\MAS-Rust\logs`；交互菜单输出在独立窗口显示。

### Ohook 原生安装与卸载

DLL 基于固定版本的 [ohook-rs](https://github.com/massgravel/ohook-rs/tree/044af0e99d40a449c855d989feb7ad8ff042783f)（MIT）构建，构建阶段逐项校验 PE 架构与转发导出；不从 MAS 脚本提取 DLL，也不随机修改 DLL 哈希。安装后需重新打开 Office 验证效果，WMI 状态不反映进程内 hook 效果。

“卸载 Ohook”直接清除 Office 目录中的 hook 文件、恢复保存的原始 OSPPC，并清理用户及默认配置中的 Resiliency 和 Office 横幅设置，不运行脚本。不卸载 Office 产品密钥；文件被占用或出现冲突原 DLL 时会报错，关闭 Office 后可重试。安装流程覆盖 C2R、MSI 和 Office 2010 OSPP；DLL 替换失败会尝试恢复原文件，恢复失败时保留备份并显示路径。

### Online KMS 原生流程

- Windows 根据 SKU 和系统已有 Activation ID 选择 GVLK；已有永久许可或 KMS38 时保留现状。
- Office / Project / Visio 原生入口读取 C2R 产品注册表，按固定上游表将支持的 Retail 产品映射至 Volume，直接导入本机许可文件并安装密钥；勾选“禁止更改版本”会跳过此转换。MSI 仅准备已安装的批量许可产品，不转换 MSI Retail。上游旧续期任务卸载仍从兼容菜单进入。
- 高级选项可指定服务器与端口；留空使用固定上游服务器列表并重试。指定主机后只连接该主机，失败不会回退到公共服务器。所有尝试失败后恢复原主机与端口；已安装的 GVLK 不会自动还原。
- 默认在成功后通过 Task Scheduler COM 注册 SYSTEM 续期任务，每 6 小时运行一次；可勾选“不创建自动续期任务”。续期只操作已有 KMS 许可证，不安装密钥或更改版本。
- 手动 Office 激活在许可准备成功后清理用户许可缓存、共享/设备许可和 OEM 屏蔽设置，可能需要重新登录 Office；后台续期不执行此清理。
- 续期程序复制到 `%ProgramFiles%\MAS-Rust\Renewal`，因此可移动原始下载文件。最近续期日志为该目录下的 `last-renewal.log`。
- 原生卸载删除本程序的续期任务并清除许可证专用 KMS 设置，保留产品密钥和 KMS38；程序副本与日志会保留，上游旧任务需在兼容菜单卸载。

v0.6.0-dev 的 TSforge 重置、v0.5.0-dev 的 Ohook 安装、Office 转换、缓存清理及卸载，以及 v0.3.0 新增的 WMI 激活和计划任务仍待 Windows 实机验证；此前用户反馈仅针对 v0.2.0。

## 构建与运行

GUI 目标为 Windows 10/11 x64，运行时通过 EXE 清单请求管理员权限。上游支持的旧系统范围不等于此 GUI 的支持范围。Linux 可编译预览界面，执行按钮不可用。

需要支持 Rust 2024 edition 的当前稳定版 Rust。Windows 原生构建还需安装 Visual Studio C++ Build Tools 和 Windows SDK。

```sh
git clone https://github.com/undownding/MAS-rust.git
cd MAS-rust
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc
cargo test --locked
cargo build --release --locked
```

Windows 原生构建输出为 `target/release/mas-rust.exe`。Linux 预览可以运行 `cargo run --locked`，需要桌面显示服务以及 X11 / Wayland、Fontconfig 和 OpenGL 相关运行库。

Windows 构建还会使用 Rust 自带 LLD 从源码编译两种架构的无标准库 Ohook DLL，因此需安装上述两个 MSVC Rust 目标。Linux 界面预览不构建 DLL。

Linux 交叉编译 Windows（需安装 Rust Windows GNU 目标及 MinGW）：

```sh
rustup target add x86_64-pc-windows-msvc i686-pc-windows-msvc
cargo build --release --locked --target x86_64-pc-windows-gnu
```

输出：`target/x86_64-pc-windows-gnu/release/mas-rust.exe`。分发时同时提供 LICENSE、vendor/mas/NOTICE.md 和对应完整源码。CI 生成 Windows x64 构建产物。

## 执行方式与已知限制

GUI 同时只允许一个任务；Windows 全局互斥锁还会阻止其他窗口和后台续期同时操作许可证。运行中不允许关闭主窗口，以保持内嵌脚本生命周期。原生流程依据 WMI 许可状态判断结果；兼容引擎退出码不代表激活成功，完成后应查询实际许可证状态。

脚本内嵌在 EXE 中，运行时不下载引擎；引擎本身的联机操作和资源下载沿用上游逻辑。兼容脚本执行时写入 `%LOCALAPPDATA%\MAS-Rust\engine-runs` 中的独占目录，退出后清理。该目录避开上游禁止使用的 Temp 子目录。所有传入脚本的参数均来自固定选项，不接受任意命令输入。不要在 Windows ARM64 的 x64 仿真环境运行此构建：上游的跨架构重启流程尚未验证。

## 项目结构

```text
src/
  app.rs          中文 GUI、任务状态与操作确认
  engine.rs       固定引擎、功能选项与启动流程
  operations.rs   许可证参数校验与命令构建
  process.rs      许可证操作入口与密钥脱敏
  native/         Rust 票据、SKU 数据、COM/WMI、服务控制与激活流程
  main.rs         应用入口与窗口图标
assets/           SVG / PNG / 多尺寸 ICO
screenshots/      README 实际运行截图
vendor/mas/       上游脚本、许可证与来源记录
vendor/ohook-rs/  固定 Rust DLL 源码、MIT 许可与改动记录
build_support/   构建阶段的 PE 导出验证
tests/hook_fixture/  隔离的 Windows DLL 测试程序
build.rs          Windows 图标资源和管理员权限清单
.github/workflows/build.yml  Windows 构建与检查
```

## 图标

`assets/app.svg` 为矢量设计，`assets/app.png` 用于窗口图标，`assets/app.ico` 含 16–256 像素多个尺寸并嵌入 Windows EXE。`tools/generate_icon.py` 使用 Pillow 重新生成 PNG / ICO 的几何渲染版本。

## 验证范围

单元测试覆盖多窗口尺寸布局、参数校验、SKU 匹配、版本回退、票据签名参考向量、原生路由、Online KMS 选择与重试策略、续期参数/XML 及兼容引擎启动器。Windows CI 另用独立 x86/x64 进程加载真实 Rust DLL 和模拟提供程序，检查 API 行为，测试不接触系统许可服务。Windows 编译检查和交叉构建用于发现平台代码与资源嵌入问题，**不等价于 Windows 实机激活测试**。

实机验收需覆盖：中文字体与输出、UAC、独立控制台交互与退出、各 Office 安装布局、各激活方式前后的许可证状态，以及历史 Windows 上的 KMS38。开发环境未执行任何激活操作；用户已反馈 v0.2.0 测试工作正常，具体覆盖范围待补充。

## 反馈与贡献

欢迎通过 [Issues](https://github.com/undownding/MAS-rust/issues) 报告问题。请附上 Windows 版本与构建号、Office 版本、所选功能、复现步骤及错误信息；分享日志前请去除产品密钥等敏感信息。

提交修改前运行：

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

涉及 Windows 行为的修改应补充目标系统的实测结果；修改内嵌引擎时同步更新来源提交和 SHA-256。

## 来源与许可

[Microsoft Activation Scripts](https://github.com/massgravel/Microsoft-Activation-Scripts) 及其贡献者保留上游版权。项目使用 [GPL-3.0-only](LICENSE)；固定版本、哈希和来源见 [来源记录](vendor/mas/NOTICE.md)。本项目非 Microsoft 或 MAS 官方产品。
