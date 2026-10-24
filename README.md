<p align="center">
  <img src="assets/app.png" alt="MAS Rust 图标" width="96" />
</p>

# MAS Rust

使用 **Rust + egui** 构建的 Windows / Office 激活与许可证管理桌面前端，内嵌固定版本的 [Microsoft Activation Scripts（MAS）](https://github.com/massgravel/Microsoft-Activation-Scripts)，提供中文界面和独立应用图标。

[![Windows build](https://github.com/undownding/MAS-rust/actions/workflows/build.yml/badge.svg)](https://github.com/undownding/MAS-rust/actions/workflows/build.yml)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

[功能](#功能) · [界面预览](#界面预览) · [获取与使用](#获取与使用) · [构建与运行](#构建与运行) · [验证范围](#验证范围)

**实现方式：Rust GUI + 固定版本的 MAS 脚本引擎，不是激活算法的纯 Rust 重写。**
主要激活方法可从图形界面选择，执行进度在独立控制台显示；高级工具仍使用完整上游交互菜单。并非所有上游流程都已改写成原生 GUI。

## 界面预览

![MAS Rust 激活页实际运行截图](screenshots/mas-rust-preview.png)

截图来自 Linux 下的实际运行画面。Linux 为预览模式，因此执行按钮置灰；激活和许可证操作需要在 Windows 上运行。图中 TSforge、Online KMS 和高级选项处于折叠状态。

## 功能

| 功能 | 入口 |
| --- | --- |
| HWID | GUI，支持禁止自动更改版本 |
| Ohook / 卸载 | GUI |
| TSforge Windows / Office / ESU / Project / Visio / KMS Host / APPX / 重置 | GUI，支持默认、SCID、ZCID、KMS4k 方法 |
| Online KMS Windows / Office / Project / Visio / 卸载 | GUI，可选择禁止版本更改与禁止自动续期任务 |
| KMS38 | GUI 执行及历史完整菜单 |
| 激活状态、Windows / Office 版本切换、排障、OEM 提取、其他高级选项 | 工具箱 → 完整 MAS 菜单 |
| 密钥安装 / 卸载、联机激活、自定义 KMS 主机与端口 | 许可证页，调用系统 slmgr / ospp |

上游 MAS 当前版本已移除 KMS38。这里保留移除前的固定版本；上游注明 **build 26100.7019 起 CLiP KMS 许可机制被废弃**。历史引擎不能恢复新系统已删除的能力，不能承诺所有 Windows 版本均可使用 KMS38。
参考：[移除提交](https://github.com/massgravel/Microsoft-Activation-Scripts/commit/470d3b900e6aebfba224fde3ea7957308dd61230)。

## 获取与使用

### 获取 Windows 程序

前往 [GitHub Actions](https://github.com/undownding/MAS-rust/actions/workflows/build.yml)，选择成功的 `Windows build` 运行，在 Artifacts 中下载 `mas-rust-windows-x64`，解压后运行 `mas-rust.exe`。下载 Actions 构建产物通常需要登录 GitHub；也可以按下方说明自行编译。

当前项目处于早期阶段，构建产物未经 Windows 实机激活验证。

### 操作步骤

1. 运行 EXE 并接受 Windows 管理员提示。
2. 在“激活”选择方法和参数，确认后查看独立引擎窗口。
3. 工具箱中的完整菜单包含上游的版本切换、排障和 OEM 等交互流程。
4. 操作结束后按任意键关闭引擎窗口，再到“许可证”查询状态。
5. “日志”页可复制 GUI 任务结果；完整过程输出请在引擎窗口查看。

## 构建与运行

GUI 目标为 Windows 10/11 x64，运行时通过 EXE 清单请求管理员权限。上游支持的旧系统范围不等于此 GUI 的支持范围。Linux 可编译预览界面，执行按钮不可用。

需要支持 Rust 2024 edition 的当前稳定版 Rust。Windows 原生构建还需安装 Visual Studio C++ Build Tools 和 Windows SDK。

```sh
git clone https://github.com/undownding/MAS-rust.git
cd MAS-rust
cargo test --locked
cargo build --release --locked
```

Windows 原生构建输出为 `target/release/mas-rust.exe`。Linux 预览可以运行 `cargo run --locked`，需要桌面显示服务以及 X11 / Wayland、Fontconfig 和 OpenGL 相关运行库。

Linux 交叉编译 Windows（需安装 Rust Windows GNU 目标及 MinGW）：

```sh
cargo build --release --locked --target x86_64-pc-windows-gnu
```

输出：`target/x86_64-pc-windows-gnu/release/mas-rust.exe`。分发时同时提供 LICENSE、vendor/mas/NOTICE.md 和对应完整源码。CI 生成 Windows x64 构建产物。

## 执行方式与已知限制

GUI 同时只允许一个任务。运行中不允许关闭主窗口，以保持内嵌脚本生命周期。GUI 日志记录任务结果，完整激活过程输出保留在引擎窗口；进程退出码不代表激活成功。系统授权工具可能返回零退出码并在正文报告失败，应阅读查询结果。

脚本内嵌在 EXE 中，运行时不下载引擎；引擎本身的联机操作和资源下载沿用上游逻辑。执行时写入独占临时目录，退出后清理。所有传入脚本的参数均来自固定选项，不接受任意命令输入。不要在 Windows ARM64 的 x64 仿真环境运行此构建：上游的跨架构重启流程尚未验证。

## 项目结构

```text
src/
  app.rs          中文 GUI、任务状态与操作确认
  engine.rs       固定引擎、功能选项与启动流程
  operations.rs   许可证参数校验与命令构建
  process.rs      系统工具执行与输出处理
  main.rs         应用入口与窗口图标
assets/           SVG / PNG / 多尺寸 ICO
screenshots/      README 实际运行截图
vendor/mas/       上游脚本、许可证与来源记录
build.rs          Windows 图标资源和管理员权限清单
.github/workflows/build.yml  Windows 构建与检查
```

## 图标

`assets/app.svg` 为矢量设计，`assets/app.png` 用于窗口图标，`assets/app.ico` 含 16–256 像素多个尺寸并嵌入 Windows EXE。`tools/generate_icon.py` 使用 Pillow 重新生成 PNG / ICO 的几何渲染版本。

## 验证范围

单元测试覆盖参数校验、命令生成、Office 路径、GUI 开关与固定版本引擎的对应关系。Windows 编译检查和交叉构建用于发现平台代码与资源嵌入问题，**不等价于 Windows 实机激活测试**。

实机验收需覆盖：中文字体与输出、UAC、独立控制台交互与退出、各 Office 安装布局、各激活方式前后的许可证状态，以及历史 Windows 上的 KMS38。当前环境未执行任何激活操作。

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
