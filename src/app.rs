use crate::{
    engine::{self, Operation, Options},
    operations::{self, Action, Product},
    process,
};
use eframe::egui::{self, Color32, RichText};
use std::sync::{Arc, atomic::AtomicBool, mpsc};

pub fn install_fonts(ctx: &egui::Context) {
    // eframe's system_fonts provider supplies CJK glyphs from the host OS.
    ctx.set_visuals(egui::Visuals::dark());
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.spacing.item_spacing = egui::vec2(12.0, 12.0);
    style.spacing.button_padding = egui::vec2(14.0, 9.0);
    style.visuals.selection.bg_fill = Color32::from_rgb(32, 110, 104);
    ctx.set_style_of(egui::Theme::Dark, style);
}

enum Event {
    Progress(String),
    Finished(Result<String, String>),
}

#[derive(Clone)]
enum Job {
    Engine(Operation, Options),
    License(Product, Action),
    RestoreBackup(String),
}

pub struct MasApp {
    page: &'static str,
    product: Product,
    key: String,
    tail: String,
    host: String,
    port: String,
    options: Options,
    backup_directory: String,
    pending: Option<Job>,
    receiver: Option<mpsc::Receiver<Event>>,
    log: String,
    #[cfg(test)]
    content_rect: Option<egui::Rect>,
}
impl Default for MasApp {
    fn default() -> Self {
        Self {
            page: "激活",
            product: Product::Windows,
            key: String::new(),
            tail: String::new(),
            host: String::new(),
            port: "1688".into(),
            options: Options::default(),
            backup_directory: String::new(),
            pending: None,
            receiver: None,
            log: "准备就绪。选择功能后查看并确认操作。\n".into(),
            #[cfg(test)]
            content_rect: None,
        }
    }
}
impl MasApp {
    fn start(&mut self, job: Job, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.page = "日志";
        self.log.push_str("\n──── 开始新任务 ────\n");
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let report = |line: &str| {
                let _ = tx.send(Event::Progress(line.to_owned()));
                ctx.request_repaint();
            };
            let result = match job {
                Job::Engine(op, options) => engine::run(op, options, &report),
                Job::RestoreBackup(path) => engine::restore_tsforge(&path, &report),
                Job::License(product, action) => {
                    process::execute(product, action, Arc::new(AtomicBool::new(false)))
                        .map(|r| r.output)
                }
            };
            let _ = tx.send(Event::Finished(result));
            ctx.request_repaint();
        });
    }
    fn activation(&mut self, ui: &mut egui::Ui) {
        ui.heading("Windows & Office");
        ui.label("HWID / Ohook / KMS38 / Online KMS 使用 Rust；TSforge Windows、ESU 与重置已接入原生流程，范围见下方。进度与错误见日志页。");
        ui.add_space(8.0);
        ui.collapsing("高级选项", |ui| {
            ui.checkbox(
                &mut self.options.no_edition_change,
                "不自动更改 Windows / Office 版本（HWID / KMS / KMS38）",
            );
            ui.checkbox(
                &mut self.options.no_renewal,
                "Online KMS 不创建自动续期任务",
            );
            ui.label("Online KMS 服务器（留空使用上游固定服务器列表）");
            ui.add(
                egui::TextEdit::singleline(&mut self.options.kms_server)
                    .desired_width(f32::INFINITY)
                    .hint_text("kms.example.org"),
            );
            ui.horizontal(|ui| {
                ui.label("Online KMS 端口");
                ui.add(egui::DragValue::new(&mut self.options.kms_port).range(1..=65535));
            });
            egui::ComboBox::from_label("TSforge 方法")
                .selected_text(["上游默认", "SCID", "ZCID", "KMS4k"][self.options.ts_method])
                .show_ui(ui, |ui| {
                    for (i, label) in ["上游默认", "SCID", "ZCID", "KMS4k"].iter().enumerate() {
                        ui.selectable_value(&mut self.options.ts_method, i, *label);
                    }
                });
        });
        for category in ["HWID", "Ohook", "TSforge", "Online KMS", "KMS38", "工具箱"] {
            egui::CollapsingHeader::new(category).default_open(matches!(category, "HWID" | "Ohook" | "TSforge" | "KMS38" | "工具箱")).show(ui, |ui| {
                if category == "KMS38" {
                    ui.colored_label(Color32::from_rgb(245,172,92), "历史功能：上游已移除；build 26100.7019 起相关机制失效。请核对系统兼容性。");
                }
                if category == "Ohook" {ui.label("安装与卸载使用 Rust，内嵌 DLL 从 Rust 源码构建；安装后请重启 Office 检查效果。");}
                if category == "TSforge" { ui.label("Windows / ESU 单项：build 9600+ 使用 Rust；Windows 评估版、旧版及其他激活入口仍兼容。原生激活待实机验收，重置不等于激活。"); }
                if category == "Online KMS" {
                    ui.label("原生支持 Windows、Office C2R 许可转换和 MSI 批量许可；可禁止自动转换。高级选项可指定服务器和端口，旧任务卸载仍在兼容菜单。");
                }
                if category == "工具箱" { ui.label("打开完整上游菜单：查询状态、更改 Windows / Office 版本、故障排查、提取 $OEM$、帮助及其他高级设置。"); }
                if category == "TSforge" {
                    ui.collapsing("恢复本机 TSforge 备份", |ui| {
                        ui.label("粘贴日志中的备份目录。恢复会替换所选存储及备份中的产品注册表值，并另行备份当前状态。");
                        ui.add(egui::TextEdit::singleline(&mut self.backup_directory).desired_width(f32::INFINITY).hint_text("包含 manifest.json 的备份目录"));
                        let path = self.backup_directory.trim().trim_matches('"');
                        if ui.add_enabled(!path.is_empty(), egui::Button::new("恢复备份 · Rust")).clicked() {
                            self.pending = Some(Job::RestoreBackup(path.to_owned()));
                        }
                    });
                }
                ui.horizontal_wrapped(|ui| {
                    for op in engine::OPERATIONS.iter().filter(|op| op.category == category) {
                        if ui.button(format!("{} · {}", op.title, if matches!(op.args, ["/Z-Windows"] | ["/Z-ESU"]) { "Rust / 兼容" } else if engine::is_native(*op) { "Rust" } else { "兼容" })).clicked() { self.pending = Some(Job::Engine(*op, self.options.clone())); }
                    }
                });
            });
        }
    }
    fn license(&mut self, ui: &mut egui::Ui) {
        ui.heading("许可证管理");
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.product, Product::Windows, "Windows");
            ui.selectable_value(&mut self.product, Product::Office, "Office");
        });
        ui.label("通过原生 COM/WMI 管理许可证，不调用 PowerShell、slmgr 或 ospp。");
        let mut action = None;
        ui.horizontal(|ui| {
            if ui.button("查询状态").clicked() {
                action = Some(Ok(Action::Query));
            }
            if ui.button("联机激活").clicked() {
                action = Some(Ok(Action::Activate));
            }
        });
        ui.separator();
        ui.label("产品密钥");
        ui.add(
            egui::TextEdit::singleline(&mut self.key)
                .password(true)
                .hint_text("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
                .desired_width(f32::INFINITY),
        );
        if ui.button("安装密钥").clicked() {
            action = Some(operations::normalize_product_key(&self.key).map(Action::InstallKey));
        }
        ui.horizontal(|ui| {
            if self.product == Product::Office {
                ui.add(
                    egui::TextEdit::singleline(&mut self.tail)
                        .hint_text("密钥末五位")
                        .desired_width(140.0),
                );
            }
            if ui.button("卸载产品密钥").clicked() {
                action = Some(if self.product == Product::Office {
                    operations::normalize_key_tail(&self.tail).map(Action::UninstallKey)
                } else {
                    Ok(Action::UninstallKey(String::new()))
                });
            }
        });
        ui.separator();
        ui.label("自定义 KMS 服务器（仅修改所选产品已安装许可证的专用设置）");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.host)
                    .hint_text("主机名 / IP 地址")
                    .desired_width((ui.available_width() - 84.0).max(120.0)),
            );
            ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(60.0));
        });
        ui.horizontal(|ui| {
            if ui.button("设置服务器").clicked() {
                action = Some(operations::normalize_kms_host(&self.host).and_then(|host| {
                    operations::validate_kms_port(&self.port)
                        .map(|port| Action::SetKms { host, port })
                }));
            }
            if ui.button("清除服务器").clicked() {
                action = Some(Ok(Action::ClearKms));
            }
        });
        if let Some(action) = action {
            match action {
                Ok(action) => {
                    self.pending = Some(Job::License(self.product, action));
                    self.key.clear();
                }
                Err(error) => self.log.push_str(&format!("{error}\n")),
            }
        }
    }
}
impl MasApp {
    fn render(&mut self, ui: &mut egui::Ui) {
        let mut finished = false;
        if let Some(rx) = &self.receiver {
            loop {
                match rx.try_recv() {
                    Ok(Event::Progress(line)) => {
                        self.log.push_str(&line);
                        self.log.push('\n');
                    }
                    Ok(Event::Finished(result)) => {
                        self.log.push_str(&match result {
                            Ok(text) => format!("{text}\n"),
                            Err(e) => format!("错误：{e}\n"),
                        });
                        finished = true;
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.log.push_str("后台任务异常中止。\n");
                        finished = true;
                        break;
                    }
                }
            }
        }
        if finished {
            self.receiver = None;
        }
        let ctx = ui.ctx().clone();
        if self.receiver.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(250));
        }
        if ctx.input(|i| i.viewport().close_requested()) && self.receiver.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(RichText::new("MAS").color(Color32::from_rgb(57,199,172)).size(32.0));
                ui.label(RichText::new("RUST").size(22.0));
                ui.label("Windows · Office · ESU");
            });
            ui.horizontal(|ui| {
                for page in ["激活", "许可证", "日志", "关于"] { ui.selectable_value(&mut self.page, page, page); }
            });
            ui.separator();
            if cfg!(windows) && !process::is_admin() {
                ui.colored_label(Color32::YELLOW, "请以管理员身份启动应用。");
            }
            if !cfg!(windows) { ui.colored_label(Color32::from_rgb(245,172,92), "预览模式 · 执行功能需要 Windows"); }
            if self.receiver.is_some() { ui.horizontal(|ui| { ui.spinner(); ui.label("任务运行中；当前日志显示执行进度。交互菜单请查看独立窗口。"); }); }
            let viewport_height = ui.available_height();
            let scroll = egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.add_enabled_ui(self.receiver.is_none() && cfg!(windows), |ui| {
                    match self.page {
                        "激活" => self.activation(ui),
                        "许可证" => self.license(ui),
                        _ => {}
                    }
                });
                match self.page {
                    "日志" => {
                        ui.horizontal(|ui| {
                            if ui.button("复制日志").clicked() { ui.ctx().copy_text(self.log.clone()); }
                            if ui.button("清空").clicked() { self.log.clear(); }
                        });
                        ui.add(egui::TextEdit::multiline(&mut self.log).desired_width(f32::INFINITY).desired_rows(1).min_size(egui::vec2(0.0, (viewport_height - 52.0).max(100.0))).interactive(false));
                    }
                    "关于" => {
                        ui.heading(concat!("MAS Rust ", env!("CARGO_PKG_VERSION")));
                        ui.label("Rust / egui 图形前端，内嵌固定版本 MAS 引擎。非 Microsoft 或 MAS 官方产品。");
                        ui.label("当前引擎：MAS 3.12 · 6401d2f36975");
                        ui.label("KMS38 历史引擎：c9789e9aa341");
                        ui.label("HWID / Ohook / KMS38 / Online KMS 核心和许可证管理已迁移 Rust；TSforge 重置已迁移 Rust，激活与高级工具仍使用兼容引擎；Office 修复分支仍在迁移。");
                        ui.hyperlink_to("上游源码与文档", "https://github.com/massgravel/Microsoft-Activation-Scripts");
                        ui.hyperlink_to("KMS38 兼容性变更", "https://github.com/massgravel/Microsoft-Activation-Scripts/commit/470d3b900e6aebfba224fde3ea7957308dd61230");
                        ui.label("GPL-3.0-only · 上游及其贡献者版权保留。许可证随源代码分发。");
                    }
                    _ => {}
                }
            });
            #[cfg(test)] { self.content_rect = Some(scroll.inner_rect); }
            #[cfg(not(test))] let _ = scroll;
        });
        if let Some(job) = self.pending.clone() {
            let mut execute = false;
            let mut dismiss = false;
            egui::Window::new("确认操作")
                .collapsible(false)
                .resizable(false)
                .show(&ctx, |ui| {
                    match &job {
                        Job::Engine(op, options) => {
                            ui.label(op.title);
                            ui.monospace(engine::arguments(*op, options).join(" "));
                            ui.label(if engine::is_native(*op) {
                                "使用原生 Rust 执行；进度与 HRESULT 错误在日志页显示。"
                            } else {
                                "使用上游兼容引擎，仍需要 Windows PowerShell；日志页显示执行结果。"
                            });
                            if op.category == "Online KMS"
                                && engine::is_native(*op)
                                && op.args != ["/K-Uninstall"]
                            {
                                ui.label(format!(
                                    "服务器：{}:{}",
                                    if options.kms_server.trim().is_empty() {
                                        "上游固定服务器列表"
                                    } else {
                                        options.kms_server.trim()
                                    },
                                    options.kms_port
                                ));
                                ui.label(if options.no_renewal {
                                    "不创建自动续期任务"
                                } else {
                                    "成功后创建 SYSTEM 续期任务（每 6 小时）"
                                });
                            }
                            if op.category == "Online KMS" && op.args.iter().any(|arg| matches!(*arg, "/K-Office" | "/K-ProjectVisio" | "/K-WindowsOffice")) {
                                ui.label("Office 激活会清理用户许可缓存及共享/设备许可设置；可能需要重新登录 Office。");
                            }
                            if op.args == ["/Z-Reset"] {
                                ui.label("将重置许可存储中的 rearm 计数、宽限/评估计时器及相关标记。每个阶段保留备份；这不等于激活系统。当前原生路径仅处理现代存储布局（build 9600+）。");
                            }
                            if op.args == ["/Ohook"] {
                                ui.label("将安装 Office 许可和 Rust DLL，并清理用户许可缓存。请先关闭 Office；可能需要重新登录。");
                            }
                            if op.legacy {
                                ui.colored_label(
                                    Color32::YELLOW,
                                    "KMS38 是历史实现，新系统可能不支持。",
                                );
                            }
                        }
                        Job::RestoreBackup(path) => {
                            ui.label("恢复本机 TSforge 备份");
                            ui.monospace(path);
                            ui.label("将许可存储和备份中的产品注册表值恢复到所选时刻，覆盖之后的许可变化。仅使用本机备份；程序将验证目标路径、校验和及存储格式，并备份当前状态。此操作不代表激活成功。");
                        }
                        Job::License(product, action) => {
                            ui.label(format!("{} · {}", product.name(), action.label()));
                        }
                    }
                    ui.horizontal(|ui| {
                        execute = ui.button("执行").clicked();
                        dismiss = ui.button("取消").clicked();
                    });
                });
            if execute {
                self.pending = None;
                self.start(job, &ctx);
            }
            if dismiss {
                self.pending = None;
            }
        }
    }
}

impl eframe::App for MasApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render(ui);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scroll_area_tracks_window_right_edge_on_every_page() {
        let ctx = egui::Context::default();
        let mut app = MasApp::default();
        for width in [760.0, 920.0, 1440.0, 760.0] {
            for page in ["激活", "许可证", "日志", "关于"] {
                app.page = page;
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 680.0),
                    )),
                    ..Default::default()
                };
                let mut output = ctx.run_ui(input, |ui| app.render(ui));
                output.textures_delta.clear();
                let rect = app.content_rect.unwrap();
                assert!(
                    rect.right() >= width - 32.0 && rect.right() <= width,
                    "{page}: {width} => {rect:?}"
                );
                assert!(
                    rect.bottom() >= 650.0,
                    "scroll area should fill the remaining height"
                );
            }
        }
    }
}
