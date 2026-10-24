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

#[derive(Clone)]
enum Job {
    Engine(Operation, Options),
    License(Product, Action),
}

pub struct MasApp {
    page: &'static str,
    product: Product,
    key: String,
    tail: String,
    host: String,
    port: String,
    options: Options,
    pending: Option<Job>,
    receiver: Option<mpsc::Receiver<Result<String, String>>>,
    log: String,
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
            pending: None,
            receiver: None,
            log: "准备就绪。选择功能后查看并确认操作。\n".into(),
        }
    }
}
impl MasApp {
    fn start(&mut self, job: Job, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = match job {
                Job::Engine(op, options) => engine::run(op, options),
                Job::License(product, action) => {
                    process::execute(product, action, Arc::new(AtomicBool::new(false)))
                        .map(|r| r.output)
                }
            };
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }
    fn activation(&mut self, ui: &mut egui::Ui) {
        ui.heading("Windows & Office");
        ui.label("选择激活方式。引擎会在独立窗口显示实时进度及交互提示。");
        ui.add_space(8.0);
        ui.collapsing("高级选项", |ui| {
            ui.checkbox(
                &mut self.options.no_edition_change,
                "不自动更改 Windows 版本（HWID / KMS / KMS38）",
            );
            ui.checkbox(
                &mut self.options.no_renewal,
                "Online KMS 不创建自动续期任务",
            );
            egui::ComboBox::from_label("TSforge 方法")
                .selected_text(["上游默认", "SCID", "ZCID", "KMS4k"][self.options.ts_method])
                .show_ui(ui, |ui| {
                    for (i, label) in ["上游默认", "SCID", "ZCID", "KMS4k"].iter().enumerate() {
                        ui.selectable_value(&mut self.options.ts_method, i, *label);
                    }
                });
        });
        for category in ["HWID", "Ohook", "TSforge", "Online KMS", "KMS38", "工具箱"] {
            egui::CollapsingHeader::new(category).default_open(matches!(category, "HWID" | "Ohook" | "KMS38" | "工具箱")).show(ui, |ui| {
                if category == "KMS38" {
                    ui.colored_label(Color32::from_rgb(245,172,92), "历史功能：上游已移除；build 26100.7019 起相关机制失效。请核对系统兼容性。");
                }
                if category == "工具箱" { ui.label("打开完整上游菜单：查询状态、更改 Windows / Office 版本、故障排查、提取 $OEM$、帮助及其他高级设置。"); }
                ui.horizontal_wrapped(|ui| {
                    for op in engine::OPERATIONS.iter().filter(|op| op.category == category) {
                        if ui.button(op.title).clicked() { self.pending = Some(Job::Engine(*op, self.options.clone())); }
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
        ui.label("通过 Windows slmgr / Office ospp 管理许可证。");
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
                .desired_width(380.0),
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
        ui.label("自定义 KMS 服务器");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.host)
                    .hint_text("主机名 / IP 地址")
                    .desired_width(260.0),
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
impl eframe::App for MasApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.receiver {
            let result = match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err("后台任务异常中止。".into())),
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = result {
                self.log.push_str(&match result {
                    Ok(text) => format!("{text}\n"),
                    Err(error) => format!("错误：{error}\n"),
                });
                self.receiver = None;
            }
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
            if self.receiver.is_some() { ui.horizontal(|ui| { ui.spinner(); ui.label("任务运行中。请查看引擎窗口；结束任务后即可关闭应用。"); }); }
            egui::ScrollArea::vertical().show(ui, |ui| {
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
                        ui.add(egui::TextEdit::multiline(&mut self.log).desired_width(f32::INFINITY).desired_rows(22).interactive(false));
                    }
                    "关于" => {
                        ui.heading("MAS Rust 0.1.0");
                        ui.label("Rust / egui 图形前端，内嵌固定版本 MAS 引擎。非 Microsoft 或 MAS 官方产品。");
                        ui.label("当前引擎：MAS 3.12 · 6401d2f36975");
                        ui.label("KMS38 历史引擎：c9789e9aa341");
                        ui.label("激活核心为上游脚本，未宣称纯 Rust 重写。高级工具保留原生控制台交互。");
                        ui.hyperlink_to("上游源码与文档", "https://github.com/massgravel/Microsoft-Activation-Scripts");
                        ui.hyperlink_to("KMS38 兼容性变更", "https://github.com/massgravel/Microsoft-Activation-Scripts/commit/470d3b900e6aebfba224fde3ea7957308dd61230");
                        ui.label("GPL-3.0-only · 上游及其贡献者版权保留。许可证随源代码分发。");
                    }
                    _ => {}
                }
            });
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
                            ui.label("将打开管理员引擎窗口。请在该窗口查看进度与结果。");
                            if op.legacy {
                                ui.colored_label(
                                    Color32::YELLOW,
                                    "KMS38 是历史实现，新系统可能不支持。",
                                );
                            }
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
