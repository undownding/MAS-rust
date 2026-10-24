#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod engine;
mod operations;
mod process;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let icon = load_icon();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("MAS Rust · 授权管理")
            .with_inner_size([920.0, 680.0])
            .with_min_inner_size([760.0, 560.0])
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "MAS Rust",
        options,
        Box::new(|context| {
            app::install_fonts(&context.egui_ctx);
            Ok(Box::new(app::MasApp::default()))
        }),
    )
}

fn load_icon() -> egui::IconData {
    let image = image::load_from_memory(include_bytes!("../assets/app.png"))
        .expect("内嵌图标应为有效 PNG")
        .into_rgba8();
    let (width, height) = image.dimensions();
    egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }
}
