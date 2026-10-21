mod app;
mod theme;
mod views;

use app::AegisApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt::init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 840.0])
            .with_min_inner_size([960.0, 600.0])
            .with_title("Aegis Antivirus & EDR (Pure-Rust)")
            .with_active(true),
        ..Default::default()
    };

    eframe::run_native(
        "Aegis Antivirus & EDR",
        native_options,
        Box::new(|cc| {
            theme::apply_theme(&cc.egui_ctx);
            Ok(Box::new(AegisApp::new(cc)))
        }),
    )
}
