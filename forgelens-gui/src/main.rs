#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;

use app::ForgeLensApp;

fn main() -> Result<(), eframe::Error> {
    env_logger::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ForgeLens Memory Forensics & Anomaly Scanner")
            .with_inner_size([1280.0, 768.0])
            .with_min_inner_size([1000.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "ForgeLens",
        options,
        Box::new(|cc| {
            // Apply custom dark theme visual configurations
            let mut style = (*cc.egui_ctx.style()).clone();
            
            // Custom styling for premium aesthetic (harmonious deep colors, rounded edges)
            style.visuals.dark_mode = true;
            style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(18, 20, 26);
            style.visuals.widgets.noninteractive.weak_bg_fill = egui::Color32::from_rgb(26, 28, 36);
            style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(45, 48, 62));
            style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(220, 224, 235));
            style.visuals.widgets.noninteractive.rounding = egui::Rounding::same(8.0);
            
            style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(28, 30, 40);
            style.visuals.widgets.inactive.rounding = egui::Rounding::same(6.0);
            style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(59, 130, 246);
            style.visuals.widgets.active.rounding = egui::Rounding::same(6.0);
            style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(40, 44, 58);
            style.visuals.widgets.hovered.rounding = egui::Rounding::same(6.0);

            style.visuals.window_rounding = egui::Rounding::same(12.0);
            style.visuals.window_shadow = egui::epaint::Shadow {
                offset: egui::vec2(0.0, 4.0),
                blur: 12.0,
                spread: 0.0,
                color: egui::Color32::from_black_alpha(80),
            };

            cc.egui_ctx.set_style(style);
            Box::new(ForgeLensApp::new(cc))
        }),
    )
}
