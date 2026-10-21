use egui::{Color32, Stroke};

pub const BG_COLOR: Color32 = Color32::from_rgb(12, 13, 18);          // #0C0D12 Deepest background
pub const SIDEBAR_COLOR: Color32 = Color32::from_rgb(16, 18, 26);     // #10121A Navigation rail
pub const CARD_BG: Color32 = Color32::from_rgb(20, 23, 33);           // #141721 Surface cards
pub const CARD_HOVER: Color32 = Color32::from_rgb(26, 30, 43);        // #1A1E2B Hover state
pub const BORDER_COLOR: Color32 = Color32::from_rgb(34, 38, 54);      // #222636 Tone-stepped border

pub const ACCENT_ORANGE: Color32 = Color32::from_rgb(255, 114, 34);   // #FF7222 Brand Accent
pub const STATUS_GREEN: Color32 = Color32::from_rgb(16, 185, 129);    // #10B981 Clean / Protected
pub const STATUS_YELLOW: Color32 = Color32::from_rgb(245, 158, 11);   // #F59E0B Warning / Suspicious
pub const STATUS_RED: Color32 = Color32::from_rgb(239, 68, 68);       // #EF4444 Critical / Convicted

pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(243, 244, 246);   // #F3F4F6 Primary typography
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(156, 163, 175); // #9CA3AF Secondary typography
pub const TEXT_MUTED: Color32 = Color32::from_rgb(107, 114, 128);     // #6B7280 Muted details

pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG_COLOR;
    visuals.window_fill = CARD_BG;
    visuals.faint_bg_color = SIDEBAR_COLOR;
    visuals.extreme_bg_color = Color32::from_rgb(8, 9, 13);
    visuals.override_text_color = Some(TEXT_PRIMARY);

    visuals.widgets.noninteractive.bg_fill = CARD_BG;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER_COLOR);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
    visuals.widgets.noninteractive.rounding = egui::Rounding::same(6.0_f32);

    visuals.widgets.inactive.bg_fill = CARD_BG;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER_COLOR);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT_SECONDARY);
    visuals.widgets.inactive.rounding = egui::Rounding::same(6.0_f32);

    visuals.widgets.hovered.bg_fill = CARD_HOVER;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT_ORANGE);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
    visuals.widgets.hovered.rounding = egui::Rounding::same(6.0_f32);

    visuals.widgets.active.bg_fill = ACCENT_ORANGE;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, ACCENT_ORANGE);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
    visuals.widgets.active.rounding = egui::Rounding::same(6.0_f32);

    ctx.set_visuals(visuals);
}
