use eframe::egui::{self, RichText, Vec2};
use crate::app::AegisApp;
use crate::theme::*;

impl AegisApp {
    pub fn view_settings(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // Header
            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(20.0, 16.0))
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("ENGINE TOGGLES & PROTECTION SHIELDS").size(15.0).strong().color(TEXT_PRIMARY));
                        ui.label(RichText::new("Configure active detection engines, machine learning confidence thresholds, and driver blocklists").size(12.0).color(TEXT_SECONDARY));
                    });
                });

            ui.add_space(16.0);

            // Engine Toggles
            let mut changed = false;

            let toggles = [
                ("Pure-Rust YARA-X Engine", "Compiles AST rules for Ransomware, Wipers, Droppers, and RAT families", &mut self.config.engines.yara),
                ("Precompiled SHA-256 Hash Database", "309+ verified threat hashes with sub-microsecond binary search", &mut self.config.engines.hash),
                ("Goblin PE/ELF Heuristics Engine", "Detects anomalous entrypoints, RWX sections, and high-entropy packers", &mut self.config.engines.heuristic),
                ("Memory Evasion & Anti-Tamper Shield", "Audits module stomping, unbacked execution, and sleep masking", &mut self.config.shields.memory_defense),
            ];

            for (title, desc, toggle) in toggles {
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
                    .rounding(egui::Rounding::same(6.0))
                    .inner_margin(egui::Margin::symmetric(16.0, 14.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new(title).size(13.0).strong().color(TEXT_PRIMARY));
                                ui.label(RichText::new(desc).size(11.0).color(TEXT_SECONDARY));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.checkbox(toggle, "").changed() {
                                    changed = true;
                                }
                            });
                        });
                    });
                ui.add_space(6.0);
            }

            if changed {
                let _ = self.config.save();
                self.set_status("Settings saved successfully.");
            }

            ui.add_space(16.0);

            // System Information
            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(egui::Margin::symmetric(16.0, 14.0))
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("ARCHITECTURE & INVARIANTS").size(12.0).strong().color(TEXT_PRIMARY));
                        ui.add_space(4.0);
                        ui.label(RichText::new("• 100% Pure-Rust Native Desktop GUI (eframe / egui 0.29)").size(11.0).monospace().color(TEXT_SECONDARY));
                        ui.label(RichText::new("• Zero Electron · Zero Node.js · Zero Web runtime overhead").size(11.0).monospace().color(TEXT_SECONDARY));
                        ui.label(RichText::new("• Direct workspace crate calls: aegis_engine, aegis_quarantine, aegis_storage").size(11.0).monospace().color(TEXT_SECONDARY));
                        ui.label(RichText::new("• Tone-stepped opaque surfaces conforming to anti-slop design taste").size(11.0).monospace().color(TEXT_SECONDARY));
                    });
                });
        });
    }
}
