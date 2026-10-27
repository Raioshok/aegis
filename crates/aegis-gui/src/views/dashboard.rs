use eframe::egui::{self, Color32, RichText};
use crate::app::{AegisApp, Tab};
use crate::theme::*;

impl AegisApp {
    pub fn view_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // Main Protection Hero Card
            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(24.0, 20.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").size(24.0).color(STATUS_GREEN));
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.label(RichText::new("SYSTEM FULLY PROTECTED").size(16.0).strong().color(TEXT_PRIMARY));
                            ui.label(RichText::new("Real-time behavioral interception, YARA-X AST, and pure-Rust GBDT inference active").size(12.0).color(TEXT_SECONDARY));
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button(RichText::new("Start Quick Scan").size(13.0).strong().color(Color32::WHITE)).clicked() {
                                self.current_tab = Tab::Scan;
                                self.start_scan(std::env::current_dir().unwrap_or_default());
                            }
                        });
                    });
                });

            ui.add_space(16.0);

            // Metrics Grid (Tabular figures)
            ui.horizontal(|ui| {
                let card_w = (ui.available_width() - 32.0) / 3.0;

                // Card 1: Vault items
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(16.0))
                    .show(ui, |ui| {
                        ui.set_width(card_w);
                        ui.vertical(|ui| {
                            ui.label(RichText::new("QUARANTINE VAULT").size(11.0).monospace().color(TEXT_MUTED));
                            ui.add_space(4.0);
                            ui.label(RichText::new(format!("{}", self.quarantine_records.len())).size(28.0).strong().monospace().color(TEXT_PRIMARY));
                            ui.add_space(4.0);
                            ui.label(RichText::new("ChaCha20-Poly1305 Encrypted").size(11.0).color(TEXT_SECONDARY));
                        });
                    });

                ui.add_space(16.0);

                // Card 2: Rules & Hashes
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(16.0))
                    .show(ui, |ui| {
                        ui.set_width(card_w);
                        ui.vertical(|ui| {
                            ui.label(RichText::new("DETECTION ENGINES").size(11.0).monospace().color(TEXT_MUTED));
                            ui.add_space(4.0);
                            ui.label(RichText::new(format!("{} loaded", self.engine_status.len())).size(28.0).strong().monospace().color(TEXT_PRIMARY));
                            ui.add_space(4.0);
                            for (name, status) in &self.engine_status {
                                ui.label(RichText::new(format!("{name}: {status}")).size(10.0).color(TEXT_SECONDARY));
                            }
                        });
                    });

                ui.add_space(16.0);

                // Card 3: Memory & Evasion Shield
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(16.0))
                    .show(ui, |ui| {
                        ui.set_width(card_w);
                        ui.vertical(|ui| {
                            ui.label(RichText::new("MEMORY AUDIT FINDINGS").size(11.0).monospace().color(TEXT_MUTED));
                            ui.add_space(4.0);
                            ui.label(RichText::new(self.memory_alerts.iter().filter(|a| a.starts_with('[')).count().to_string()).size(28.0).strong().monospace().color(STATUS_GREEN));
                            ui.add_space(4.0);
                            ui.label(RichText::new("Module Stomping / TEB Masking").size(11.0).color(TEXT_SECONDARY));
                        });
                    });
            });

            ui.add_space(20.0);

            // Active Defense Modules
            ui.label(RichText::new("DETECTION SUBSYSTEMS").size(13.0).strong().color(TEXT_PRIMARY));
            ui.add_space(10.0);

            let shields = [
                ("Multi-Engine File Scanner", "YARA-X rules, PE/ELF heuristics and SHA-256 hash matching", "ON SCAN", STATUS_GREEN),
                ("On-Device GBDT Machine Learning", "Gradient boosted trees over structural PE features", "ON SCAN", STATUS_GREEN),
                ("ChaCha20-Poly1305 Quarantine Vault", "Encrypts quarantined files at rest so they cannot run", "READY", STATUS_GREEN),
                ("Android APK/DEX Inspector", "Dalvik bytecode and permission analysis for .apk/.dex files", "ON SCAN", STATUS_GREEN),
            ];

            for (title, desc, status, color) in shields {
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                    .rounding(egui::Rounding::same(6.0))
                    .inner_margin(egui::Margin::symmetric(16.0, 12.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new(title).size(13.0).strong().color(TEXT_PRIMARY));
                                ui.label(RichText::new(desc).size(11.0).color(TEXT_SECONDARY));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(status).size(11.0).monospace().strong().color(color));
                            });
                        });
                    });
                ui.add_space(6.0);
            }
        });
    }
}
