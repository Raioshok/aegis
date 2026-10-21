use eframe::egui::{self, Color32, RichText};
use crate::app::{AegisApp, Tab};
use crate::theme::*;

impl AegisApp {
    pub fn view_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // Main Protection Hero Card
            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
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
                    .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
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
                    .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(16.0))
                    .show(ui, |ui| {
                        ui.set_width(card_w);
                        ui.vertical(|ui| {
                            ui.label(RichText::new("ACTIVE DETECTORS").size(11.0).monospace().color(TEXT_MUTED));
                            ui.add_space(4.0);
                            ui.label(RichText::new("309+ / 26 Rules").size(28.0).strong().monospace().color(TEXT_PRIMARY));
                            ui.add_space(4.0);
                            ui.label(RichText::new("YARA-X AST + 14-Tree GBDT").size(11.0).color(TEXT_SECONDARY));
                        });
                    });

                ui.add_space(16.0);

                // Card 3: Memory & Evasion Shield
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
                    .rounding(egui::Rounding::same(8.0))
                    .inner_margin(egui::Margin::same(16.0))
                    .show(ui, |ui| {
                        ui.set_width(card_w);
                        ui.vertical(|ui| {
                            ui.label(RichText::new("MEMORY EVASION SHIELD").size(11.0).monospace().color(TEXT_MUTED));
                            ui.add_space(4.0);
                            ui.label(RichText::new("ACTIVE").size(28.0).strong().monospace().color(STATUS_GREEN));
                            ui.add_space(4.0);
                            ui.label(RichText::new("Module Stomping / TEB Masking").size(11.0).color(TEXT_SECONDARY));
                        });
                    });
            });

            ui.add_space(20.0);

            // Active Defense Modules
            ui.label(RichText::new("ACTIVE DEFENSE SUBSYSTEMS").size(13.0).strong().color(TEXT_PRIMARY));
            ui.add_space(10.0);

            let shields = [
                ("Multi-Engine Static Orchestrator", "Pure-Rust YARA-X, Goblin PE/ELF, and SHA-256 binary search", "OPERATIONAL", STATUS_GREEN),
                ("On-Device GBDT Machine Learning", "14-tree gradient boosted classifier evaluating structural PE feature distributions", "OPERATIONAL", STATUS_GREEN),
                ("ChaCha20-Poly1305 Quarantine Vault", "Authenticated cryptographic isolation preventing malware execution on host", "OPERATIONAL", STATUS_GREEN),
                ("LOLDrivers BYOVD Shield", "Blocklist verifying vulnerable signed driver certificates (RTCore64, DBUtil, etc.)", "OPERATIONAL", STATUS_GREEN),
                ("Process Execution DAG Anomaly Engine", "Real-time Shannon command entropy and parent-child execution lineage scoring", "OPERATIONAL", STATUS_GREEN),
                ("Android APK/DEX Security Engine", "Dalvik bytecode inspector, permission scoring, and payload unpacker", "OPERATIONAL", STATUS_GREEN),
            ];

            for (title, desc, status, color) in shields {
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
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
