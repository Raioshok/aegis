use std::path::PathBuf;
use eframe::egui::{self, Color32, RichText, Vec2};
use crate::app::AegisApp;
use crate::theme::*;

impl AegisApp {
    pub fn view_scan(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // Scan Controls Header
            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(20.0, 16.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("MALWARE SCANNER").size(15.0).strong().color(TEXT_PRIMARY));
                            ui.label(RichText::new("Target: " ).size(12.0).color(TEXT_MUTED));
                            if self.scan_target_path.is_empty() {
                                ui.label(RichText::new("Select a file or directory to scan").size(12.0).color(TEXT_SECONDARY));
                            } else {
                                ui.label(RichText::new(&self.scan_target_path).size(12.0).monospace().color(ACCENT_ORANGE));
                            }
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if self.is_scanning {
                                ui.label(RichText::new("SCANNING IN PROGRESS...").size(13.0).strong().color(ACCENT_ORANGE));
                            } else {
                                if ui.button(RichText::new("Select Directory").size(12.0)).clicked() {
                                    if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                        self.start_scan(folder);
                                    }
                                }
                                if ui.button(RichText::new("Select File").size(12.0)).clicked() {
                                    if let Some(file) = rfd::FileDialog::new().pick_file() {
                                        self.start_scan(file);
                                    }
                                }
                                if ui.button(RichText::new("Scan Current Dir").size(12.0).strong().color(Color32::WHITE)).clicked() {
                                    self.start_scan(std::env::current_dir().unwrap_or_default());
                                }
                            }
                        });
                    });

                    // Live Scan Progress Bar
                    if self.is_scanning || self.scan_total > 0 {
                        ui.add_space(14.0);
                        let progress = if self.scan_total > 0 {
                            self.scan_scanned as f32 / self.scan_total as f32
                        } else {
                            0.0
                        };

                        ui.add(egui::ProgressBar::new(progress)
                            .show_percentage()
                            .fill(ACCENT_ORANGE)
                            .animate(self.is_scanning));

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("Processed: {} / {} files", self.scan_scanned, self.scan_total)).size(11.0).monospace().color(TEXT_SECONDARY));
                            ui.label(RichText::new("·").size(11.0).color(TEXT_MUTED));
                            ui.label(RichText::new(format!("Threats: {}", self.scan_findings.len())).size(11.0).monospace().strong().color(if self.scan_findings.is_empty() { STATUS_GREEN } else { STATUS_RED }));
                        });

                        if !self.scan_current_file.is_empty() {
                            ui.add_space(2.0);
                            ui.label(RichText::new(format!("Scanning: {}", self.scan_current_file)).size(10.0).monospace().color(TEXT_MUTED));
                        }
                    }

                    if let Some(ref summary) = self.scan_summary {
                        ui.add_space(10.0);
                        ui.label(RichText::new(summary).size(12.0).strong().color(if self.scan_findings.is_empty() { STATUS_GREEN } else { STATUS_YELLOW }));
                    }
                });

            ui.add_space(16.0);

            // Findings List
            ui.horizontal(|ui| {
                ui.label(RichText::new("SCAN FINDINGS").size(13.0).strong().color(TEXT_PRIMARY));
                ui.label(RichText::new(format!("({})", self.scan_findings.len())).size(13.0).monospace().color(TEXT_MUTED));
            });
            ui.add_space(8.0);

            if self.scan_findings.is_empty() {
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
                    .rounding(egui::Rounding::same(6.0))
                    .inner_margin(egui::Margin::symmetric(16.0, 24.0))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            if self.is_scanning {
                                ui.label(RichText::new("Analyzing files against YARA-X, GBDT ML, and section heuristics...").size(12.0).color(TEXT_SECONDARY));
                            } else {
                                ui.label(RichText::new("No threats detected. Select a target to begin scanning.").size(12.0).color(TEXT_MUTED));
                            }
                        });
                    });
            } else {
                let mut quarantine_req = None;

                for (idx, (path_str, det)) in self.scan_findings.iter().enumerate() {
                    egui::Frame::none()
                        .fill(CARD_BG)
                        .stroke(egui::Stroke::new(1.0, BORDER_COLOR))
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(egui::Margin::symmetric(16.0, 12.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let (badge_color, badge_text) = match det.severity {
                                    aegis_core::Severity::Critical => (STATUS_RED, "CRITICAL"),
                                    aegis_core::Severity::High => (STATUS_RED, "HIGH"),
                                    aegis_core::Severity::Medium => (STATUS_YELLOW, "MEDIUM"),
                                    aegis_core::Severity::Low => (TEXT_SECONDARY, "LOW"),
                                    aegis_core::Severity::Clean => (STATUS_GREEN, "CLEAN"),
                                };

                                ui.label(RichText::new(format!("[{}]", badge_text)).size(11.0).monospace().strong().color(badge_color));
                                ui.add_space(4.0);

                                ui.vertical(|ui| {
                                    ui.label(RichText::new(&det.threat).size(13.0).strong().color(TEXT_PRIMARY));
                                    ui.label(RichText::new(path_str).size(11.0).monospace().color(TEXT_SECONDARY));
                                    ui.label(RichText::new(format!("Engine: {} · {}", det.engine, det.detail)).size(11.0).color(TEXT_MUTED));
                                });

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(RichText::new("Quarantine").size(11.0).color(Color32::WHITE)).clicked() {
                                        quarantine_req = Some((path_str.clone(), det.clone()));
                                    }
                                });
                            });
                        });
                    ui.add_space(6.0);
                }

                if let Some((p, d)) = quarantine_req {
                    self.quarantine_file(&p, &d);
                }
            }
        });
    }
}
