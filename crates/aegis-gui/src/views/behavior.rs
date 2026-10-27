use eframe::egui::{self, Color32, RichText};
use crate::app::AegisApp;
use crate::theme::*;

impl AegisApp {
    pub fn view_behavior(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // Header
            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(20.0, 16.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("BEHAVIORAL LINEAGE & IN-MEMORY DEFENSE").size(15.0).strong().color(TEXT_PRIMARY));
                            ui.label(RichText::new("Process Execution DAG anomaly scoring, Module Stomping diffing, and FunctionPeekaboo sleep-mask inspection").size(12.0).color(TEXT_SECONDARY));
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if self.is_auditing_memory {
                                ui.label(RichText::new("AUDITING MEMORY...").size(12.0).strong().color(ACCENT_ORANGE));
                            } else {
                                if ui.button(RichText::new("Run Memory Audit").size(12.0).strong().color(Color32::WHITE)).clicked() {
                                    self.start_memory_audit();
                                }
                            }
                        });
                    });
                });

            ui.add_space(16.0);

            // Active Memory Shields
            ui.label(RichText::new("IN-MEMORY EVASION DETECTORS (RUN BY MEMORY AUDIT)").size(13.0).strong().color(TEXT_PRIMARY));
            ui.add_space(8.0);

            let detectors = [
                ("Module Stomping Diffing", "Compares on-disk .text section SHA-256 against the live in-memory mapping to detect overwritten DLL code", "ON DEMAND"),
                ("FunctionPeekaboo TEB Inspector", "Checks TEB.UserReserved[0..4] pointers for per-function sleep obfuscation", "ON DEMAND"),
                ("Unbacked Thread Hunter", "Finds threads whose start address or instruction pointer is in memory not backed by a file", "ON DEMAND"),
                ("Thread Hijack / PoolParty", "Flags threads executing from unbacked memory, the footprint of thread-pool hijacking", "ON DEMAND"),
            ];

            for (title, desc, status) in detectors {
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
                                ui.label(RichText::new(status).size(11.0).monospace().strong().color(STATUS_GREEN));
                            });
                        });
                    });
                ui.add_space(6.0);
            }

            ui.add_space(14.0);

            // Audit Telemetry Log
            ui.label(RichText::new("AUDIT TELEMETRY STREAM").size(13.0).strong().color(TEXT_PRIMARY));
            ui.add_space(8.0);

            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(egui::Margin::same(16.0))
                .show(ui, |ui| {
                    if self.memory_alerts.is_empty() {
                        ui.label(RichText::new("Click 'Run Memory Audit' above to audit live running processes for in-memory evasion.").size(12.0).color(TEXT_MUTED));
                    } else {
                        for alert in &self.memory_alerts {
                            ui.label(RichText::new(alert).size(11.0).monospace().color(STATUS_GREEN));
                            ui.add_space(4.0);
                        }
                    }
                });
        });
    }
}
