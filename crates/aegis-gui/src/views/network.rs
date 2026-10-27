use eframe::egui::{self, RichText};
use crate::app::AegisApp;
use crate::theme::*;

impl AegisApp {
    pub fn view_network(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // Header
            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(20.0, 16.0))
                .show(ui, |ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("NETWORK DEFENSE & GATEWAY TELEMETRY").size(15.0).strong().color(TEXT_PRIMARY));
                        ui.label(RichText::new("Aegis Telemetry Training Gateway on port 9090 and active connection auditing").size(12.0).color(TEXT_SECONDARY));
                    });
                });

            ui.add_space(16.0);

            // Gateway Status Card
            egui::Frame::none()
                .fill(CARD_BG)
                .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                .rounding(egui::Rounding::same(6.0))
                .inner_margin(egui::Margin::symmetric(20.0, 16.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("TELEMETRY TRAINING GATEWAY").size(13.0).strong().color(TEXT_PRIMARY));
                            ui.label(RichText::new("Listening: http://127.0.0.1:9090 · http://172.18.32.1:9090 (WSL / Guest VM sync)").size(11.0).monospace().color(TEXT_SECONDARY));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new("ONLINE · LISTENING").size(11.0).monospace().strong().color(STATUS_GREEN));
                        });
                    });
                });

            ui.add_space(16.0);

            // Firewall Shields
            ui.label(RichText::new("NETWORK CHECKS").size(13.0).strong().color(TEXT_PRIMARY));
            ui.add_space(8.0);

            let net_shields = [
                ("C2 / Botnet IP Matching", "Matches open connections against your IP blocklist and the synced Feodo Tracker feed", "ON SCAN"),
            ];

            for (title, desc, status) in net_shields {
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
        });
    }
}
