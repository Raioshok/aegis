use eframe::egui::{self, RichText};
use crate::app::AegisApp;
use crate::theme::*;

impl AegisApp {
    pub fn view_quarantine(&mut self, ui: &mut egui::Ui) {
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
                            ui.label(RichText::new("CHACHA20-POLY1305 QUARANTINE VAULT").size(15.0).strong().color(TEXT_PRIMARY));
                            ui.label(RichText::new("Neutralized threats are isolated into self-describing encrypted blobs with verified SHA-256 integrity").size(12.0).color(TEXT_SECONDARY));
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button(RichText::new("Refresh Vault").size(12.0)).clicked() {
                                self.refresh_quarantine();
                            }
                        });
                    });
                });

            ui.add_space(16.0);

            // Table of Quarantined Files
            ui.horizontal(|ui| {
                ui.label(RichText::new("ENCRYPTED VAULT INVENTORY").size(13.0).strong().color(TEXT_PRIMARY));
                ui.label(RichText::new(format!("({} records)", self.quarantine_records.len())).size(13.0).monospace().color(TEXT_MUTED));
            });
            ui.add_space(8.0);

            if self.quarantine_records.is_empty() {
                egui::Frame::none()
                    .fill(CARD_BG)
                    .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                    .rounding(egui::Rounding::same(6.0))
                    .inner_margin(egui::Margin::symmetric(16.0, 24.0))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("Quarantine vault is empty. No files currently isolated.").size(12.0).color(TEXT_MUTED));
                        });
                    });
            } else {
                let mut restore_sha = None;
                let mut delete_sha = None;

                for rec in &self.quarantine_records {
                    egui::Frame::none()
                        .fill(CARD_BG)
                        .stroke(egui::Stroke::new(1.0_f32, BORDER_COLOR))
                        .rounding(egui::Rounding::same(6.0))
                        .inner_margin(egui::Margin::symmetric(16.0, 12.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(&rec.threat).size(13.0).strong().color(STATUS_RED));
                                        ui.label(RichText::new("·").size(11.0).color(TEXT_MUTED));
                                        ui.label(RichText::new(format!("Size: {:.1} KB", rec.size as f64 / 1024.0)).size(11.0).monospace().color(TEXT_SECONDARY));
                                    });
                                    ui.add_space(2.0);
                                    ui.label(RichText::new(&rec.original_path).size(11.0).monospace().color(TEXT_SECONDARY));
                                    ui.label(RichText::new(format!("SHA256: {}", rec.sha256)).size(10.0).monospace().color(TEXT_MUTED));
                                });

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(RichText::new("Purge").size(11.0).color(STATUS_RED)).clicked() {
                                        delete_sha = Some(rec.sha256.clone());
                                    }
                                    ui.add_space(6.0);
                                    if ui.button(RichText::new("Restore").size(11.0)).clicked() {
                                        restore_sha = Some(rec.sha256.clone());
                                    }
                                });
                            });
                        });
                    ui.add_space(6.0);
                }

                if let Some(sha) = restore_sha {
                    if let Some(ref db) = self.db {
                        if let Ok(q) = aegis_quarantine::Quarantine::open(db) {
                            match q.restore(&sha) {
                                Ok(p) => self.set_status(&format!("Restored to {}", p.display())),
                                Err(e) => self.set_status(&format!("Restore failed: {}", e)),
                            }
                            self.refresh_quarantine();
                        }
                    }
                }

                if let Some(sha) = delete_sha {
                    if let Some(ref db) = self.db {
                        if let Ok(q) = aegis_quarantine::Quarantine::open(db) {
                            match q.delete(&sha) {
                                Ok(_) => self.set_status(&format!("Permanently purged from vault")),
                                Err(e) => self.set_status(&format!("Delete failed: {}", e)),
                            }
                            self.refresh_quarantine();
                        }
                    }
                }
            }
        });
    }
}
