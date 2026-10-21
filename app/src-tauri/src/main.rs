// Prevent a second console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use commands::AppState;

fn main() {
    let state = AppState::new().expect("failed to initialise Aegis state");

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::dashboard,
            commands::run_scan,
            commands::list_history,
            commands::list_threats,
            commands::list_quarantine,
            commands::quarantine_action,
            commands::quarantine_file,
            commands::list_whitelist,
            commands::add_whitelist,
            commands::remove_whitelist,
            commands::rootkit_scan,
            commands::memory_scan,
            commands::network_scan,
            commands::plugins_list,
            commands::optimize_scan,
            commands::toggle_autostart,
            commands::is_autostart_active,
            commands::list_processes,
            commands::kill_process,
            commands::inspect_process_memory,
            commands::security_audit,
            commands::sync_threat_feeds,
            commands::deploy_ransomware_honeypot,
            commands::get_protection_config,
            commands::set_protection_config,
            commands::get_game_mode_status,
            commands::toggle_game_mode,
            commands::get_scan_progress,
            commands::get_smart_scan_target,
            commands::scan_android_package,
            commands::get_gateway_stats,
            commands::get_process_dag_snapshot,
            commands::get_process_lineage_alerts,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aegis");
}
