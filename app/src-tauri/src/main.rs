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
            commands::list_whitelist,
            commands::add_whitelist,
            commands::remove_whitelist,
            commands::rootkit_scan,
            commands::memory_scan,
            commands::network_scan,
            commands::plugins_list,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aegis");
}
