mod commands;
pub mod ipc_client;
mod tray;

use commands::approvals::{list_pending_approvals, submit_approval_decision};
use commands::profiles::{get_active_profile, set_active_profile};
use commands::telemetry::{check_daemon_status, get_live_events, get_telemetry_snapshot};

#[cfg(target_os = "macos")]
extern "C" {
    fn aegisbox_set_dock_icon(bytes: *const u8, len: usize);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            #[cfg(target_os = "macos")]
            // SAFETY: Valid static byte slice and safe Cocoa image conversion
            unsafe { // SAFETY: ICON_BYTES is valid for program lifetime and Cocoa image conversion is memory safe
                const ICON_BYTES: &[u8] = include_bytes!("../icons/icon.png");
                aegisbox_set_dock_icon(ICON_BYTES.as_ptr(), ICON_BYTES.len());
            }

            #[cfg(desktop)]
            {
                let _ = tray::setup_tray(app.handle());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            submit_approval_decision,
            list_pending_approvals,
            get_active_profile,
            set_active_profile,
            get_telemetry_snapshot,
            get_live_events,
            check_daemon_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running aegisbox desktop application");
}
