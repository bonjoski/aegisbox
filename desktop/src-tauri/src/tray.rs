use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIcon, TrayIconBuilder},
    AppHandle, Manager,
};

pub fn setup_tray(app: &AppHandle) -> Result<TrayIcon, tauri::Error> {
    let status_item = MenuItem::with_id(app, "status", "Aegisbox: MicroVM Active", false, None::<&str>)?;
    let sep1 = tauri::menu::PredefinedMenuItem::separator(app)?;
    
    let tier2_item = MenuItem::with_id(app, "tier2", "🟢 MicroVM Hardened (Tier 2)", true, None::<&str>)?;
    let tier1_item = MenuItem::with_id(app, "tier1", "🟡 Standard Sandbox (Tier 1)", true, None::<&str>)?;
    let tier0_item = MenuItem::with_id(app, "tier0", "⚪ Permissive Mode (Tier 0)", true, None::<&str>)?;
    let sep2 = tauri::menu::PredefinedMenuItem::separator(app)?;

    let show_item = MenuItem::with_id(app, "show", "Show Cockpit Window", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit Aegisbox", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &status_item,
            &sep1,
            &tier2_item,
            &tier1_item,
            &tier0_item,
            &sep2,
            &show_item,
            &quit_item,
        ],
    )?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .show_menu_on_left_click(true);

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder
        .on_menu_event(|app, event| match event.id.as_ref() {
            "tier2" => {
                println!("[Tray] Selected Tier 2 (MicroVM Hardened)");
            }
            "tier1" => {
                println!("[Tray] Selected Tier 1 (Airlock Standard)");
            }
            "tier0" => {
                println!("[Tray] Selected Tier 0 (Permissive)");
            }
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .build(app)
}
