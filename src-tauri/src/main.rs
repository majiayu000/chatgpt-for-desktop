#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

fn main() {
  tauri::Builder::default()
    .plugin(tauri_plugin_http::init())
    .setup(|_app| {
      // 简单的设置
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

