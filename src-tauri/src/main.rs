#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use tauri::{Manager, WindowEvent};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{TrayIconBuilder, MouseButton, MouseButtonState, TrayIconEvent};

fn main() {
  tauri::Builder::default()
    .plugin(tauri_plugin_http::init())
    .setup(|app| {

      // 创建菜单项
      let quit_item = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
      let show_item = MenuItem::with_id(app, "show", "显示", true, None::<&str>)?;
      let hide_item = MenuItem::with_id(app, "hide", "隐藏", true, None::<&str>)?;
      let gemini_item = MenuItem::with_id(app, "gemini", "切换到 Gemini", true, None::<&str>)?;
      let poe_item = MenuItem::with_id(app, "poe", "切换到 Poe", true, None::<&str>)?;

      // 创建菜单
      let menu = Menu::with_items(app, &[&show_item, &hide_item, &gemini_item, &poe_item, &quit_item])?;

      // 创建系统托盘
      let tray = TrayIconBuilder::new()
        .icon(app.default_window_icon().unwrap().clone()) // 使用应用默认图标
        .menu(&menu)
        .tooltip("Gemini Desktop")
        .on_menu_event(|app, event| match event.id.as_ref() {
          "quit" => {
            app.exit(0);
          }
          "show" => {
            // 显示当前活动的窗口
            if let Some(window) = app.get_webview_window("gemini") {
              if window.is_visible().unwrap_or(false) {
                let _ = window.show();
                let _ = window.set_focus();
              }
            }
            if let Some(window) = app.get_webview_window("poe") {
              if window.is_visible().unwrap_or(false) {
                let _ = window.show();
                let _ = window.set_focus();
              }
            }
          }
          "hide" => {
            // 隐藏所有窗口
            if let Some(window) = app.get_webview_window("gemini") {
              if window.is_visible().unwrap_or(false) {
                let _ = window.hide();
              }
            }
            if let Some(window) = app.get_webview_window("poe") {
              if window.is_visible().unwrap_or(false) {
                let _ = window.hide();
              }
            }
          }
          "gemini" => {
            // 切换到 Gemini
            if let Some(window) = app.get_webview_window("poe") {
              let _ = window.hide();
            }
            if let Some(window) = app.get_webview_window("gemini") {
              let _ = window.show();
              let _ = window.set_focus();
            }
          }
          "poe" => {
            // 切换到 Poe
            if let Some(window) = app.get_webview_window("gemini") {
              let _ = window.hide();
            }
            if let Some(window) = app.get_webview_window("poe") {
              let _ = window.show();
              let _ = window.set_focus();
            }
          }
          _ => {}
        })
        .on_tray_icon_event(|tray, event| match event {
          TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
          } => {
            // 点击托盘图标时切换窗口显示状态
            let app = tray.app_handle();

            // 检查 Gemini 窗口
            let gemini_visible = if let Some(window) = app.get_webview_window("gemini") {
              window.is_visible().unwrap_or(false)
            } else {
              false
            };

            // 检查 Poe 窗口
            let poe_visible = if let Some(window) = app.get_webview_window("poe") {
              window.is_visible().unwrap_or(false)
            } else {
              false
            };

            // 如果两个窗口都不可见，则显示 Gemini
            if !gemini_visible && !poe_visible {
              if let Some(window) = app.get_webview_window("gemini") {
                let _ = window.show();
                let _ = window.set_focus();
              }
            }
            // 如果 Gemini 可见，则隐藏它
            else if gemini_visible {
              if let Some(window) = app.get_webview_window("gemini") {
                let _ = window.hide();
              }
            }
            // 如果 Poe 可见，则隐藏它
            else if poe_visible {
              if let Some(window) = app.get_webview_window("poe") {
                let _ = window.hide();
              }
            }
          }
          _ => {}
        })
        .build(app)?;

      Ok(())
    })
    .on_window_event(|app, event| {
      if let WindowEvent::CloseRequested { api, .. } = event {
        // 当用户点击关闭按钮时，隐藏窗口而不是退出应用
        // 隐藏所有窗口
        if let Some(window) = app.get_webview_window("gemini") {
          if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
          }
        }
        if let Some(window) = app.get_webview_window("poe") {
          if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
          }
        }
        api.prevent_close();
      }
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
