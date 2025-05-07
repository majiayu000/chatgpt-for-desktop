#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use tauri::{Manager, WindowEvent};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;
use std::io::Read;

// 定义应用状态结构体
struct AppState {
    // 跟踪窗口是否处于前台
    gemini_focused: bool,
    poe_focused: bool,
    settings_focused: bool,
    // 跟踪上次点击托盘图标的时间
    last_tray_click_time: Instant,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            gemini_focused: false,
            poe_focused: false,
            settings_focused: false,
            last_tray_click_time: Instant::now(),
        }
    }
}

// 定义凭证结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Credentials {
    username: String,
    password: String,
    service: String,
}

// 保存凭证
fn save_credentials_to_file(service: &str, username: &str, password: &str) -> Result<(), String> {
    // 简单地将凭证保存到文件中
    let credentials = Credentials {
        username: username.to_string(),
        password: password.to_string(),
        service: service.to_string(),
    };

    let json = serde_json::to_string(&credentials).map_err(|e| e.to_string())?;

    // 创建目录（如果不存在）
    fs::create_dir_all("credentials").map_err(|e| e.to_string())?;

    // 保存到文件
    fs::write(format!("credentials/{}.json", service), json).map_err(|e| e.to_string())?;

    Ok(())
}

// 获取凭证
fn get_credentials_from_file(service: &str) -> Result<Option<Credentials>, String> {
    let path = format!("credentials/{}.json", service);

    // 检查文件是否存在
    if !Path::new(&path).exists() {
        return Ok(None);
    }

    // 读取文件
    let json = fs::read_to_string(path).map_err(|e| e.to_string())?;

    // 解析 JSON
    let credentials: Credentials = serde_json::from_str(&json).map_err(|e| e.to_string())?;

    Ok(Some(credentials))
}

// 删除凭证
fn delete_credentials_from_file(service: &str) -> Result<(), String> {
    let path = format!("credentials/{}.json", service);

    // 检查文件是否存在
    if Path::new(&path).exists() {
        // 删除文件
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }

    Ok(())
}

// 生成自动登录脚本
fn generate_login_script(service: &str, username: &str, password: &str) -> String {
    match service {
        "gemini" => format!(
            r#"
            (function() {{
                // 检查是否有登录表单
                const emailInput = document.querySelector('input[type="email"]');
                const passwordInput = document.querySelector('input[type="password"]');
                const loginButton = document.querySelector('button[type="submit"]');

                if (emailInput && passwordInput && loginButton) {{
                    // 填充凭证
                    emailInput.value = "{}";
                    passwordInput.value = "{}";

                    // 点击登录按钮
                    setTimeout(() => {{
                        loginButton.click();
                    }}, 500);

                    return true;
                }}
                return false;
            }})()
            "#,
            username, password
        ),
        "poe" => format!(
            r#"
            (function() {{
                // 检查是否有登录表单
                const emailInput = document.querySelector('input[name="email"]');
                const passwordInput = document.querySelector('input[name="password"]');
                const loginButton = document.querySelector('button[type="submit"]');

                if (emailInput && passwordInput && loginButton) {{
                    // 填充凭证
                    emailInput.value = "{}";
                    passwordInput.value = "{}";

                    // 点击登录按钮
                    setTimeout(() => {{
                        loginButton.click();
                    }}, 500);

                    return true;
                }}
                return false;
            }})()
            "#,
            username, password
        ),
        _ => String::from("console.log('不支持的服务类型');"),
    }
}

// 定义命令：保存凭证
#[tauri::command]
fn save_credentials(service: String, username: String, password: String) -> Result<(), String> {
    save_credentials_to_file(&service, &username, &password)
}

// 定义命令：获取凭证
#[tauri::command]
fn get_credentials(service: String) -> Result<Option<Credentials>, String> {
    get_credentials_from_file(&service)
}

// 定义命令：删除凭证
#[tauri::command]
fn delete_credentials(service: String) -> Result<(), String> {
    delete_credentials_from_file(&service)
}

// 加载浏览器模拟脚本
fn load_browser_emulation_script() -> Result<String, String> {
    // 尝试从当前目录加载
    let mut path = "browser_emulation.js".to_string();

    // 如果当前目录不存在，尝试从 src-tauri 目录加载
    if !Path::new(&path).exists() {
        path = "src-tauri/browser_emulation.js".to_string();
    }

    // 如果 src-tauri 目录也不存在，返回错误
    if !Path::new(&path).exists() {
        return Err(format!("找不到浏览器模拟脚本文件: {}", path));
    }

    let mut file = fs::File::open(&path).map_err(|e| e.to_string())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| e.to_string())?;
    Ok(contents)
}

// 定义命令：自动登录
#[tauri::command]
fn auto_login(window: tauri::WebviewWindow, service: String) -> Result<bool, String> {
    // 获取凭证
    if let Ok(Some(creds)) = get_credentials_from_file(&service) {
        // 生成登录脚本
        let script = generate_login_script(&service, &creds.username, &creds.password);

        // 执行登录脚本
        if let Err(e) = window.eval(&script) {
            return Err(e.to_string());
        }

        Ok(true)
    } else {
        // 没有保存的凭证
        Ok(false)
    }
}

// 注入浏览器模拟脚本
#[tauri::command]
fn inject_browser_emulation(window: tauri::WebviewWindow) -> Result<bool, String> {
    // 加载浏览器模拟脚本
    let script = load_browser_emulation_script()?;

    // 执行脚本
    if let Err(e) = window.eval(&script) {
        return Err(e.to_string());
    }

    Ok(true)
}

fn main() {
  tauri::Builder::default()
    .plugin(tauri_plugin_http::init())
    .manage(Mutex::new(AppState::default()))
    .invoke_handler(tauri::generate_handler![
      save_credentials,
      get_credentials,
      delete_credentials,
      auto_login,
      inject_browser_emulation
    ])
    .setup(|app| {
      // 创建菜单项
      let quit_item = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
      let show_item = MenuItem::with_id(app, "show", "显示", true, None::<&str>)?;
      let hide_item = MenuItem::with_id(app, "hide", "隐藏", true, None::<&str>)?;
      let gemini_item = MenuItem::with_id(app, "gemini", "切换到 Gemini", true, None::<&str>)?;
      let poe_item = MenuItem::with_id(app, "poe", "切换到 Poe", true, None::<&str>)?;
      let settings_item = MenuItem::with_id(app, "settings", "设置", true, None::<&str>)?;

      // 创建菜单
      let menu = Menu::with_items(app, &[&show_item, &hide_item, &gemini_item, &poe_item, &settings_item, &quit_item])?;

      // 创建系统托盘
      let _tray = TrayIconBuilder::new()
        .icon(app.default_window_icon().unwrap().clone()) // 使用应用默认图标
        .menu(&menu)
        .tooltip("AI Assistant")
        .build(app)?;

      // 为 Gemini 窗口添加事件处理
      if let Some(window) = app.get_webview_window("gemini") {
        let window_clone = window.clone();
        let app_handle = app.app_handle().clone();

        window.on_window_event(move |event| {
          match event {
            WindowEvent::Focused(focused) => {
              // 更新窗口焦点状态
              if let Ok(mut state) = app_handle.state::<Mutex<AppState>>().try_lock() {
                state.gemini_focused = *focused;
              }

              // 如果窗口获得焦点，尝试自动登录
              if *focused {
                let window_clone2 = window_clone.clone();
                std::thread::spawn(move || {
                  // 等待一段时间，确保页面完全加载
                  std::thread::sleep(std::time::Duration::from_secs(2));

                  // 注入浏览器模拟脚本
                  let _ = inject_browser_emulation(window_clone2.clone());

                  // 尝试自动登录
                  let _ = auto_login(window_clone2, "gemini".to_string());
                });
              }
            },
            _ => {}
          }
        });
      }

      // 设置菜单事件处理程序
      let app_handle_clone = app.app_handle().clone();
      app.on_menu_event(move |_window, event| {
        let id = &event.id().0;  // Access the inner String field of MenuId
        let app_handle = app_handle_clone.clone();

        match id.as_str() {
            "quit" => {
              app_handle.exit(0);
            }
            "show" => {
              // 显示 Gemini 窗口
              if let Some(window) = app_handle.get_webview_window("gemini") {
                let _ = window.show();
                let _ = window.set_focus();
              }
            }
            "hide" => {
              // 隐藏所有窗口
              if let Some(window) = app_handle.get_webview_window("gemini") {
                let _ = window.hide();
              }
              if let Some(window) = app_handle.get_webview_window("poe") {
                let _ = window.hide();
              }
            }
            "gemini" => {
              // 切换到 Gemini
              if let Some(window) = app_handle.get_webview_window("poe") {
                let _ = window.hide();
              }
              if let Some(window) = app_handle.get_webview_window("gemini") {
                let _ = window.show();
                let _ = window.set_focus();
              }
            }
            "poe" => {
              // 切换到 Poe
              if let Some(window) = app_handle.get_webview_window("gemini") {
                let _ = window.hide();
              }

              // 检查 Poe 窗口是否存在
              if let Some(window) = app_handle.get_webview_window("poe") {
                let _ = window.show();
                let _ = window.set_focus();
              } else {
                // 如果 Poe 窗口不存在，则创建它
                let user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

                let poe_url = tauri::WebviewUrl::External(tauri::Url::parse("https://poe.com").expect("Invalid URL"));
                if let Ok(window) = tauri::WebviewWindow::builder(&app_handle, "poe", poe_url)
                  .title("Poe")
                  .resizable(true)
                  .fullscreen(false)
                  .inner_size(1440.0, 1080.0)
                  .user_agent(user_agent)
                  .additional_browser_args("--disable-blink-features=AutomationControlled --disable-features=IsolateOrigins,site-per-process --disable-site-isolation-trials --disable-web-security --allow-running-insecure-content --disable-blink-features=AutomationControlled")
                  .build() {

                  let _ = window.set_focus();

                  // 添加页面加载完成事件监听器，用于自动登录和跟踪焦点
                  let window_clone = window.clone();
                  let app_handle_poe = app_handle.clone();

                  window.on_window_event(move |event| {
                    match event {
                      WindowEvent::Focused(focused) => {
                        // 更新窗口焦点状态
                        if let Ok(mut state) = app_handle_poe.state::<Mutex<AppState>>().try_lock() {
                          state.poe_focused = *focused;
                        }

                        // 如果窗口获得焦点，尝试自动登录
                        if *focused {
                          let window_clone2 = window_clone.clone();
                          std::thread::spawn(move || {
                            // 等待一段时间，确保页面完全加载
                            std::thread::sleep(std::time::Duration::from_secs(2));

                            // 注入浏览器模拟脚本
                            let _ = inject_browser_emulation(window_clone2.clone());

                            // 尝试自动登录
                            let _ = auto_login(window_clone2, "poe".to_string());
                          });
                        }
                      },
                      _ => {}
                    }
                  });
                }
              }
            }
            "settings" => {
              // 打开设置窗口
              if let Some(window) = app_handle.get_webview_window("settings") {
                let _ = window.show();
                let _ = window.set_focus();
              } else {
                // 如果设置窗口不存在，则创建它
                let settings_url = tauri::WebviewUrl::App("settings.html".to_string().into());
                if let Ok(window) = tauri::WebviewWindow::builder(&app_handle, "settings", settings_url)
                  .title("AI Assistant 设置")
                  .resizable(true)
                  .fullscreen(false)
                  .inner_size(800.0, 600.0)
                  .build() {

                  let _ = window.set_focus();

                  // 添加焦点事件监听器
                  let app_handle_settings = app_handle.clone();
                  window.on_window_event(move |event| {
                    if let WindowEvent::Focused(focused) = event {
                      // 更新窗口焦点状态
                      if let Ok(mut state) = app_handle_settings.state::<Mutex<AppState>>().try_lock() {
                        state.settings_focused = *focused;
                      }
                    }
                  });
                }
              }
            }
            _ => {}
          }
      });

      // 设置托盘图标点击事件处理程序
      let app_handle_clone = app.app_handle().clone();

      app.on_tray_icon_event(move |_tray, event| {
        // 只处理左键点击事件
        if let tauri::tray::TrayIconEvent::Click { button, .. } = event {
          // 只处理左键点击
          if button == tauri::tray::MouseButton::Left {
            let app_handle = app_handle_clone.clone();

            // 获取应用状态
            let mut is_double_click = false;
            let mut gemini_focused = false;
            let mut poe_focused = false;
            let mut settings_focused = false;

            // 获取状态并检查是否是双击
            if let Ok(mut state) = app_handle.state::<Mutex<AppState>>().try_lock() {
              let now = Instant::now();
              is_double_click = now.duration_since(state.last_tray_click_time).as_millis() < 300;
              state.last_tray_click_time = now;

              gemini_focused = state.gemini_focused;
              poe_focused = state.poe_focused;
              settings_focused = state.settings_focused;
            }

            // 获取所有窗口
            let gemini_window = app_handle.get_webview_window("gemini");
            let poe_window = app_handle.get_webview_window("poe");
            let settings_window = app_handle.get_webview_window("settings");

            // 检查是否有任何窗口可见
            let gemini_visible = gemini_window.as_ref().map(|w| w.is_visible().unwrap_or(false)).unwrap_or(false);
            let poe_visible = poe_window.as_ref().map(|w| w.is_visible().unwrap_or(false)).unwrap_or(false);
            let settings_visible = settings_window.as_ref().map(|w| w.is_visible().unwrap_or(false)).unwrap_or(false);

            let any_window_visible = gemini_visible || poe_visible || settings_visible;

            if !any_window_visible {
              // 如果没有窗口可见，则显示 Gemini 窗口
              if let Some(window) = gemini_window {
                let _ = window.show();
                let _ = window.set_focus();
              }
            }
            // 如果有窗口可见但没有窗口在前台，或者是双击，则隐藏所有窗口
            else if !gemini_focused && !poe_focused && !settings_focused || is_double_click {
              // 隐藏所有可见窗口
              if gemini_visible {
                if let Some(window) = gemini_window {
                  let _ = window.hide();
                }
              }

              if poe_visible {
                if let Some(window) = poe_window {
                  let _ = window.hide();
                }
              }

              if settings_visible {
                if let Some(window) = settings_window {
                  let _ = window.hide();
                }
              }
            }
            // 如果有窗口可见且有窗口在前台，则将窗口置于前台
            else {
              // 将可见窗口置于前台
              if gemini_visible {
                if let Some(window) = gemini_window {
                  let _ = window.set_focus();
                }
              } else if poe_visible {
                if let Some(window) = poe_window {
                  let _ = window.set_focus();
                }
              } else if settings_visible {
                if let Some(window) = settings_window {
                  let _ = window.set_focus();
                }
              }
            }
          }
        }
      });

      Ok(())
    })
    .on_window_event(|window, event| {
      if let WindowEvent::CloseRequested { api, .. } = event {
        // 当用户点击关闭按钮时，隐藏窗口而不是退出应用
        let _ = window.hide();
        api.prevent_close();
      }
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
