use tauri::{plugin::Plugin, Runtime};

pub struct WebviewHandler;

impl<R: Runtime> Plugin<R> for WebviewHandler {
    fn name(&self) -> &'static str {
        "webview-handler"
    }

    fn initialization_script(&self) -> Option<String> {
        // Use the embedded script
        Some(include_str!("init_script.js").to_string())
    }
}
