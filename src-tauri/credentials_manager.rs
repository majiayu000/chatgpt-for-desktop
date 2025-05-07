use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

// 定义凭证结构体
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub service: String,
}

// 保存凭证
pub fn save_credentials(
    service: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
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
pub fn get_credentials(
    service: &str,
) -> Result<Option<Credentials>, String> {
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
pub fn delete_credentials(
    service: &str,
) -> Result<(), String> {
    let path = format!("credentials/{}.json", service);
    
    // 检查文件是否存在
    if Path::new(&path).exists() {
        // 删除文件
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    
    Ok(())
}

// 生成自动登录脚本
pub fn generate_login_script(
    service: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    // 根据服务类型执行不同的登录脚本
    let script = match service {
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
        _ => return Err("不支持的服务类型".to_string()),
    };
    
    Ok(script)
}
