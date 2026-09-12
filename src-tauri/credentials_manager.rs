use serde::{Serialize, Deserialize};
use std::fs;
use std::path::{Path, PathBuf};

const ALLOWED_CREDENTIAL_SERVICES: &[&str] = &["gemini", "poe"];

/// Allowlist credential `service` names used for filesystem paths.
/// Rejects empty values, path separators, `..`, and anything outside the known UI services.
fn validate_service_name(service: &str) -> Result<&str, String> {
    if service.is_empty() {
        return Err("Invalid service name: empty".to_string());
    }
    if service.contains('/') || service.contains('\\') || service.contains("..") {
        return Err("Invalid service name: path characters not allowed".to_string());
    }
    if !ALLOWED_CREDENTIAL_SERVICES.contains(&service) {
        return Err(format!("Unsupported service: {}", service));
    }
    Ok(service)
}

/// Build a path under a fixed `credentials/` base with canonicalize + prefix containment.
fn credentials_file_path(service: &str) -> Result<PathBuf, String> {
    let service = validate_service_name(service)?;

    fs::create_dir_all("credentials").map_err(|e| e.to_string())?;

    let base = Path::new("credentials")
        .canonicalize()
        .map_err(|e| format!("Failed to resolve credentials directory: {}", e))?;

    let path = base.join(format!("{}.json", service));

    if path.exists() {
        let canonical = path
            .canonicalize()
            .map_err(|e| format!("Failed to resolve credentials path: {}", e))?;
        if !canonical.starts_with(&base) {
            return Err("Path traversal detected".to_string());
        }
        Ok(canonical)
    } else {
        if path.parent() != Some(base.as_path()) {
            return Err("Path traversal detected".to_string());
        }
        Ok(path)
    }
}

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
    let path = credentials_file_path(service)?;

    let credentials = Credentials {
        username: username.to_string(),
        password: password.to_string(),
        service: service.to_string(),
    };

    let json = serde_json::to_string(&credentials).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())?;

    Ok(())
}

// 获取凭证
pub fn get_credentials(
    service: &str,
) -> Result<Option<Credentials>, String> {
    let path = credentials_file_path(service)?;

    if !path.exists() {
        return Ok(None);
    }

    let json = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let credentials: Credentials = serde_json::from_str(&json).map_err(|e| e.to_string())?;

    Ok(Some(credentials))
}

// 删除凭证
pub fn delete_credentials(
    service: &str,
) -> Result<(), String> {
    let path = credentials_file_path(service)?;

    if path.exists() {
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
    validate_service_name(service)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_service_name_accepts_allowed() {
        assert_eq!(validate_service_name("gemini").unwrap(), "gemini");
        assert_eq!(validate_service_name("poe").unwrap(), "poe");
    }

    #[test]
    fn validate_service_name_rejects_traversal() {
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name("../../tmp/evil").is_err());
        assert!(validate_service_name("foo/bar").is_err());
    }
}
