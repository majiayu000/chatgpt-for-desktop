use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// OS keychain service name (matches Tauri app identifier).
const KEYRING_SERVICE: &str = "com.lif.ai.assistant";

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub service: String,
}

fn legacy_credentials_path(service: &str) -> PathBuf {
    PathBuf::from("credentials").join(format!("{}.json", service))
}

fn keyring_entry(service: &str) -> Result<Entry, String> {
    Entry::new(KEYRING_SERVICE, service).map_err(|e| e.to_string())
}

fn remove_legacy_file(service: &str) -> Result<(), String> {
    let path = legacy_credentials_path(service);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Read a legacy plaintext `credentials/{service}.json` file, if present.
pub fn read_legacy_credentials_file(service: &str) -> Result<Option<Credentials>, String> {
    let path = legacy_credentials_path(service);
    if !Path::new(&path).exists() {
        return Ok(None);
    }
    let json = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let credentials: Credentials = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    Ok(Some(credentials))
}

/// Store credentials in the OS keychain and remove any leftover plaintext file.
pub fn save_credentials(service: &str, username: &str, password: &str) -> Result<(), String> {
    let credentials = Credentials {
        username: username.to_string(),
        password: password.to_string(),
        service: service.to_string(),
    };
    let json = serde_json::to_string(&credentials).map_err(|e| e.to_string())?;
    let entry = keyring_entry(service)?;
    entry.set_password(&json).map_err(|e| e.to_string())?;
    remove_legacy_file(service)?;
    Ok(())
}

/// Load credentials from the keychain. If missing, one-time migrate from legacy JSON
/// then delete the plaintext file.
pub fn get_credentials(service: &str) -> Result<Option<Credentials>, String> {
    let entry = keyring_entry(service)?;
    match entry.get_password() {
        Ok(json) => {
            let credentials: Credentials = serde_json::from_str(&json).map_err(|e| e.to_string())?;
            // Surface leftover-plaintext cleanup failures so migration cannot leave
            // credentials/{service}.json on disk indefinitely after a keychain hit.
            remove_legacy_file(service)?;
            Ok(Some(credentials))
        }
        Err(keyring::Error::NoEntry) => {
            if let Some(mut legacy) = read_legacy_credentials_file(service)? {
                // Always migrate and clean up under the requested service key.
                // If the embedded service differs (copied/renamed file), normalize it
                // so we do not leave the requested plaintext file behind or overwrite
                // an unrelated keychain entry.
                if legacy.service != service {
                    legacy.service = service.to_string();
                }
                save_credentials(service, &legacy.username, &legacy.password)?;
                Ok(Some(legacy))
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Delete any leftover plaintext credentials file, then the keychain entry.
///
/// Legacy plaintext is removed first so a failed file delete cannot leave a
/// migration source that resurrects credentials after the keychain entry is gone.
pub fn delete_credentials(service: &str) -> Result<(), String> {
    remove_legacy_file(service)?;
    let entry = keyring_entry(service)?;
    match entry.delete_credential() {
        Ok(()) => {}
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Serialize tests that touch the working directory / credentials folder.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_temp_cwd<F: FnOnce()>(f: F) {
        let _guard = TEST_LOCK.lock().unwrap();
        let original = env::current_dir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        env::set_current_dir(tmp.path()).unwrap();
        f();
        env::set_current_dir(original).unwrap();
    }

    #[test]
    fn read_legacy_credentials_parses_and_reports_missing() {
        with_temp_cwd(|| {
            assert_eq!(read_legacy_credentials_file("gemini").unwrap(), None);

            fs::create_dir_all("credentials").unwrap();
            let sample = Credentials {
                username: "user@example.com".into(),
                password: "s3cret".into(),
                service: "gemini".into(),
            };
            fs::write(
                "credentials/gemini.json",
                serde_json::to_string(&sample).unwrap(),
            )
            .unwrap();

            let loaded = read_legacy_credentials_file("gemini").unwrap().unwrap();
            assert_eq!(loaded, sample);
        });
    }

    #[test]
    fn remove_legacy_file_deletes_plaintext() {
        with_temp_cwd(|| {
            fs::create_dir_all("credentials").unwrap();
            fs::write("credentials/poe.json", r#"{"username":"a","password":"b","service":"poe"}"#)
                .unwrap();
            assert!(Path::new("credentials/poe.json").exists());
            remove_legacy_file("poe").unwrap();
            assert!(!Path::new("credentials/poe.json").exists());
        });
    }

    #[test]
    fn read_legacy_keeps_requested_path_even_when_embedded_service_differs() {
        with_temp_cwd(|| {
            fs::create_dir_all("credentials").unwrap();
            fs::write(
                "credentials/gemini.json",
                r#"{"username":"u","password":"p","service":"other"}"#,
            )
            .unwrap();
            let loaded = read_legacy_credentials_file("gemini").unwrap().unwrap();
            assert_eq!(loaded.service, "other");
            // Callers must migrate under the requested path key ("gemini"), not
            // the embedded value — exercised by get_credentials normalization.
            assert!(Path::new("credentials/gemini.json").exists());
            assert!(!Path::new("credentials/other.json").exists());
        });
    }
}
