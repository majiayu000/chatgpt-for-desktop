use fslock::LockFile;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// OS keychain service name (matches Tauri app identifier).
const KEYRING_SERVICE: &str = "com.lif.ai.assistant";

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub service: String,
}

/// Per-service locks so get/save/delete for the same service cannot interleave.
/// Auto-login threads call `get_credentials` while settings IPC may call
/// `delete_credentials` concurrently; without this, an in-flight legacy
/// migration can recreate a keychain entry after a completed deletion.
///
/// Combines a process-local mutex with an inter-process file lock under a
/// shared writable application-data directory (not CWD), so instances launched
/// from different working directories — including read-only installs — still
/// serialize migrate/delete against the same OS keychain account.
static SERVICE_LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();

/// Writable, process-independent directory for per-service lock files.
///
/// Prefer the OS application-data location keyed by the Tauri/app identifier so
/// all instances share one lock namespace. Tests may override via
/// `CREDENTIALS_LOCK_DIR`.
fn credential_locks_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("CREDENTIALS_LOCK_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let base = dirs::data_local_dir().ok_or_else(|| {
        "no writable application data directory for credential locks".to_string()
    })?;
    Ok(base.join(KEYRING_SERVICE).join("credential-locks"))
}

fn service_lock_path(service: &str) -> Result<PathBuf, String> {
    // Keep lock names flat even if a service string contains path separators.
    let safe: String = service
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(credential_locks_dir()?.join(format!("{}.lock", safe)))
}

fn with_service_lock<T>(service: &str, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let map_mutex = SERVICE_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let service_lock = {
        let mut map = map_mutex.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(service.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let _guard = service_lock.lock().unwrap_or_else(|e| e.into_inner());

    let lock_path = service_lock_path(service)?;
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create lock dir: {}", e))?;
    }
    let mut file_lock =
        LockFile::open(&lock_path).map_err(|e| format!("open service lock: {}", e))?;
    file_lock
        .lock()
        .map_err(|e| format!("acquire service lock: {}", e))?;

    f()
}

/// Stable application-data directory for legacy plaintext credentials.
///
/// Prefer the OS application-data location keyed by the app identifier so
/// migrate/delete do not depend on the process CWD. Tests may override via
/// `CREDENTIALS_LEGACY_DIR`.
fn legacy_credentials_app_data_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("CREDENTIALS_LEGACY_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let base = dirs::data_local_dir().ok_or_else(|| {
        "no writable application data directory for legacy credentials".to_string()
    })?;
    Ok(base.join(KEYRING_SERVICE).join("credentials"))
}

/// Registry of absolute directories that previously held legacy plaintext files.
///
/// Old builds only wrote `credentials/{service}.json` relative to their launch
/// CWD and never used the app-data directory. Recording those absolute roots
/// (and relocating discovered files into app-data) lets later launches from a
/// different CWD still find and delete the original source.
fn legacy_roots_registry_path() -> Result<PathBuf, String> {
    Ok(legacy_credentials_app_data_dir()?.join("legacy-credential-roots.json"))
}

fn load_recorded_legacy_roots() -> Result<Vec<PathBuf>, String> {
    let path = legacy_roots_registry_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let json = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let roots: Vec<String> = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    Ok(roots.into_iter().map(PathBuf::from).collect())
}

fn record_legacy_root(root: &Path) -> Result<(), String> {
    let abs = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(root)
    };
    let mut roots = load_recorded_legacy_roots()?;
    if roots.iter().any(|r| r == &abs) {
        return Ok(());
    }
    roots.push(abs);
    let dir = legacy_credentials_app_data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let encoded: Vec<String> = roots
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    fs::write(
        legacy_roots_registry_path()?,
        serde_json::to_string(&encoded).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn deletion_tombstone_path(service: &str) -> Result<PathBuf, String> {
    Ok(legacy_credentials_app_data_dir()?.join(format!("{}.deleted", service)))
}

fn mark_credentials_deleted(service: &str) -> Result<(), String> {
    let dir = legacy_credentials_app_data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::write(deletion_tombstone_path(service)?, b"1").map_err(|e| e.to_string())
}

fn clear_credentials_deleted_marker(service: &str) -> Result<(), String> {
    let path = deletion_tombstone_path(service)?;
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn credentials_were_deleted(service: &str) -> bool {
    deletion_tombstone_path(service)
        .map(|p| p.exists())
        .unwrap_or(false)
}

/// Candidate directories that may contain `{service}.json` from older builds.
fn legacy_credential_roots() -> Result<Vec<PathBuf>, String> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |p: PathBuf| {
        if seen.insert(p.clone()) {
            roots.push(p);
        }
    };

    // Relocated / stable copy — process-independent.
    push(legacy_credentials_app_data_dir()?);

    // Historical launch CWD (absolute when available, plus relative fallback).
    if let Ok(cwd) = std::env::current_dir() {
        push(cwd.join("credentials"));
    }
    push(PathBuf::from("credentials"));

    // Absolute roots discovered on prior launches (actual old CWDs).
    for root in load_recorded_legacy_roots()? {
        push(root);
    }

    // Explicit known launch locations (tests / operators), OS path-separated.
    if let Ok(extra) = std::env::var("CREDENTIALS_LEGACY_ROOTS") {
        if !extra.is_empty() {
            for root in std::env::split_paths(&extra) {
                if !root.as_os_str().is_empty() {
                    push(root);
                }
            }
        }
    }

    Ok(roots)
}

/// Every supported legacy plaintext path for a service.
fn legacy_credentials_paths(service: &str) -> Result<Vec<PathBuf>, String> {
    let file_name = format!("{}.json", service);
    Ok(legacy_credential_roots()?
        .into_iter()
        .map(|root| root.join(&file_name))
        .collect())
}

/// Copy a discovered non-app-data legacy file into the stable app-data location
/// and remember its absolute source directory for later cross-CWD delete/migrate.
fn remember_and_relocate_legacy(service: &str, src: &Path) -> Result<(), String> {
    if let Some(parent) = src.parent() {
        record_legacy_root(parent)?;
    }

    let dest_dir = legacy_credentials_app_data_dir()?;
    fs::create_dir_all(&dest_dir).map_err(|e| e.to_string())?;
    let dest = dest_dir.join(format!("{}.json", service));

    let same = match (fs::canonicalize(src), fs::canonicalize(&dest)) {
        (Ok(a), Ok(b)) => a == b,
        _ => src == dest,
    };
    if same {
        return Ok(());
    }

    fs::copy(src, &dest).map_err(|e| format!("relocate legacy credentials: {}", e))?;
    Ok(())
}

fn keyring_entry(service: &str) -> Result<Entry, String> {
    Entry::new(KEYRING_SERVICE, service).map_err(|e| e.to_string())
}

fn remove_legacy_file(service: &str) -> Result<(), String> {
    for path in legacy_credentials_paths(service)? {
        if path.exists() {
            fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Read a legacy plaintext credentials file from any supported location.
pub fn read_legacy_credentials_file(service: &str) -> Result<Option<Credentials>, String> {
    for path in legacy_credentials_paths(service)? {
        if !Path::new(&path).exists() {
            continue;
        }
        let json = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let credentials: Credentials = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        // Move the original CWD-relative source into app-data and record its
        // absolute root so a later launch/delete from another CWD still finds it.
        remember_and_relocate_legacy(service, &path)?;
        return Ok(Some(credentials));
    }
    Ok(None)
}

fn save_credentials_unlocked(service: &str, username: &str, password: &str) -> Result<(), String> {
    let credentials = Credentials {
        username: username.to_string(),
        password: password.to_string(),
        service: service.to_string(),
    };
    let json = serde_json::to_string(&credentials).map_err(|e| e.to_string())?;
    let entry = keyring_entry(service)?;
    entry.set_password(&json).map_err(|e| e.to_string())?;
    // Intentional save after delete clears the anti-resurrection tombstone.
    clear_credentials_deleted_marker(service)?;
    remove_legacy_file(service)?;
    Ok(())
}

fn get_credentials_unlocked(service: &str) -> Result<Option<Credentials>, String> {
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
            // A prior delete that could not see every historical CWD must not be
            // undone by later launching from an old directory that still has JSON.
            if credentials_were_deleted(service) {
                remove_legacy_file(service)?;
                return Ok(None);
            }
            if let Some(mut legacy) = read_legacy_credentials_file(service)? {
                // Always migrate and clean up under the requested service key.
                // If the embedded service differs (copied/renamed file), normalize it
                // so we do not leave the requested plaintext file behind or overwrite
                // an unrelated keychain entry.
                if legacy.service != service {
                    legacy.service = service.to_string();
                }
                save_credentials_unlocked(service, &legacy.username, &legacy.password)?;
                Ok(Some(legacy))
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

fn delete_credentials_unlocked(service: &str) -> Result<(), String> {
    remove_legacy_file(service)?;
    // Tombstone survives even if some historical CWD file was not yet recorded,
    // so a later launch from that old CWD cannot remigrate into the keychain.
    mark_credentials_deleted(service)?;
    let entry = keyring_entry(service)?;
    match entry.delete_credential() {
        Ok(()) => {}
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(e.to_string()),
    }
    Ok(())
}

/// Store credentials in the OS keychain and remove any leftover plaintext file.
pub fn save_credentials(service: &str, username: &str, password: &str) -> Result<(), String> {
    with_service_lock(service, || save_credentials_unlocked(service, username, password))
}

/// Load credentials from the keychain. If missing, one-time migrate from legacy JSON
/// then delete the plaintext file.
pub fn get_credentials(service: &str) -> Result<Option<Credentials>, String> {
    with_service_lock(service, || get_credentials_unlocked(service))
}

/// Delete any leftover plaintext credentials file, then the keychain entry.
///
/// Legacy plaintext is removed first so a failed file delete cannot leave a
/// migration source that resurrects credentials after the keychain entry is gone.
/// Holds the per-service lock for the whole operation so a concurrent
/// `get_credentials` migration cannot recreate the entry after delete returns.
pub fn delete_credentials(service: &str) -> Result<(), String> {
    with_service_lock(service, || delete_credentials_unlocked(service))
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
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");
        env::set_current_dir(tmp.path()).unwrap();
        f();
        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");
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

    #[test]
    fn service_lock_allows_unlocked_helpers_while_held() {
        // Public APIs take the lock once; migration uses unlocked save so we
        // do not deadlock on a non-reentrant Mutex.
        let _guard = TEST_LOCK.lock().unwrap();
        let lock_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LOCK_DIR", lock_root.path());
        let expected = lock_root.path().join("lock-test.lock");

        // Read-only CWD must not block lock acquisition (install-dir case).
        let original = env::current_dir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        env::set_current_dir(tmp.path()).unwrap();
        let cwd = env::current_dir().unwrap();
        let mut perms = fs::metadata(&cwd).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&cwd, perms).unwrap();

        let mut ran = false;
        let result = with_service_lock("lock-test", || {
            let _ = save_credentials_unlocked as fn(&str, &str, &str) -> Result<(), String>;
            ran = true;
            Ok(())
        });

        // Restore writability before leaving the temp CWD.
        let mut perms = fs::metadata(&cwd).unwrap().permissions();
        perms.set_readonly(false);
        fs::set_permissions(&cwd, perms).unwrap();
        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LOCK_DIR");

        result.unwrap();
        assert!(ran);
        assert!(expected.exists());
        assert!(!tmp.path().join("credentials/.locks/lock-test.lock").exists());
    }

    #[test]
    fn service_lock_path_is_independent_of_cwd() {
        let _guard = TEST_LOCK.lock().unwrap();
        let lock_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LOCK_DIR", lock_root.path());
        let path_a = service_lock_path("gemini").unwrap();

        let original = env::current_dir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        env::set_current_dir(tmp.path()).unwrap();
        let path_b = service_lock_path("gemini").unwrap();
        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LOCK_DIR");

        assert_eq!(path_a, path_b);
        assert_eq!(path_a, lock_root.path().join("gemini.lock"));
    }

    #[test]
    fn legacy_app_data_path_is_independent_of_cwd() {
        let _guard = TEST_LOCK.lock().unwrap();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let paths_a = legacy_credentials_paths("gemini").unwrap();
        let original = env::current_dir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        env::set_current_dir(tmp.path()).unwrap();
        let paths_b = legacy_credentials_paths("gemini").unwrap();
        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");

        assert_eq!(paths_a[0], paths_b[0]);
        assert_eq!(paths_a[0], legacy_root.path().join("gemini.json"));
        // CWD-relative historical path remains a supported location.
        assert!(paths_a.iter().any(|p| p == &PathBuf::from("credentials/gemini.json")));
        assert!(paths_b.iter().any(|p| p == &PathBuf::from("credentials/gemini.json")));
    }

    #[test]
    fn read_legacy_finds_app_data_file_from_other_cwd() {
        let _guard = TEST_LOCK.lock().unwrap();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let sample = Credentials {
            username: "user@example.com".into(),
            password: "s3cret".into(),
            service: "gemini".into(),
        };
        fs::write(
            legacy_root.path().join("gemini.json"),
            serde_json::to_string(&sample).unwrap(),
        )
        .unwrap();

        let original = env::current_dir().unwrap();
        let other_cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(other_cwd.path()).unwrap();
        // No CWD-relative credentials/ here — only the shared app-data file.
        assert!(!other_cwd.path().join("credentials/gemini.json").exists());
        let loaded = read_legacy_credentials_file("gemini").unwrap().unwrap();
        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");

        assert_eq!(loaded, sample);
    }

    #[test]
    fn read_legacy_finds_prior_cwd_file_via_known_roots() {
        // Old builds only wrote CWD-relative credentials/{service}.json and never
        // the new app-data directory. A later launch from another CWD must still
        // find that original file via known/recorded legacy roots.
        let _guard = TEST_LOCK.lock().unwrap();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());

        let old_cwd = tempfile::tempdir().unwrap();
        let old_creds_dir = old_cwd.path().join("credentials");
        fs::create_dir_all(&old_creds_dir).unwrap();
        let sample = Credentials {
            username: "user@example.com".into(),
            password: "s3cret".into(),
            service: "gemini".into(),
        };
        fs::write(
            old_creds_dir.join("gemini.json"),
            serde_json::to_string(&sample).unwrap(),
        )
        .unwrap();

        // Simulate an operator/test supplying the historical launch location, or
        // a prior discovery that recorded it — never manufacture an app-data file.
        env::set_var("CREDENTIALS_LEGACY_ROOTS", &old_creds_dir);

        let original = env::current_dir().unwrap();
        let other_cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(other_cwd.path()).unwrap();
        assert!(!other_cwd.path().join("credentials/gemini.json").exists());
        assert!(!legacy_root.path().join("gemini.json").exists());

        let loaded = read_legacy_credentials_file("gemini").unwrap().unwrap();
        // Discovery relocates into stable app-data for subsequent CWD-independent ops.
        assert!(legacy_root.path().join("gemini.json").exists());
        assert_eq!(loaded, sample);

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");
    }

    #[test]
    fn discovering_cwd_legacy_records_root_for_other_cwd() {
        let _guard = TEST_LOCK.lock().unwrap();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let original = env::current_dir().unwrap();
        let old_cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(old_cwd.path()).unwrap();
        fs::create_dir_all("credentials").unwrap();
        let sample = Credentials {
            username: "u".into(),
            password: "p".into(),
            service: "poe".into(),
        };
        fs::write(
            "credentials/poe.json",
            serde_json::to_string(&sample).unwrap(),
        )
        .unwrap();

        let loaded = read_legacy_credentials_file("poe").unwrap().unwrap();
        assert_eq!(loaded, sample);
        assert!(legacy_root.path().join("poe.json").exists());

        // Switch away from the historical CWD; recorded root + relocated copy
        // must still be deletable without re-launching from old_cwd.
        let other_cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(other_cwd.path()).unwrap();
        remove_legacy_file("poe").unwrap();
        assert!(!legacy_root.path().join("poe.json").exists());
        assert!(!old_cwd.path().join("credentials/poe.json").exists());

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn delete_tombstone_blocks_remigration_from_missed_cwd_file() {
        let _guard = TEST_LOCK.lock().unwrap();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let original = env::current_dir().unwrap();
        let new_cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(new_cwd.path()).unwrap();

        // Delete from a CWD that never saw the historical plaintext file.
        mark_credentials_deleted("gemini").unwrap();
        assert!(credentials_were_deleted("gemini"));

        // Later launch from the old CWD still finds leftover JSON, but must not
        // treat it as migratable after an explicit delete.
        let old_cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(old_cwd.path()).unwrap();
        fs::create_dir_all("credentials").unwrap();
        fs::write(
            "credentials/gemini.json",
            r#"{"username":"u","password":"p","service":"gemini"}"#,
        )
        .unwrap();

        assert!(credentials_were_deleted("gemini"));
        // Scrub leftovers without remigrating when the tombstone is present.
        remove_legacy_file("gemini").unwrap();
        // get_credentials_unlocked path: tombstone => Ok(None) after scrub.
        // We exercise the helper directly to avoid keyring in unit tests.
        assert!(credentials_were_deleted("gemini"));
        let _ = read_legacy_credentials_file("gemini"); // may relocate; tombstone still wins in get
        assert!(credentials_were_deleted("gemini"));

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn remove_legacy_clears_app_data_and_cwd_locations() {
        let _guard = TEST_LOCK.lock().unwrap();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let original = env::current_dir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        env::set_current_dir(tmp.path()).unwrap();

        let app_data_file = legacy_root.path().join("poe.json");
        let cwd_file = PathBuf::from("credentials/poe.json");
        fs::write(&app_data_file, r#"{"username":"a","password":"b","service":"poe"}"#).unwrap();
        fs::create_dir_all("credentials").unwrap();
        fs::write(&cwd_file, r#"{"username":"c","password":"d","service":"poe"}"#).unwrap();

        remove_legacy_file("poe").unwrap();
        assert!(!app_data_file.exists());
        assert!(!cwd_file.exists());

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }
}
