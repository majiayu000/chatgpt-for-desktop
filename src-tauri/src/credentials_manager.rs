use fslock::LockFile;
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// OS keychain service name (matches Tauri app identifier).
const KEYRING_SERVICE: &str = "com.lif.ai.assistant";

/// Credential service keys accepted via IPC / filesystem path construction.
/// Restricting to this allowlist prevents `PathBuf::join` escapes when a caller
/// supplies absolute or `../`-style service strings.
const SUPPORTED_SERVICES: &[&str] = &["gemini", "poe"];

/// Reject unsupported or path-like service names before any filesystem join.
fn validate_service_name(service: &str) -> Result<(), String> {
    if SUPPORTED_SERVICES.contains(&service) {
        Ok(())
    } else {
        Err(format!(
            "unsupported credentials service `{service}` (expected gemini or poe)"
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub service: String,
}

/// JSON payload stored in the OS keychain. Extends the public `Credentials`
/// shape with an optional write timestamp so a later plaintext save from an
/// older build can be detected as newer than the keychain copy.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
struct KeychainPayload {
    username: String,
    password: String,
    service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_at_ms: Option<u128>,
}

impl KeychainPayload {
    fn from_credentials(username: &str, password: &str, service: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            service: service.to_string(),
            updated_at_ms: Some(system_time_as_millis(SystemTime::now())),
        }
    }

    fn into_credentials(self) -> Credentials {
        Credentials {
            username: self.username,
            password: self.password,
            service: self.service,
        }
    }

    fn same_secret_as(&self, other: &Credentials) -> bool {
        self.username == other.username
            && self.password == other.password
            && self.service == other.service
    }
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
/// lets later launches from a different CWD still find and delete the original
/// source. Relocating into app-data happens only after a successful keychain
/// write so a failed migrate cannot prefer a stale relocated copy.
fn legacy_roots_registry_path() -> Result<PathBuf, String> {
    Ok(legacy_credentials_app_data_dir()?.join("legacy-credential-roots.json"))
}

fn legacy_roots_registry_lock_path() -> Result<PathBuf, String> {
    // Keep the registry lock beside the registry under the (overridable) legacy
    // app-data dir so tests using CREDENTIALS_LEGACY_DIR stay isolated.
    Ok(legacy_credentials_app_data_dir()?.join("legacy-roots-registry.lock"))
}

/// Inter-process lock for the shared roots registry read-modify-write path.
/// Distinct from per-service locks so concurrent migrations of different
/// services cannot clobber each other's recorded roots.
fn with_registry_lock<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let lock_path = legacy_roots_registry_lock_path()?;
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create registry lock dir: {}", e))?;
    }
    let mut file_lock =
        LockFile::open(&lock_path).map_err(|e| format!("open registry lock: {}", e))?;
    file_lock
        .lock()
        .map_err(|e| format!("acquire registry lock: {}", e))?;
    f()
}

/// Lossless registry encoding for a filesystem path.
///
/// Prefer a UTF-8 string (backward-compatible with older registries). When a
/// Unix path contains non-UTF-8 bytes, persist the raw OS bytes as a JSON array
/// so later launches reconstruct the exact path instead of a lossy substitute.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum EncodedPath {
    Utf8(String),
    Bytes(Vec<u8>),
}

fn encode_path_for_registry(path: &Path) -> EncodedPath {
    match path.to_str() {
        Some(s) => EncodedPath::Utf8(s.to_string()),
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                EncodedPath::Bytes(path.as_os_str().as_bytes().to_vec())
            }
            #[cfg(not(unix))]
            {
                // Windows paths are UTF-16; to_str failing is unexpected. Fall
                // back to lossy only as a last resort so the registry still writes.
                EncodedPath::Utf8(path.to_string_lossy().into_owned())
            }
        }
    }
}

fn decode_path_from_registry(encoded: EncodedPath) -> PathBuf {
    match encoded {
        EncodedPath::Utf8(s) => PathBuf::from(s),
        EncodedPath::Bytes(bytes) => {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                PathBuf::from(std::ffi::OsStr::from_bytes(&bytes))
            }
            #[cfg(not(unix))]
            {
                // Byte-array entries are only produced on Unix; treat as UTF-8
                // lossy if somehow present on other platforms.
                PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
            }
        }
    }
}

fn write_legacy_roots_atomic(roots: &[PathBuf]) -> Result<(), String> {
    let path = legacy_roots_registry_path()?;
    let dir = legacy_credentials_app_data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let encoded: Vec<EncodedPath> = roots.iter().map(|p| encode_path_for_registry(p)).collect();
    let tmp = dir.join(format!(
        "legacy-credential-roots.{}.tmp",
        std::process::id()
    ));
    fs::write(
        &tmp,
        serde_json::to_string(&encoded).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    // Same-directory rename is atomic on POSIX and replaces the target on
    // Windows, avoiding a truncated/partial registry visible to other readers.
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })
}

/// Load recorded roots. Malformed/partial registry content is quarantined and
/// treated as empty so keychain-hit reads and deletes can still proceed and the
/// registry can be rebuilt on the next successful discovery.
fn load_recorded_legacy_roots_unlocked() -> Result<Vec<PathBuf>, String> {
    let path = legacy_roots_registry_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let json = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    match serde_json::from_str::<Vec<EncodedPath>>(&json) {
        Ok(roots) => Ok(roots.into_iter().map(decode_path_from_registry).collect()),
        Err(_) => {
            let quarantine = path.with_extension("json.corrupt");
            let _ = fs::rename(&path, &quarantine);
            Ok(Vec::new())
        }
    }
}

fn load_recorded_legacy_roots() -> Result<Vec<PathBuf>, String> {
    with_registry_lock(load_recorded_legacy_roots_unlocked)
}

fn record_legacy_root(root: &Path) -> Result<(), String> {
    let abs = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(root)
    };
    let abs = fs::canonicalize(&abs).unwrap_or(abs);
    with_registry_lock(|| {
        let mut roots = load_recorded_legacy_roots_unlocked()?;
        if roots.iter().any(|r| r == &abs) {
            return Ok(());
        }
        roots.push(abs);
        write_legacy_roots_atomic(&roots)
    })
}

/// Historical launch locations that do not depend on a prior discovery write.
///
/// Old builds wrote relative to the process CWD. Typical CWDs for this desktop
/// app include the executable directory and, on macOS, locations *inside* the
/// `.app` bundle (`Foo.app/Contents/MacOS`, `Foo.app/Contents`, `Foo.app`).
/// These are seeded into the candidate list independently of the on-disk
/// registry so a first upgraded launch from a different CWD can still find
/// leftover plaintext.
///
/// Deliberately avoids install-directory and arbitrary-ancestor guesses: a
/// bundle under `~/Downloads/Foo.app` must not treat `~/Downloads/credentials`
/// as ours, and a portable binary a few levels under home must not guess
/// `~/credentials`. Other tools may store schema-shaped JSON there that
/// cleanup would then delete.
fn bootstrap_legacy_root_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut push = |p: PathBuf| {
        if !p.as_os_str().is_empty() && !candidates.iter().any(|c| c == &p) {
            candidates.push(p);
        }
    };

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent().map(|p| p.to_path_buf()) {
            push(exe_dir.join("credentials"));
            for root in macos_bundle_internal_legacy_roots(&exe_dir) {
                push(root);
            }
        }
    }

    candidates
}

/// Legacy credential dirs that stay inside a macOS `.app` bundle.
///
/// Given `.../Foo.app/Contents/MacOS`, returns `Contents/credentials` and
/// `Foo.app/credentials` only — never the install parent (e.g. `~/Downloads`).
fn macos_bundle_internal_legacy_roots(exe_dir: &Path) -> Vec<PathBuf> {
    let is_macos_bundle = exe_dir.components().any(|c| {
        c.as_os_str()
            .to_str()
            .map(|s| s.ends_with(".app"))
            .unwrap_or(false)
    }) && exe_dir.ends_with("Contents/MacOS");
    if !is_macos_bundle {
        return Vec::new();
    }

    let mut roots = Vec::new();
    if let Some(contents) = exe_dir.parent() {
        roots.push(contents.join("credentials"));
        if let Some(app_bundle) = contents.parent() {
            roots.push(app_bundle.join("credentials"));
            // Intentionally omit app_bundle.parent()/credentials — that is the
            // install directory (Downloads, Desktop, /Applications, …), not an
            // application-owned legacy location.
        }
    }
    roots
}

/// True when `path` deserializes as this app's legacy `Credentials` JSON.
///
/// Used before deleting or seeding so unrelated `{service}.json` files (for
/// example under a shared `credentials/` directory used by another tool) are
/// left alone. I/O failures while inspecting are propagated so callers cannot
/// treat an unreadable plaintext file as a safe schema mismatch.
fn looks_like_app_legacy_credentials(path: &Path) -> Result<bool, String> {
    let json = fs::read_to_string(path).map_err(|e| {
        format!(
            "inspect legacy credentials {}: {}",
            path.display(),
            e
        )
    })?;
    Ok(serde_json::from_str::<Credentials>(&json).is_ok())
}

/// Persist bootstrap directories that already contain this app's legacy
/// credential JSON into the registry without waiting for a per-service read.
fn seed_registry_from_bootstrap_locations() -> Result<(), String> {
    with_registry_lock(|| {
        let mut roots = load_recorded_legacy_roots_unlocked()?;
        let mut changed = false;
        for candidate in bootstrap_legacy_root_candidates() {
            if !candidate.is_dir() {
                continue;
            }
            // Require confirmed app credential JSON, not any `.json` file.
            let mut has_app_legacy = false;
            match fs::read_dir(&candidate) {
                Ok(rd) => {
                    for entry in rd {
                        let entry = match entry {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let path = entry.path();
                        if !path
                            .extension()
                            .map(|ext| ext == "json")
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        // Defer I/O errors to per-service cleanup: an unreadable
                        // unrelated `{other}.json` must not abort registry seeding
                        // (and therefore every save/load/delete) for other services.
                        match looks_like_app_legacy_credentials(&path) {
                            Ok(true) => {
                                has_app_legacy = true;
                                break;
                            }
                            Ok(false) | Err(_) => continue,
                        }
                    }
                }
                Err(_) => continue,
            }
            if !has_app_legacy {
                continue;
            }
            if roots.iter().any(|r| r == &candidate) {
                continue;
            }
            roots.push(candidate);
            changed = true;
        }
        if changed {
            write_legacy_roots_atomic(&roots)?;
        }
        Ok(())
    })
}

fn deletion_tombstone_path(service: &str) -> Result<PathBuf, String> {
    validate_service_name(service)?;
    Ok(legacy_credentials_app_data_dir()?.join(format!("{}.deleted", service)))
}

fn mark_credentials_deleted(service: &str) -> Result<(), String> {
    validate_service_name(service)?;
    let dir = legacy_credentials_app_data_dir()?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Milliseconds so sub-second file mtimes cannot look "newer" than a
    // same-second truncated tombstone and escape scrubbing.
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis();
    // Store the deletion instant so a later intentional save from an older build
    // (which cannot clear this marker) is not scrubbed as a pre-delete leftover.
    // Atomic temp+rename so an interrupted write cannot leave a numeric prefix
    // (e.g. "17") that would parse as a 1970-era cutoff.
    let path = deletion_tombstone_path(service)?;
    let tmp = dir.join(format!("{}.deleted.{}.tmp", service, std::process::id()));
    fs::write(&tmp, millis.to_string()).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        e.to_string()
    })
}

/// Earliest plausible deletion timestamp (2020-01-01 UTC). Truncated numeric
/// prefixes like `17` decode to 1970-era cutoffs and must fail closed.
const MIN_PLAUSIBLE_DELETION_SECS: u64 = 1_577_836_800;
const MIN_PLAUSIBLE_DELETION_MILLIS: u128 = 1_577_836_800_000;
/// Values below this are treated as unix seconds; at/above as milliseconds.
const TOMBSTONE_SECONDS_CEILING: u128 = 10_000_000_000;

fn quarantine_tombstone_as_now(service: &str) -> Result<SystemTime, String> {
    // Persist a stable millisecond cutoff before returning it. Discarding a
    // write failure would leave the malformed marker in place and make every
    // later no-entry lookup use a moving `now`, so an intentional older-build
    // save after an earlier lookup could be scrubbed as pre-deletion.
    mark_credentials_deleted(service)?;
    Ok(SystemTime::now())
}

fn clear_credentials_deleted_marker(service: &str) -> Result<(), String> {
    let path = deletion_tombstone_path(service)?;
    match fs::metadata(&path) {
        Ok(_) => fs::remove_file(&path).map_err(|e| e.to_string())?,
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "stat deletion tombstone {}: {}",
                path.display(),
                e
            ))
        }
    }
    Ok(())
}

fn system_time_as_millis(t: SystemTime) -> u128 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Instant recorded when credentials were intentionally deleted, if any.
///
/// Legacy tombstones that only contained `1` are treated as "suppress all
/// current leftovers" (cutoff = now) so older installs keep anti-resurrection
/// behavior until a timed tombstone replaces them. Whole-second timestamps from
/// earlier timed markers remain supported.
///
/// `NotFound` means no deletion occurred. Other tombstone read/stat I/O errors
/// propagate so a locked or unreadable marker cannot be mistaken for "absent"
/// and allow a stale legacy file to remigrate.
///
/// Truncated or otherwise malformed markers also fail closed: treat them as an
/// intentional deletion (cutoff = now) and rewrite a timed tombstone so a
/// corrupted file cannot be mistaken for absence and remigrate stale JSON.
/// Numeric prefixes from interrupted writes (e.g. `17`) are rejected the same
/// way — they must not parse as 1970-era cutoffs.
fn credentials_deleted_at(service: &str) -> Result<Option<SystemTime>, String> {
    let path = deletion_tombstone_path(service)?;
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "read deletion tombstone {}: {}",
                path.display(),
                e
            ))
        }
    };
    let trimmed = raw.trim();
    if trimmed == "1" {
        return Ok(Some(SystemTime::now()));
    }
    let value: u128 = match trimmed.parse() {
        Ok(v) => v,
        Err(_) => {
            // Fail closed: preserve deletion suppression, then quarantine the
            // marker by rewriting a proper millisecond timestamp.
            return Ok(Some(quarantine_tombstone_as_now(service)?));
        }
    };
    // Heuristic: values below the seconds/millis ceiling are unix-seconds;
    // larger values are milliseconds. Reject implausible truncations (e.g. "17"
    // from an interrupted write) that would become 1970-era cutoffs and allow
    // remigration of pre-delete leftovers.
    let duration = if value < TOMBSTONE_SECONDS_CEILING {
        if value < u128::from(MIN_PLAUSIBLE_DELETION_SECS) {
            return Ok(Some(quarantine_tombstone_as_now(service)?));
        }
        // value < 10^10 fits in u64; use try_from for consistency.
        let secs = u64::try_from(value).map_err(|_| {
            format!("deletion tombstone seconds overflow for `{service}`")
        })?;
        Duration::from_secs(secs)
    } else if value < MIN_PLAUSIBLE_DELETION_MILLIS {
        return Ok(Some(quarantine_tombstone_as_now(service)?));
    } else {
        // Oversized numerics (e.g. u64::MAX+1) must not wrap via `as u64` into a
        // 1970-era cutoff that remigrates deleted credentials.
        match u64::try_from(value) {
            Ok(millis) => Duration::from_millis(millis),
            Err(_) => return Ok(Some(quarantine_tombstone_as_now(service)?)),
        }
    };
    // Unchecked `UNIX_EPOCH + duration` panics when the duration exceeds the
    // platform SystemTime range (notably Windows for u64::MAX-range millis) and
    // otherwise yields a remote-future cutoff that freezes intentional legacy
    // saves indefinitely. Bound relative to now and quarantine failures.
    let Some(deleted_at) = UNIX_EPOCH.checked_add(duration) else {
        return Ok(Some(quarantine_tombstone_as_now(service)?));
    };
    if deleted_at > SystemTime::now() {
        return Ok(Some(quarantine_tombstone_as_now(service)?));
    }
    Ok(Some(deleted_at))
}

fn credentials_were_deleted(service: &str) -> bool {
    matches!(credentials_deleted_at(service), Ok(Some(_)))
}

/// Whether a differing legacy plaintext file should replace the keychain copy.
///
/// Prefer legacy when its mtime is strictly newer than the keychain write stamp.
/// When the keychain entry has no stamp (pre-timestamp installs), treat a
/// differing legacy file as an intentional older-build save and reconcile it;
/// same-secret leftovers are never reconciled (cleanup-only).
fn should_reconcile_legacy_over_keychain(
    keychain: &KeychainPayload,
    legacy: &Credentials,
    legacy_mtime: SystemTime,
) -> bool {
    if keychain.same_secret_as(legacy) {
        return false;
    }
    match keychain.updated_at_ms {
        Some(written_ms) => system_time_as_millis(legacy_mtime) > written_ms,
        None => true,
    }
}

/// Distinguish missing paths from metadata failures that `Path::exists()` masks.
fn legacy_path_present(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!(
            "stat legacy credentials {}: {}",
            path.display(),
            e
        )),
    }
}

/// Candidate directories that may contain `{service}.json` from older builds.
fn legacy_credential_roots() -> Result<Vec<PathBuf>, String> {
    // Establish known launch locations in the registry independently of a
    // prior per-service discovery (first upgraded launch from another CWD).
    seed_registry_from_bootstrap_locations()?;

    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |p: PathBuf| {
        if seen.insert(p.clone()) {
            roots.push(p);
        }
    };

    // Historical launch CWD (absolute when available, plus relative fallback).
    if let Ok(cwd) = std::env::current_dir() {
        push(cwd.join("credentials"));
    }
    push(PathBuf::from("credentials"));

    // Executable-relative bootstrap locations (independent of registry writes).
    for root in bootstrap_legacy_root_candidates() {
        push(root);
    }

    // Absolute roots discovered on prior launches or seeded from bootstrap.
    for root in load_recorded_legacy_roots()? {
        push(root);
    }

    // Stable app-data copy — checked last so a fresher CWD/source file wins
    // when callers resolve by modification time across all candidates.
    push(legacy_credentials_app_data_dir()?);

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
    validate_service_name(service)?;
    let file_name = format!("{}.json", service);
    Ok(legacy_credential_roots()?
        .into_iter()
        .map(|root| root.join(&file_name))
        .collect())
}

fn file_mtime(path: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Record a discovered source root. Does not copy into app-data — relocating
/// before a successful keychain write can leave a stale preferred copy.
fn remember_legacy_source(src: &Path) -> Result<(), String> {
    if let Some(parent) = src.parent() {
        record_legacy_root(parent)?;
    }
    Ok(())
}

fn keyring_entry(service: &str) -> Result<Entry, String> {
    Entry::new(KEYRING_SERVICE, service).map_err(|e| e.to_string())
}

fn remove_legacy_file(service: &str) -> Result<(), String> {
    remove_legacy_files_with_cutoff(service, None)
}

/// Remove confirmed app legacy files, optionally keeping copies newer than a
/// deletion tombstone (intentional post-delete saves from an older build).
fn remove_legacy_files_with_cutoff(
    service: &str,
    not_newer_than: Option<SystemTime>,
) -> Result<(), String> {
    for path in legacy_credentials_paths(service)? {
        // Use metadata so inaccessible parents/stat failures are not masked the
        // way `Path::exists()` is (it returns false on many I/O errors).
        if !legacy_path_present(&path)? {
            continue;
        }
        // Only delete files that parse as this app's legacy credentials schema.
        // Unrelated tools may use the same `{service}.json` filename under a
        // shared directory; deleting those would destroy other apps' data.
        // I/O failures while inspecting are errors — do not silently leave
        // unreadable plaintext behind after a keychain write.
        if !looks_like_app_legacy_credentials(&path)? {
            continue;
        }
        if let Some(cutoff) = not_newer_than {
            let mtime = file_mtime(&path).unwrap_or(UNIX_EPOCH);
            if system_time_as_millis(mtime) > system_time_as_millis(cutoff) {
                // Newer than the intentional delete — leave for remigration.
                continue;
            }
        }
        // Record the confirmed source before attempting removal so a failed
        // delete (permissions / sharing lock) still leaves a retryable root
        // for future launches from other CWDs.
        remember_legacy_source(&path)?;
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Read a legacy plaintext credentials file from any supported location.
///
/// When multiple copies exist, prefer the newest by mtime so a stale app-data
/// relocation cannot win over a later-updated CWD source. Discovery records the
/// source root but does not relocate until keychain migration succeeds.
/// Foreign or malformed JSON at one candidate is skipped so a valid copy in
/// another root can still be migrated.
fn read_freshest_legacy_credentials(
    service: &str,
) -> Result<Option<(Credentials, SystemTime)>, String> {
    let mut best: Option<(PathBuf, SystemTime, Credentials)> = None;

    for path in legacy_credentials_paths(service)? {
        if !legacy_path_present(&path)? {
            continue;
        }
        let json = fs::read_to_string(&path).map_err(|e| {
            format!("read legacy credentials {}: {}", path.display(), e)
        })?;
        let credentials: Credentials = match serde_json::from_str(&json) {
            Ok(c) => c,
            // Skip foreign/malformed JSON; keep searching other roots.
            Err(_) => continue,
        };
        let mtime = file_mtime(&path).unwrap_or(UNIX_EPOCH);
        match &best {
            Some((_, best_mtime, _)) if mtime <= *best_mtime => {}
            _ => best = Some((path, mtime, credentials)),
        }
    }

    if let Some((path, mtime, credentials)) = best {
        remember_legacy_source(&path)?;
        return Ok(Some((credentials, mtime)));
    }
    Ok(None)
}

pub fn read_legacy_credentials_file(service: &str) -> Result<Option<Credentials>, String> {
    Ok(read_freshest_legacy_credentials(service)?.map(|(c, _)| c))
}

/// Write the keychain entry and clear any deletion tombstone without touching
/// legacy plaintext. Callers that race with older unlocked builds must recheck
/// the plaintext snapshot before deleting it.
fn write_keychain_credentials(
    service: &str,
    username: &str,
    password: &str,
) -> Result<KeychainPayload, String> {
    let payload = KeychainPayload::from_credentials(username, password, service);
    let json = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let entry = keyring_entry(service)?;
    entry.set_password(&json).map_err(|e| e.to_string())?;
    // Intentional save after delete clears the anti-resurrection tombstone.
    clear_credentials_deleted_marker(service)?;
    Ok(payload)
}

fn save_credentials_unlocked(service: &str, username: &str, password: &str) -> Result<(), String> {
    write_keychain_credentials(service, username, password)?;
    remove_legacy_file(service)?;
    Ok(())
}

/// Whether two legacy observations refer to the same secret snapshot.
fn legacy_snapshot_matches(
    service: &str,
    expected: &Credentials,
    expected_mtime: SystemTime,
    observed: &Credentials,
    observed_mtime: SystemTime,
) -> bool {
    let mut left = expected.clone();
    let mut right = observed.clone();
    if left.service != service {
        left.service = service.to_string();
    }
    if right.service != service {
        right.service = service.to_string();
    }
    left == right && system_time_as_millis(expected_mtime) == system_time_as_millis(observed_mtime)
}

/// Outcome of attempting to remove legacy plaintext after a prior decision.
enum LegacyCleanupOutcome {
    /// No legacy file remained (or it matched and was removed).
    Cleared,
    /// File identity/mtime/content changed since the decision; caller must retry.
    Changed {
        credentials: Credentials,
        mtime: SystemTime,
    },
}

/// Re-read legacy credentials immediately before deletion. If an older build
/// rewrote the file after our decision snapshot, refuse to delete and report
/// the new snapshot so the caller can reconcile instead of discarding it.
fn remove_legacy_if_snapshot_unchanged(
    service: &str,
    expected: &Credentials,
    expected_mtime: SystemTime,
) -> Result<LegacyCleanupOutcome, String> {
    match read_freshest_legacy_credentials(service)? {
        None => Ok(LegacyCleanupOutcome::Cleared),
        Some((observed, observed_mtime)) => {
            if !legacy_snapshot_matches(
                service,
                expected,
                expected_mtime,
                &observed,
                observed_mtime,
            ) {
                return Ok(LegacyCleanupOutcome::Changed {
                    credentials: observed,
                    mtime: observed_mtime,
                });
            }
            remove_legacy_file(service)?;
            // An unlocked older build may rewrite during/after remove_file.
            match read_freshest_legacy_credentials(service)? {
                None => Ok(LegacyCleanupOutcome::Cleared),
                Some((again, again_mtime)) => Ok(LegacyCleanupOutcome::Changed {
                    credentials: again,
                    mtime: again_mtime,
                }),
            }
        }
    }
}

/// Normalize embedded service to the lookup key used for migration/cleanup.
fn normalize_legacy_service(service: &str, legacy: &mut Credentials) {
    if legacy.service != service {
        legacy.service = service.to_string();
    }
}

fn get_credentials_unlocked(service: &str) -> Result<Option<Credentials>, String> {
    let entry = keyring_entry(service)?;
    match entry.get_password() {
        Ok(json) => {
            let mut payload: KeychainPayload =
                serde_json::from_str(&json).map_err(|e| e.to_string())?;
            // Older builds do not take our inter-process lock. Re-check the
            // legacy snapshot immediately before every delete/reconcile so a
            // concurrent plaintext rewrite is promoted instead of discarded.
            const MAX_LEGACY_STABILIZE_ATTEMPTS: u32 = 8;
            let mut pending: Option<(Credentials, SystemTime)> =
                read_freshest_legacy_credentials(service)?;
            for _ in 0..MAX_LEGACY_STABILIZE_ATTEMPTS {
                let Some((mut legacy, legacy_mtime)) = pending.take() else {
                    return Ok(Some(payload.into_credentials()));
                };
                normalize_legacy_service(service, &mut legacy);
                if should_reconcile_legacy_over_keychain(&payload, &legacy, legacy_mtime) {
                    // Write keychain first without deleting plaintext, then
                    // remove only if the file still matches this snapshot.
                    payload = write_keychain_credentials(
                        service,
                        &legacy.username,
                        &legacy.password,
                    )?;
                    match remove_legacy_if_snapshot_unchanged(service, &legacy, legacy_mtime)? {
                        LegacyCleanupOutcome::Cleared => return Ok(Some(legacy)),
                        LegacyCleanupOutcome::Changed {
                            credentials,
                            mtime,
                        } => {
                            pending = Some((credentials, mtime));
                            continue;
                        }
                    }
                }
                // Same-secret (or older) leftover: delete only if unchanged.
                match remove_legacy_if_snapshot_unchanged(service, &legacy, legacy_mtime)? {
                    LegacyCleanupOutcome::Cleared => {
                        return Ok(Some(payload.into_credentials()));
                    }
                    LegacyCleanupOutcome::Changed {
                        credentials,
                        mtime,
                    } => {
                        pending = Some((credentials, mtime));
                    }
                }
            }
            Err(format!(
                "legacy credentials for `{service}` kept changing during cleanup"
            ))
        }
        Err(keyring::Error::NoEntry) => {
            // A prior delete that could not see every historical CWD must not be
            // undone by later launching from an old directory that still has JSON
            // from before the delete. Files saved after the tombstone timestamp
            // (e.g. intentional save in an older build) are allowed to remigrate.
            if let Some(deleted_at) = credentials_deleted_at(service)? {
                remove_legacy_files_with_cutoff(service, Some(deleted_at))?;
            }
            // Same stabilize loop as the keychain-hit path: older unlocked builds
            // may rewrite plaintext after we snapshot it. Write keychain first,
            // then delete only if the file is unchanged — never blind-delete via
            // save_credentials_unlocked.
            const MAX_LEGACY_STABILIZE_ATTEMPTS: u32 = 8;
            let mut pending = read_freshest_legacy_credentials(service)?;
            for _ in 0..MAX_LEGACY_STABILIZE_ATTEMPTS {
                let Some((mut legacy, legacy_mtime)) = pending.take() else {
                    return Ok(None);
                };
                normalize_legacy_service(service, &mut legacy);
                write_keychain_credentials(service, &legacy.username, &legacy.password)?;
                match remove_legacy_if_snapshot_unchanged(service, &legacy, legacy_mtime)? {
                    LegacyCleanupOutcome::Cleared => return Ok(Some(legacy)),
                    LegacyCleanupOutcome::Changed {
                        credentials,
                        mtime,
                    } => {
                        pending = Some((credentials, mtime));
                    }
                }
            }
            Err(format!(
                "legacy credentials for `{service}` kept changing during migration"
            ))
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
    // Refresh the cutoff after keychain deletion completes. An older unlocked
    // build may have written plaintext while delete_credential() ran; that
    // file's mtime can post-date the first tombstone even though this delete
    // finished later. Re-stamp and re-scrub so those mid-delete writes cannot
    // remigrate as "intentional post-delete saves".
    mark_credentials_deleted(service)?;
    if let Some(deleted_at) = credentials_deleted_at(service)? {
        remove_legacy_files_with_cutoff(service, Some(deleted_at))?;
    }
    Ok(())
}

/// Store credentials in the OS keychain and remove any leftover plaintext file.
pub fn save_credentials(service: &str, username: &str, password: &str) -> Result<(), String> {
    validate_service_name(service)?;
    with_service_lock(service, || save_credentials_unlocked(service, username, password))
}

/// Load credentials from the keychain. If missing, one-time migrate from legacy JSON
/// then delete the plaintext file.
pub fn get_credentials(service: &str) -> Result<Option<Credentials>, String> {
    validate_service_name(service)?;
    with_service_lock(service, || get_credentials_unlocked(service))
}

/// Delete any leftover plaintext credentials file, then the keychain entry.
///
/// Legacy plaintext is removed first so a failed file delete cannot leave a
/// migration source that resurrects credentials after the keychain entry is gone.
/// Holds the per-service lock for the whole operation so a concurrent
/// `get_credentials` migration cannot recreate the entry after delete returns.
pub fn delete_credentials(service: &str) -> Result<(), String> {
    validate_service_name(service)?;
    with_service_lock(service, || delete_credentials_unlocked(service))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Serialize tests that touch the working directory / credentials folder.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn paths_equivalent(a: &Path, b: &Path) -> bool {
        if a == b {
            return true;
        }
        match (fs::canonicalize(a), fs::canonicalize(b)) {
            (Ok(ca), Ok(cb)) => ca == cb,
            _ => false,
        }
    }

    fn with_temp_cwd<F: FnOnce()>(f: F) {
        let _guard = test_guard();
        let original = env::current_dir().expect("current_dir before with_temp_cwd");
        struct RestoreCwd(PathBuf);
        impl Drop for RestoreCwd {
            fn drop(&mut self) {
                let _ = env::set_current_dir(&self.0);
            }
        }
        let _restore = RestoreCwd(original);
        let tmp = tempfile::tempdir().unwrap();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");
        env::set_current_dir(tmp.path()).unwrap();
        f();
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
        let _guard = test_guard();
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
        let _guard = test_guard();
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
        let _guard = test_guard();
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

        let app_data = legacy_root.path().join("gemini.json");
        assert!(paths_a.iter().any(|p| p == &app_data));
        assert!(paths_b.iter().any(|p| p == &app_data));
        // CWD-relative historical path remains a supported location.
        assert!(paths_a.iter().any(|p| p == &PathBuf::from("credentials/gemini.json")));
        assert!(paths_b.iter().any(|p| p == &PathBuf::from("credentials/gemini.json")));
    }

    #[test]
    fn read_legacy_finds_app_data_file_from_other_cwd() {
        let _guard = test_guard();
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
        let _guard = test_guard();
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
        // Discovery records the source root but does not relocate before migrate.
        assert!(!legacy_root.path().join("gemini.json").exists());
        let recorded = load_recorded_legacy_roots().unwrap();
        assert!(recorded.iter().any(|r| paths_equivalent(r, &old_creds_dir)));
        assert_eq!(loaded, sample);

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");
    }

    #[test]
    fn discovering_cwd_legacy_records_root_for_other_cwd() {
        let _guard = test_guard();
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
        // No pre-migrate relocate into app-data.
        assert!(!legacy_root.path().join("poe.json").exists());
        let recorded = load_recorded_legacy_roots().unwrap();
        assert!(recorded
            .iter()
            .any(|r| paths_equivalent(r, &old_cwd.path().join("credentials"))));

        // Switch away from the historical CWD; recorded root must still make
        // the original file deletable without re-launching from old_cwd.
        let other_cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(other_cwd.path()).unwrap();
        remove_legacy_file("poe").unwrap();
        assert!(!old_cwd.path().join("credentials/poe.json").exists());

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn corrupt_registry_is_quarantined_and_rebuildable() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        fs::create_dir_all(legacy_root.path()).unwrap();
        let registry = legacy_root.path().join("legacy-credential-roots.json");
        fs::write(&registry, b"{not-valid-json").unwrap();

        // Parse failure must not block path enumeration / rebuild.
        let roots = load_recorded_legacy_roots().unwrap();
        assert!(roots.is_empty());
        assert!(!registry.exists());
        assert!(legacy_root
            .path()
            .join("legacy-credential-roots.json.corrupt")
            .exists());

        let original = env::current_dir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(cwd.path()).unwrap();
        fs::create_dir_all("credentials").unwrap();
        fs::write(
            "credentials/gemini.json",
            r#"{"username":"u","password":"p","service":"gemini"}"#,
        )
        .unwrap();
        let _ = read_legacy_credentials_file("gemini").unwrap().unwrap();
        let rebuilt = load_recorded_legacy_roots().unwrap();
        assert!(rebuilt.iter().any(|r| {
            paths_equivalent(r, &cwd.path().join("credentials"))
                || paths_equivalent(r, &env::current_dir().unwrap().join("credentials"))
        }));

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn prefers_fresher_cwd_source_over_stale_app_data_copy() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let original = env::current_dir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(cwd.path()).unwrap();
        fs::create_dir_all("credentials").unwrap();

        let stale = Credentials {
            username: "old".into(),
            password: "oldpass".into(),
            service: "gemini".into(),
        };
        let fresh = Credentials {
            username: "new".into(),
            password: "newpass".into(),
            service: "gemini".into(),
        };
        fs::write(
            legacy_root.path().join("gemini.json"),
            serde_json::to_string(&stale).unwrap(),
        )
        .unwrap();
        // Ensure the CWD copy is newer than the app-data copy.
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(
            "credentials/gemini.json",
            serde_json::to_string(&fresh).unwrap(),
        )
        .unwrap();

        let loaded = read_legacy_credentials_file("gemini").unwrap().unwrap();
        assert_eq!(loaded, fresh);

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn bootstrap_candidates_include_exe_relative_credentials() {
        let candidates = bootstrap_legacy_root_candidates();
        assert!(candidates.iter().any(|p| {
            p.file_name().and_then(|n| n.to_str()) == Some("credentials")
        }));
    }

    #[test]
    fn bootstrap_candidates_exclude_generic_home_credentials() {
        let candidates = bootstrap_legacy_root_candidates();
        if let Some(home) = dirs::home_dir() {
            let home_creds = home.join("credentials");
            assert!(
                !candidates.iter().any(|p| paths_equivalent(p, &home_creds)),
                "generic ~/credentials must not be a guessed legacy root"
            );
        }
    }

    #[test]
    fn remove_legacy_skips_unrelated_json_without_app_schema() {
        with_temp_cwd(|| {
            fs::create_dir_all("credentials").unwrap();
            let foreign = PathBuf::from("credentials/gemini.json");
            // Other tools may use the same filename with a different schema.
            fs::write(&foreign, r#"{"api_key":"sk-foreign","project":"other-app"}"#).unwrap();

            remove_legacy_file("gemini").unwrap();
            assert!(
                foreign.exists(),
                "unrelated JSON must not be deleted without provenance"
            );

            // App-shaped legacy files are still cleaned up.
            fs::write(
                &foreign,
                r#"{"username":"u","password":"p","service":"gemini"}"#,
            )
            .unwrap();
            remove_legacy_file("gemini").unwrap();
            assert!(!foreign.exists());
        });
    }

    #[test]
    fn read_legacy_skips_foreign_json_and_continues_search() {
        let _guard = test_guard();
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
        let cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(cwd.path()).unwrap();
        fs::create_dir_all("credentials").unwrap();
        // Foreign/malformed CWD file must not abort search of app-data copy.
        fs::write(
            "credentials/gemini.json",
            r#"{"api_key":"sk-foreign","project":"other-app"}"#,
        )
        .unwrap();

        let loaded = read_legacy_credentials_file("gemini").unwrap().unwrap();
        assert_eq!(loaded, sample);

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn remove_legacy_propagates_unreadable_file_inspection_errors() {
        with_temp_cwd(|| {
            fs::create_dir_all("credentials").unwrap();
            let path = PathBuf::from("credentials/gemini.json");
            fs::write(
                &path,
                r#"{"username":"u","password":"p","service":"gemini"}"#,
            )
            .unwrap();

            // Make the file unreadable so inspection cannot confirm schema.
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_readonly(true);
            // On Unix, clear owner read bit to force a permission error.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            }
            #[cfg(not(unix))]
            {
                fs::set_permissions(&path, perms).unwrap();
            }

            let err = remove_legacy_file("gemini");

            // Restore so tempfile cleanup can remove the file.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o644));
            }
            #[cfg(not(unix))]
            {
                let mut perms = fs::metadata(&path).unwrap().permissions();
                perms.set_readonly(false);
                let _ = fs::set_permissions(&path, perms);
            }

            #[cfg(unix)]
            {
                assert!(
                    err.is_err(),
                    "unreadable legacy file must surface an inspection error"
                );
                let msg = err.unwrap_err();
                assert!(
                    msg.contains("inspect legacy credentials"),
                    "unexpected error: {msg}"
                );
            }
            #[cfg(not(unix))]
            {
                // Windows permission models vary; at least ensure no panic.
                let _ = err;
            }
        });
    }

    #[test]
    fn registry_roundtrips_non_utf8_unix_paths() {
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;

            let _guard = test_guard();
            let legacy_root = tempfile::tempdir().unwrap();
            env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
            env::remove_var("CREDENTIALS_LEGACY_ROOTS");

            // APFS rejects non-UTF-8 directory names on create, but historical
            // launch paths on other Unix filesystems may still contain them —
            // exercise lossless registry encode/decode without mkdir.
            let weird = PathBuf::from(OsStr::from_bytes(b"/tmp/cred\xffentials"));

            write_legacy_roots_atomic(&[weird.clone()]).unwrap();
            let loaded = load_recorded_legacy_roots().unwrap();
            assert!(
                loaded.iter().any(|r| r == &weird),
                "lossy UTF-8 substitution must not rewrite non-UTF-8 roots; got {loaded:?}"
            );

            // Ensure on-disk encoding used a byte array, not to_string_lossy.
            let registry = legacy_root.path().join("legacy-credential-roots.json");
            let raw = fs::read_to_string(&registry).unwrap();
            assert!(
                raw.starts_with("[[") || raw.contains("],["),
                "non-UTF-8 path should serialize as a byte array: {raw}"
            );
            // 0xFF must appear as 255 in the JSON byte array (not U+FFFD).
            assert!(
                raw.contains("255"),
                "0xFF byte must be preserved in registry JSON: {raw}"
            );
            assert!(
                !raw.contains('\u{FFFD}'),
                "registry must not contain U+FFFD from to_string_lossy: {raw}"
            );

            env::remove_var("CREDENTIALS_LEGACY_DIR");
        }
    }

    #[test]
    fn delete_tombstone_blocks_remigration_from_missed_cwd_file() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let original = env::current_dir().unwrap();
        let old_cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(old_cwd.path()).unwrap();
        fs::create_dir_all("credentials").unwrap();
        let leftover = PathBuf::from("credentials/gemini.json");
        fs::write(
            &leftover,
            r#"{"username":"u","password":"p","service":"gemini"}"#,
        )
        .unwrap();

        // Delete after the leftover exists: tombstone timestamp is >= file mtime.
        mark_credentials_deleted("gemini").unwrap();
        assert!(credentials_were_deleted("gemini"));

        let deleted_at = credentials_deleted_at("gemini").unwrap().unwrap();
        remove_legacy_files_with_cutoff("gemini", Some(deleted_at)).unwrap();
        assert!(
            !leftover.exists(),
            "pre-delete leftover must be scrubbed by timed tombstone"
        );
        assert!(credentials_were_deleted("gemini"));
        assert!(read_legacy_credentials_file("gemini").unwrap().is_none());

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn delete_tombstone_allows_newer_legacy_save_to_remigrate() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let original = env::current_dir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        env::set_current_dir(cwd.path()).unwrap();

        // Backdate the tombstone so a subsequent old-build save is clearly newer.
        let dir = legacy_credentials_app_data_dir().unwrap();
        fs::create_dir_all(&dir).unwrap();
        let past_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .saturating_sub(60_000);
        fs::write(
            deletion_tombstone_path("gemini").unwrap(),
            past_millis.to_string(),
        )
        .unwrap();

        fs::create_dir_all("credentials").unwrap();
        fs::write(
            "credentials/gemini.json",
            r#"{"username":"fresh","password":"new","service":"gemini"}"#,
        )
        .unwrap();

        let deleted_at = credentials_deleted_at("gemini").unwrap().unwrap();
        remove_legacy_files_with_cutoff("gemini", Some(deleted_at)).unwrap();
        let loaded = read_legacy_credentials_file("gemini").unwrap().unwrap();
        assert_eq!(loaded.username, "fresh");
        assert_eq!(loaded.password, "new");

        env::set_current_dir(original).unwrap();
        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn credentials_deleted_at_fails_closed_on_malformed_tombstone() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let dir = legacy_credentials_app_data_dir().unwrap();
        fs::create_dir_all(&dir).unwrap();
        let tombstone = deletion_tombstone_path("gemini").unwrap();
        fs::write(&tombstone, "not-a-timestamp").unwrap();

        let deleted_at = credentials_deleted_at("gemini")
            .expect("malformed tombstone must fail closed, not look absent");
        assert!(
            deleted_at.is_some(),
            "malformed marker must preserve deletion suppression"
        );

        // Quarantine rewrite should leave a parseable millisecond timestamp.
        let rewritten = fs::read_to_string(&tombstone).unwrap();
        assert!(
            rewritten.trim().parse::<u128>().is_ok(),
            "quarantine rewrite must store a numeric timestamp, got {rewritten:?}"
        );

        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn credentials_deleted_at_fails_closed_on_truncated_numeric_tombstone() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let dir = legacy_credentials_app_data_dir().unwrap();
        fs::create_dir_all(&dir).unwrap();
        let tombstone = deletion_tombstone_path("gemini").unwrap();
        // Interrupted write of a millisecond timestamp can leave a short prefix
        // that still parses as an integer — but as a 1970-era seconds cutoff.
        fs::write(&tombstone, "17").unwrap();

        let deleted_at = credentials_deleted_at("gemini")
            .expect("truncated numeric tombstone must fail closed");
        let cutoff = deleted_at.expect("must preserve deletion suppression");
        let cutoff_secs = cutoff
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            cutoff_secs >= MIN_PLAUSIBLE_DELETION_SECS,
            "quarantined cutoff must not be a 1970-era truncated parse, got {cutoff_secs}"
        );

        let rewritten: u128 = fs::read_to_string(&tombstone).unwrap().trim().parse().unwrap();
        assert!(
            rewritten >= MIN_PLAUSIBLE_DELETION_MILLIS,
            "quarantine rewrite must be a plausible millisecond timestamp, got {rewritten}"
        );

        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn credentials_deleted_at_fails_closed_on_u64_overflow_tombstone() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let dir = legacy_credentials_app_data_dir().unwrap();
        fs::create_dir_all(&dir).unwrap();
        let tombstone = deletion_tombstone_path("gemini").unwrap();
        // u64::MAX + 1 parses as u128 but wraps to 0 under `as u64`.
        fs::write(&tombstone, "18446744073709551616").unwrap();

        let deleted_at = credentials_deleted_at("gemini")
            .expect("overflow tombstone must fail closed, not wrap to epoch");
        let cutoff = deleted_at.expect("must preserve deletion suppression");
        let cutoff_secs = cutoff
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            cutoff_secs >= MIN_PLAUSIBLE_DELETION_SECS,
            "overflow wrap must not yield a 1970-era cutoff, got {cutoff_secs}"
        );

        let rewritten: u128 = fs::read_to_string(&tombstone).unwrap().trim().parse().unwrap();
        assert!(
            rewritten >= MIN_PLAUSIBLE_DELETION_MILLIS,
            "quarantine rewrite must be a plausible millisecond timestamp, got {rewritten}"
        );
        assert!(
            rewritten <= u128::from(u64::MAX),
            "rewritten tombstone must fit in u64 millis"
        );

        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn credentials_deleted_at_fails_closed_on_u64_max_range_tombstone() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let dir = legacy_credentials_app_data_dir().unwrap();
        fs::create_dir_all(&dir).unwrap();
        let tombstone = deletion_tombstone_path("gemini").unwrap();
        // Fits in u64 but overflows/far-futures SystemTime via unchecked add.
        fs::write(&tombstone, u64::MAX.to_string()).unwrap();

        let deleted_at = credentials_deleted_at("gemini")
            .expect("u64::MAX tombstone must fail closed without panicking");
        let cutoff = deleted_at.expect("must preserve deletion suppression");
        assert!(
            cutoff <= SystemTime::now(),
            "quarantined cutoff must not be a remote-future freeze"
        );

        let rewritten: u128 = fs::read_to_string(&tombstone).unwrap().trim().parse().unwrap();
        assert!(
            rewritten >= MIN_PLAUSIBLE_DELETION_MILLIS,
            "quarantine rewrite must be a plausible millisecond timestamp, got {rewritten}"
        );
        assert!(
            rewritten <= u128::from(u64::MAX),
            "rewritten tombstone must fit in u64 millis"
        );
        // Rewritten value must itself be representable and not far-future.
        let rewritten_time = UNIX_EPOCH
            .checked_add(Duration::from_millis(rewritten as u64))
            .expect("rewritten millis must be representable");
        assert!(
            rewritten_time <= SystemTime::now(),
            "rewritten tombstone must not remain a remote-future cutoff"
        );

        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn quarantine_tombstone_propagates_write_failures() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        let dir = legacy_credentials_app_data_dir().unwrap();
        fs::create_dir_all(&dir).unwrap();
        let tombstone = deletion_tombstone_path("gemini").unwrap();
        fs::write(&tombstone, "not-a-timestamp").unwrap();

        // Make the credentials app-data directory read-only so quarantine rewrite fails.
        let mut perms = fs::metadata(&dir).unwrap().permissions();
        let original_readonly = perms.readonly();
        perms.set_readonly(true);
        fs::set_permissions(&dir, perms).unwrap();

        let result = credentials_deleted_at("gemini");

        let mut restore = fs::metadata(&dir).unwrap().permissions();
        restore.set_readonly(original_readonly);
        fs::set_permissions(&dir, restore).unwrap();

        let err = result.expect_err(
            "quarantine write failure must propagate, not return a moving now cutoff",
        );
        assert!(
            !err.is_empty(),
            "expected a non-empty quarantine write error"
        );
        // Malformed marker must remain until a stable rewrite succeeds.
        assert_eq!(
            fs::read_to_string(&tombstone).unwrap().trim(),
            "not-a-timestamp"
        );

        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn path_helpers_reject_path_like_service_names() {
        let _guard = test_guard();
        let legacy_root = tempfile::tempdir().unwrap();
        env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
        env::remove_var("CREDENTIALS_LEGACY_ROOTS");

        for evil in [
            "/tmp/item",
            "../escape",
            "gemini/../poe",
            "foo\\bar",
            "unknown",
        ] {
            let tombstone_err = deletion_tombstone_path(evil).expect_err("must reject");
            assert!(
                tombstone_err.contains("unsupported credentials service"),
                "unexpected tombstone error for {evil:?}: {tombstone_err}"
            );
            let legacy_err = legacy_credentials_paths(evil).expect_err("must reject");
            assert!(
                legacy_err.contains("unsupported credentials service"),
                "unexpected legacy path error for {evil:?}: {legacy_err}"
            );
            let delete_err = delete_credentials(evil).expect_err("public delete must reject");
            assert!(
                delete_err.contains("unsupported credentials service"),
                "unexpected delete error for {evil:?}: {delete_err}"
            );
            // Absolute services must never create files outside app-data.
            assert!(
                !Path::new("/tmp/item.deleted").exists(),
                "must not write escaped tombstone for {evil:?}"
            );
        }

        // Supported names still resolve under the configured app-data dir.
        let ok = deletion_tombstone_path("gemini").unwrap();
        assert!(
            ok.starts_with(legacy_root.path()),
            "supported tombstone must stay under app-data, got {}",
            ok.display()
        );

        env::remove_var("CREDENTIALS_LEGACY_DIR");
    }

    #[test]
    fn bootstrap_candidates_do_not_walk_arbitrary_ancestors() {
        let candidates = bootstrap_legacy_root_candidates();
        if let Ok(exe) = env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                let is_macos_bundle = exe_dir.ends_with("Contents/MacOS");
                if !is_macos_bundle {
                    // Non-bundle launches: only the exe directory itself.
                    assert_eq!(
                        candidates,
                        vec![exe_dir.join("credentials")],
                        "must not walk arbitrary parents outside a .app bundle"
                    );
                } else if let Some(install_dir) = exe_dir
                    .parent() // Contents
                    .and_then(|c| c.parent()) // Foo.app
                    .and_then(|app| app.parent())
                {
                    let install_creds = install_dir.join("credentials");
                    assert!(
                        !candidates
                            .iter()
                            .any(|p| paths_equivalent(p, &install_creds)),
                        "install-dir credentials ({}) must not be a guessed legacy root",
                        install_creds.display()
                    );
                }
            }
        }
        if let Some(home) = dirs::home_dir() {
            let home_creds = home.join("credentials");
            assert!(
                !candidates.iter().any(|p| paths_equivalent(p, &home_creds)),
                "generic ~/credentials must not be seeded by ancestor walk"
            );
        }
    }

    #[test]
    fn macos_bundle_roots_stay_inside_app_not_install_parent() {
        let macos = PathBuf::from("/Users/me/Downloads/ChatGPT.app/Contents/MacOS");
        let roots = macos_bundle_internal_legacy_roots(&macos);
        assert_eq!(
            roots,
            vec![
                PathBuf::from("/Users/me/Downloads/ChatGPT.app/Contents/credentials"),
                PathBuf::from("/Users/me/Downloads/ChatGPT.app/credentials"),
            ]
        );
        assert!(
            !roots
                .iter()
                .any(|p| p == &PathBuf::from("/Users/me/Downloads/credentials")),
            "must not treat the .app install parent as a legacy root"
        );

        let non_bundle = PathBuf::from("/Users/me/Downloads/App/bin");
        assert!(macos_bundle_internal_legacy_roots(&non_bundle).is_empty());
    }

    #[test]
    fn remove_legacy_if_snapshot_unchanged_refuses_changed_file() {
        with_temp_cwd(|| {
            fs::create_dir_all("credentials").unwrap();
            let path = PathBuf::from("credentials/gemini.json");
            fs::write(
                &path,
                r#"{"username":"old","password":"oldpass","service":"gemini"}"#,
            )
            .unwrap();
            let (expected, expected_mtime) = read_freshest_legacy_credentials("gemini")
                .unwrap()
                .expect("legacy present");

            // Simulate an older unlocked build rewriting after our decision.
            fs::write(
                &path,
                r#"{"username":"fresh","password":"newpass","service":"gemini"}"#,
            )
            .unwrap();

            match remove_legacy_if_snapshot_unchanged("gemini", &expected, expected_mtime).unwrap()
            {
                LegacyCleanupOutcome::Cleared => {
                    panic!("changed legacy file must not be deleted")
                }
                LegacyCleanupOutcome::Changed {
                    credentials,
                    mtime: _,
                } => {
                    assert_eq!(credentials.username, "fresh");
                    assert_eq!(credentials.password, "newpass");
                    assert!(
                        path.exists(),
                        "changed plaintext must remain for reconciliation"
                    );
                }
            }
        });
    }

    #[test]
    fn credentials_deleted_at_propagates_tombstone_read_errors() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let _guard = test_guard();
            let legacy_root = tempfile::tempdir().unwrap();
            env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
            env::remove_var("CREDENTIALS_LEGACY_ROOTS");

            let dir = legacy_credentials_app_data_dir().unwrap();
            fs::create_dir_all(&dir).unwrap();
            let tombstone = deletion_tombstone_path("gemini").unwrap();
            fs::write(&tombstone, "1234567890123").unwrap();
            fs::set_permissions(&tombstone, fs::Permissions::from_mode(0o000)).unwrap();

            let err = credentials_deleted_at("gemini");

            let _ = fs::set_permissions(&tombstone, fs::Permissions::from_mode(0o644));
            env::remove_var("CREDENTIALS_LEGACY_DIR");

            assert!(
                err.is_err(),
                "unreadable tombstone must not be treated as absent"
            );
            let msg = err.unwrap_err();
            assert!(
                msg.contains("read deletion tombstone"),
                "unexpected error: {msg}"
            );
        }
    }

    #[test]
    fn reconcile_prefers_newer_legacy_over_stamped_keychain() {
        let keychain = KeychainPayload {
            username: "old".into(),
            password: "oldpass".into(),
            service: "gemini".into(),
            updated_at_ms: Some(1_000),
        };
        let legacy = Credentials {
            username: "new".into(),
            password: "newpass".into(),
            service: "gemini".into(),
        };
        let newer = UNIX_EPOCH + Duration::from_millis(2_000);
        let older = UNIX_EPOCH + Duration::from_millis(500);

        assert!(should_reconcile_legacy_over_keychain(
            &keychain, &legacy, newer
        ));
        assert!(!should_reconcile_legacy_over_keychain(
            &keychain, &legacy, older
        ));

        // Same secret leftovers are cleanup-only even when mtime is newer.
        let same = Credentials {
            username: "old".into(),
            password: "oldpass".into(),
            service: "gemini".into(),
        };
        assert!(!should_reconcile_legacy_over_keychain(
            &keychain, &same, newer
        ));

        // Pre-timestamp keychain entries reconcile any differing legacy save.
        let unstamped = KeychainPayload {
            updated_at_ms: None,
            ..keychain
        };
        assert!(should_reconcile_legacy_over_keychain(
            &unstamped, &legacy, older
        ));
        assert!(!should_reconcile_legacy_over_keychain(
            &unstamped, &same, newer
        ));
    }

    #[test]
    fn remove_legacy_records_source_before_delete_failure() {
        with_temp_cwd(|| {
            fs::create_dir_all("credentials").unwrap();
            let path = PathBuf::from("credentials/gemini.json");
            fs::write(
                &path,
                r#"{"username":"u","password":"p","service":"gemini"}"#,
            )
            .unwrap();

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // File is readable for schema inspect, but not deletable.
                fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
                let mut dir_perms = fs::metadata("credentials").unwrap().permissions();
                dir_perms.set_mode(0o555);
                fs::set_permissions("credentials", dir_perms).unwrap();

                let err = remove_legacy_file("gemini");
                assert!(err.is_err(), "immutable dir should block delete");

                // Restore permissions for assertions / cleanup.
                fs::set_permissions("credentials", fs::Permissions::from_mode(0o755)).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

                let roots = load_recorded_legacy_roots().unwrap();
                let cwd_creds = env::current_dir().unwrap().join("credentials");
                assert!(
                    roots.iter().any(|r| paths_equivalent(r, &cwd_creds)),
                    "failed delete must still record the discovered CWD root; got {roots:?}"
                );
            }
            #[cfg(not(unix))]
            {
                let _ = remove_legacy_file("gemini");
            }
        });
    }

    #[test]
    fn bootstrap_seed_ignores_unreadable_unrelated_json() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let _guard = test_guard();
            let legacy_root = tempfile::tempdir().unwrap();
            env::set_var("CREDENTIALS_LEGACY_DIR", legacy_root.path());
            env::remove_var("CREDENTIALS_LEGACY_ROOTS");

            let candidates = bootstrap_legacy_root_candidates();
            let seed_dir = candidates
                .first()
                .expect("bootstrap should include an exe-relative credentials dir");
            fs::create_dir_all(seed_dir).unwrap();
            let foreign = seed_dir.join("other.json");
            let gemini = seed_dir.join("gemini.json");
            fs::write(&foreign, r#"{"not":"ours"}"#).unwrap();
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o000)).unwrap();
            fs::write(
                &gemini,
                r#"{"username":"u","password":"p","service":"gemini"}"#,
            )
            .unwrap();

            let result = seed_registry_from_bootstrap_locations();

            let _ = fs::set_permissions(&foreign, fs::Permissions::from_mode(0o644));
            let _ = fs::remove_file(&foreign);
            let _ = fs::remove_file(&gemini);

            result.expect("unreadable unrelated JSON must not abort bootstrap seeding");
            let roots = load_recorded_legacy_roots().unwrap();
            assert!(
                roots.iter().any(|r| paths_equivalent(r, seed_dir)),
                "bootstrap must seed the dir that contains a valid app credential; got {roots:?}"
            );

            env::remove_var("CREDENTIALS_LEGACY_DIR");
        }
    }

    #[test]
    fn remove_legacy_propagates_parent_metadata_errors() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            with_temp_cwd(|| {
                fs::create_dir_all("credentials").unwrap();
                let path = PathBuf::from("credentials/gemini.json");
                fs::write(
                    &path,
                    r#"{"username":"u","password":"p","service":"gemini"}"#,
                )
                .unwrap();

                // Remove execute bit so metadata on the child fails (exists() would
                // mask this as "not present").
                fs::set_permissions("credentials", fs::Permissions::from_mode(0o000)).unwrap();

                let err = remove_legacy_file("gemini");

                fs::set_permissions("credentials", fs::Permissions::from_mode(0o755)).unwrap();

                assert!(
                    err.is_err(),
                    "inaccessible parent must surface a metadata/stat error"
                );
                let msg = err.unwrap_err();
                assert!(
                    msg.contains("stat legacy credentials"),
                    "unexpected error: {msg}"
                );
            });
        }
    }

    #[test]
    fn remove_legacy_clears_app_data_and_cwd_locations() {
        let _guard = test_guard();
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
