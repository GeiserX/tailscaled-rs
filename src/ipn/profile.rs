//! Multi-profile state layout — the Rust analogue of Go's `profileManager` (`ipn/ipnlocal/
//! profiles.go`) over the `StateStore` key scheme (`ipn/store.go`).
//!
//! ## Layout (backward-compatible by construction)
//!
//! A daemon persists each profile's prefs + node key as two files. The **default** profile lives at
//! the *existing* top-level paths so a pre-profiles install keeps working untouched (no migration,
//! no data movement — the safest possible upgrade for state that includes a node key):
//!
//! ```text
//! <state_dir>/prefs.json            ← default profile's prefs   (unchanged legacy path)
//! <state_dir>/node.key.json         ← default profile's node key (unchanged legacy path)
//! <state_dir>/profiles/<id>/prefs.json      ← a named profile's prefs
//! <state_dir>/profiles/<id>/node.key.json   ← a named profile's node key
//! <state_dir>/profiles.json         ← metadata map: { "<id>": { "name": "<display>" } }
//! <state_dir>/current-profile       ← the current profile id (absent ⇒ "default")
//! ```
//!
//! This mirrors Go's design where the device **machine key is shared** and only the **prefs blob
//! (which carries the node key) is per-profile** — here each profile simply owns its own
//! `prefs.json` + `node.key.json`, and switching swaps which pair is active. The `default` id is the
//! reserved analogue of Go's migrated legacy `_daemon` state.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The reserved id of the always-present default profile (lives at the legacy top-level paths).
pub(super) const DEFAULT_PROFILE_ID: &str = "default";

/// One profile's metadata (the analogue of the parts of Go's `ipn.LoginProfile` we can fill). The
/// prefs + node key themselves live in the profile's files, not here.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct ProfileMeta {
    /// User-visible display name. Defaults to the id when unset.
    #[serde(default)]
    pub(super) name: String,
}

/// The on-disk `profiles.json` metadata map (id → [`ProfileMeta`]). The default profile is implicit
/// (it always exists) and is included here once it has been touched, so `--list` can show it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct ProfilesFile {
    /// All known profiles, keyed by id. The default profile may or may not appear; callers always
    /// treat [`DEFAULT_PROFILE_ID`] as existing regardless.
    #[serde(default)]
    pub(super) profiles: std::collections::BTreeMap<String, ProfileMeta>,
}

/// Whether `id` is a syntactically valid profile id: non-empty, and only `[A-Za-z0-9_-]` so it is a
/// safe single path component (no traversal, no separators). The reserved `default` is valid.
pub(super) fn is_valid_profile_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Resolve a user-supplied `tnet switch <target>` to a canonical profile **id**, matching by id OR by
/// display name (Go's `tailscale switch` accepts either). Precedence, mirroring Go (id wins over name
/// so an exact-id target is never shadowed by a coincidental name):
/// 1. `target` is a valid id that names a known profile (the reserved [`DEFAULT_PROFILE_ID`], or a key
///    present in `profiles.json`) → that id.
/// 2. exactly ONE profile's [`ProfileMeta::name`] equals `target` → that profile's id.
/// 3. otherwise `None` — the caller reports an error. A name matching MULTIPLE ids is ambiguous and
///    also yields `None` (the caller must be told to use the id), never an arbitrary pick.
///
/// Pure over the parsed `profiles.json` (no I/O) so it is unit-testable; the caller loads the file.
/// Note a *syntactically* valid id that is NOT yet a known profile is intentionally left to the
/// caller (switching to a brand-new id is how a new profile is created), so this returns `None` for
/// it and the caller falls back to its own id-validation path — see the `switch_profile` call site.
pub(super) fn resolve_target_to_id(target: &str, meta: &ProfilesFile) -> Option<String> {
    // 1. Exact id match against a KNOWN profile (default is always known).
    if is_valid_profile_id(target)
        && (target == DEFAULT_PROFILE_ID || meta.profiles.contains_key(target))
    {
        return Some(target.to_string());
    }
    // 2. Unique display-name match. Collect all ids whose name equals `target`; resolve only if
    //    exactly one (an ambiguous name must not silently pick one).
    let mut by_name = meta
        .profiles
        .iter()
        .filter(|(_, m)| m.name == target)
        .map(|(id, _)| id.clone());
    let first = by_name.next()?;
    if by_name.next().is_some() {
        return None; // ambiguous: >1 profile shares this name → caller errors, user must use the id.
    }
    Some(first)
}

/// The `(prefs.json, node.key.json)` paths for profile `id` under `state_dir`. The default profile
/// maps to the legacy top-level paths (so existing installs are untouched); every other profile maps
/// under `profiles/<id>/`. `id` MUST already be validated by [`is_valid_profile_id`] — this joins it
/// as a path component.
pub(super) fn profile_paths(state_dir: &Path, id: &str) -> (PathBuf, PathBuf) {
    if id == DEFAULT_PROFILE_ID {
        (
            state_dir.join("prefs.json"),
            state_dir.join("node.key.json"),
        )
    } else {
        let dir = state_dir.join("profiles").join(id);
        (dir.join("prefs.json"), dir.join("node.key.json"))
    }
}

/// Path of the `current-profile` pointer file.
pub(super) fn current_profile_path(state_dir: &Path) -> PathBuf {
    state_dir.join("current-profile")
}

/// Path of the `profiles.json` metadata file.
pub(super) fn profiles_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join("profiles.json")
}

/// Read the current profile id from the pointer file. A missing/empty/unreadable/invalid pointer
/// falls back to [`DEFAULT_PROFILE_ID`] — so a fresh or legacy daemon (no pointer file) is always on
/// the default profile, which is exactly the legacy top-level layout.
pub(super) async fn load_current_profile(state_dir: &Path) -> String {
    let path = current_profile_path(state_dir);
    match tokio::fs::read_to_string(&path).await {
        Ok(s) => {
            let id = s.trim();
            if is_valid_profile_id(id) {
                id.to_string()
            } else {
                DEFAULT_PROFILE_ID.to_string()
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DEFAULT_PROFILE_ID.to_string(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "profile: current-profile pointer unreadable; treating as default");
            DEFAULT_PROFILE_ID.to_string()
        }
    }
}

/// Atomically persist the current profile pointer (crash-safe via temp-then-rename — see
/// [`atomic_write`]). A torn pointer would otherwise be read back as invalid and silently fall back
/// to the default profile, losing the active selection.
pub(super) async fn save_current_profile(state_dir: &Path, id: &str) -> std::io::Result<()> {
    tokio::fs::create_dir_all(state_dir).await?;
    atomic_write(&current_profile_path(state_dir), id.as_bytes()).await
}

/// Load the `profiles.json` metadata map (missing/malformed → empty, with the malformed case logged
/// — the default profile still works without it).
pub(super) async fn load_profiles_file(state_dir: &Path) -> ProfilesFile {
    match tokio::fs::read(profiles_file_path(state_dir)).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "profile: profiles.json is malformed; treating as empty");
            ProfilesFile::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ProfilesFile::default(),
        Err(e) => {
            tracing::warn!(error = %e, "profile: profiles file unreadable; treating as empty");
            ProfilesFile::default()
        }
    }
}

/// Persist the `profiles.json` metadata map (crash-safe via temp-then-rename — see [`atomic_write`],
/// so a crash mid-write can never truncate the map into the malformed-→-empty fallback).
pub(super) async fn save_profiles_file(state_dir: &Path, f: &ProfilesFile) -> std::io::Result<()> {
    tokio::fs::create_dir_all(state_dir).await?;
    let bytes = serde_json::to_vec_pretty(f).expect("profiles file serialize");
    atomic_write(&profiles_file_path(state_dir), &bytes).await
}

/// Write `bytes` to `path` atomically: stage them in a temp file in the *same* directory, then
/// [`tokio::fs::rename`] it over `path` (atomic on POSIX within one filesystem). On any failure the
/// temp file is removed best-effort so no stray `.tmp` is left behind. Same-dir staging is required —
/// a cross-filesystem rename is neither atomic nor guaranteed to succeed. Both profile writers set no
/// explicit file mode, so the temp file (created in the same state dir) carries the same umask/dir
/// perms the previous in-place write produced.
async fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let mut tmp_name = file_name;
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = dir.join(tmp_name);

    if let Err(e) = tokio::fs::write(&tmp, bytes).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ids() {
        assert!(is_valid_profile_id("default"));
        assert!(is_valid_profile_id("work"));
        assert!(is_valid_profile_id("1ab3"));
        assert!(is_valid_profile_id("my-profile_2"));
        // Invalid: empty, traversal, separators, too long.
        assert!(!is_valid_profile_id(""));
        assert!(!is_valid_profile_id(".."));
        assert!(!is_valid_profile_id("a/b"));
        assert!(!is_valid_profile_id("a.b"));
        assert!(!is_valid_profile_id(&"x".repeat(65)));
    }

    #[test]
    fn default_profile_uses_legacy_top_level_paths() {
        let sd = Path::new("/var/lib/tailnetd");
        let (prefs, key) = profile_paths(sd, DEFAULT_PROFILE_ID);
        assert_eq!(prefs, sd.join("prefs.json"));
        assert_eq!(key, sd.join("node.key.json"));
    }

    #[test]
    fn named_profile_nests_under_profiles_dir() {
        let sd = Path::new("/var/lib/tailnetd");
        let (prefs, key) = profile_paths(sd, "work");
        assert_eq!(prefs, sd.join("profiles").join("work").join("prefs.json"));
        assert_eq!(key, sd.join("profiles").join("work").join("node.key.json"));
    }

    #[tokio::test]
    async fn current_profile_round_trips_and_defaults() {
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-cur-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        // Missing pointer → default.
        assert_eq!(load_current_profile(&dir).await, DEFAULT_PROFILE_ID);
        // Round-trip a real id.
        save_current_profile(&dir, "work").await.unwrap();
        assert_eq!(load_current_profile(&dir).await, "work");
        // A garbage pointer falls back to default (never an invalid path component).
        tokio::fs::write(current_profile_path(&dir), b"../evil")
            .await
            .unwrap();
        assert_eq!(load_current_profile(&dir).await, DEFAULT_PROFILE_ID);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn profiles_file_round_trips() {
        let dir = std::env::temp_dir().join(format!("tailnetd-prof-meta-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        // Missing → empty.
        assert!(load_profiles_file(&dir).await.profiles.is_empty());
        let mut f = ProfilesFile::default();
        f.profiles.insert(
            "work".to_string(),
            ProfileMeta {
                name: "Work tailnet".to_string(),
            },
        );
        save_profiles_file(&dir, &f).await.unwrap();
        let back = load_profiles_file(&dir).await;
        assert_eq!(back.profiles.get("work").unwrap().name, "Work tailnet");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn resolve_target_matches_id_name_and_handles_ambiguity() {
        let mut meta = ProfilesFile::default();
        meta.profiles.insert(
            "work".into(),
            ProfileMeta {
                name: "Work tailnet".into(),
            },
        );
        meta.profiles.insert(
            "home".into(),
            ProfileMeta {
                name: "Home".into(),
            },
        );

        // Exact id match (known profile) → that id.
        assert_eq!(resolve_target_to_id("work", &meta).as_deref(), Some("work"));
        // The reserved default is always a known id.
        assert_eq!(
            resolve_target_to_id(DEFAULT_PROFILE_ID, &meta).as_deref(),
            Some(DEFAULT_PROFILE_ID)
        );
        // Display-name match (the name has a space → not a valid id, so this proves the name path).
        assert_eq!(
            resolve_target_to_id("Work tailnet", &meta).as_deref(),
            Some("work")
        );
        // A syntactically-valid id that is NOT yet known → None (caller treats it as a new-profile id).
        assert_eq!(resolve_target_to_id("brand-new", &meta), None);
        // Neither a known id/name nor (here) relevant → None.
        assert_eq!(resolve_target_to_id("nope", &meta), None);

        // Ambiguous name (two ids share it) → None: never silently pick one.
        let mut amb = ProfilesFile::default();
        amb.profiles
            .insert("a".into(), ProfileMeta { name: "dup".into() });
        amb.profiles
            .insert("b".into(), ProfileMeta { name: "dup".into() });
        assert_eq!(resolve_target_to_id("dup", &amb), None);

        // id precedence over name: a target that is BOTH a known id AND some other profile's name
        // resolves to the id. (Set up "home" id whose name coincides with a target that is also an id.)
        let mut prec = ProfilesFile::default();
        prec.profiles.insert(
            "work".into(),
            ProfileMeta {
                name: "home".into(), // "work"'s display name is literally "home"
            },
        );
        prec.profiles.insert(
            "home".into(),
            ProfileMeta {
                name: "Home tailnet".into(),
            },
        );
        // "home" is a known id → resolves to id "home", NOT to "work" (whose name is "home").
        assert_eq!(resolve_target_to_id("home", &prec).as_deref(), Some("home"));
    }
}
