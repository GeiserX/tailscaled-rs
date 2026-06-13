//! System-policy (MDM) resolution — the Rust analogue of Go's `util/syspolicy`.
//!
//! Go resolves an **effective policy** by merging zero or more registered policy *stores* into a
//! single `setting.Snapshot` (a map of policy-key → {value, origin, error}). The `tailscale
//! syspolicy list` / `reload` commands print that snapshot. On **Windows** Go registers the
//! registry-backed `Platform` store (HKLM for the device scope, HKCU for the user scope). On
//! **Linux/Unix** — and in this daemon — **no policy store is registered**, so the effective policy
//! is always an empty-but-valid snapshot: `syspolicy list` prints "No policy settings", and `reload`
//! returns the same empty snapshot (never an error).
//!
//! This matches Go's *runtime* behavior on Linux exactly. Go ships an in-tree `EnvPolicyStore`
//! (env-var sourced, `TS_DEBUGSYSPOLICY_*` prefixed) but **never registers it by default** — so a
//! faithful port likewise reads no environment or file source. Registering one would make this
//! daemon report policy where upstream Go reports none, i.e. a behavioral *deviation*, so we do not.
//!
//! The model below is the real (if currently source-less) merge point: [`registered_store_settings`]
//! is the single authority for "which stores contribute settings," so a future managed-platform
//! source (macOS configuration profiles, an explicit opt-in store, …) would populate the snapshot
//! here without reshaping the LocalAPI wire or the CLI renderer.
//!
//! Scope: Go's CLI always resolves `setting.DefaultScope()`, which is the **device scope** on every
//! non-Windows platform. We record that as the report's scope and do not parameterize it (the CLI
//! never varies it); profile/user scoping can be added if a real caller ever needs it.

use crate::localapi::{PolicyReport, PolicySetting};

/// The scope name the CLI resolves, matching Go `setting.DefaultScope().String()` on non-Windows
/// hosts (`"Device"`). Centralized so the report and any future scope plumbing agree on the spelling.
const DEVICE_SCOPE: &str = "Device";

/// Resolve the effective system policy (the `tnet syspolicy list` path; Go
/// `LocalClient.GetEffectivePolicy(DefaultScope())` → `rsop.PolicyFor(scope).Get()`).
///
/// Returns the merge of all registered policy stores for the device scope. This daemon (like Go on
/// Linux/Unix) registers **zero** stores, so the result is always an empty-but-valid snapshot:
/// `settings` is empty and the CLI prints "No policy settings". Never errors.
pub(super) fn effective_policy() -> PolicyReport {
    PolicyReport {
        scope: DEVICE_SCOPE.to_string(),
        settings: registered_store_settings(),
    }
}

/// Force a re-read of the effective system policy (the `tnet syspolicy reload` path; Go
/// `LocalClient.ReloadEffectivePolicy(DefaultScope())` → `rsop.PolicyFor(scope).Reload()`).
///
/// Go's `reload` forces a full re-read + re-merge of every registered source even when nothing
/// changed. With zero registered stores the forced re-read re-merges nothing, so `reload` yields the
/// same empty snapshot as [`effective_policy`] — observationally identical here, but kept a distinct
/// verb (faithful to Go, and the place a real re-read would happen the moment a source is
/// registered). Never errors.
pub(super) fn reload_effective_policy() -> PolicyReport {
    // No registered stores → the forced re-read has nothing to re-read; the merge is empty. The two
    // verbs diverge only once a source exists (this is where the source would be re-read).
    PolicyReport {
        scope: DEVICE_SCOPE.to_string(),
        settings: registered_store_settings(),
    }
}

/// The merged settings from every registered policy store, for the device scope.
///
/// EMPTY on this platform: no policy store is registered. (Go registers a store only in
/// `syspolicy_windows.go`; its in-tree `EnvPolicyStore` is never registered by default, so we read
/// no env/file source either.) This is the single seam a future managed-platform source would
/// extend — it returns the contributed settings, which the snapshot then carries through the
/// LocalAPI to the CLI unchanged.
///
/// INVARIANT for any future store wired in here: reading/reloading it MUST be side-effect-free. The
/// `syspolicy list`/`reload` LocalAPI is classified read-only (`auth::requires_write` → false,
/// gated on `PermitRead`, matching Go's `policy/` handler). If a registered store's read ever
/// performs an observable action (writes a cache as the daemon's uid, fetches over the network,
/// spawns a helper), that classification becomes too weak — a non-owner read-only caller could drive
/// the side effect. In that case, reclassify `Request::SyspolicyReload` (at least) as a write in
/// `auth.rs` before wiring the store.
fn registered_store_settings() -> Vec<PolicySetting> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_empty_device_scoped_on_this_platform() {
        // Faithful to Go on Linux: zero registered stores → empty snapshot, device scope, no error.
        let r = effective_policy();
        assert_eq!(r.scope, "Device");
        assert!(
            r.settings.is_empty(),
            "no policy store is registered on this platform; the effective policy must be empty"
        );
    }

    #[test]
    fn reload_matches_list_with_no_sources() {
        // With zero sources the forced re-read yields the same empty snapshot as `list`.
        assert_eq!(reload_effective_policy(), effective_policy());
    }

    #[test]
    fn reload_is_device_scoped_and_empty() {
        let r = reload_effective_policy();
        assert_eq!(r.scope, "Device");
        assert!(r.settings.is_empty());
    }
}
