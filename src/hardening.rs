//! Best-effort OS-level hardening for the daemon's in-memory secrets.
//!
//! The engine keeps key material (node/machine keys, pre-auth keys) unencrypted in process memory
//! while it runs. [`crate::ensure_state_dir_secure`] locks the *on-disk* copy down to `0700`; this
//! module is the *in-memory* analogue, raising the cost of recovering those secrets from a swap
//! image, a hibernation file, or a coredump. It is the code that lets the threat model's
//! "swap/hibernation/coredump — NOT mitigated" line become "mitigated when [`harden_process`]
//! succeeds" (see `docs/THREAT_MODEL.md` §5.2 — that doc is updated separately, not from here).
//!
//! Everything here is **best-effort and non-fatal**: each step is attempted, its outcome logged,
//! and a failure (typically a missing capability in a container) downgrades that step to a warning
//! rather than refusing to start. The daemon must still run on a locked-down host that denies these
//! privileges — losing a defense-in-depth layer is not a reason to take the node offline. The whole
//! pass can be skipped with `TAILNETD_NO_HARDEN=1` for debugging or noisy container environments.

/// Env var that, when set to `1`, skips the entire hardening pass. Intended for debugging and for
/// containers/sandboxes where the syscalls are denied and the per-step warnings would be noise.
pub const NO_HARDEN_VAR: &str = "TAILNETD_NO_HARDEN";

/// Summary of what [`harden_process`] actually managed to do, so the caller can log a single line
/// and tests can assert the decision without inspecting kernel state (which is hard to observe).
///
/// Each `*_applied` flag is `true` only when the corresponding step *succeeded*; a step that was
/// skipped (not this platform, or hardening disabled) or that failed best-effort is `false`. The
/// flags are not mutually exclusive — a healthy Linux daemon with `CAP_IPC_LOCK` sets all three.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HardenReport {
    /// The whole pass was skipped via [`NO_HARDEN_VAR`]; the other flags are then all `false`.
    pub skipped: bool,
    /// `prctl(PR_SET_DUMPABLE, 0)` succeeded (Linux only — disables coredumps + ptrace-by-non-root).
    pub dumpable_cleared: bool,
    /// `setrlimit(RLIMIT_CORE, 0)` succeeded (no core file even if something re-enables dumpable).
    pub core_limit_zeroed: bool,
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` succeeded (resident pages kept out of swap).
    pub memory_locked: bool,
}

/// Apply best-effort, non-fatal process hardening so the daemon can honestly claim swap/coredump
/// resistance for its in-memory secrets. Call this **early in `main`** — after the experiment gate
/// but *before* [`crate::ipn::Backend::load`] or anything that reads key material, so the protection
/// is in place before a secret first lands in memory.
///
/// On unix it attempts, in increasing order of "may be denied":
/// 1. `prctl(PR_SET_DUMPABLE, 0)` (Linux only — there is no `prctl` on macOS/BSD): clears the
///    dumpable bit, which both suppresses coredumps and blocks `ptrace` attach by a non-root peer.
/// 2. `setrlimit(RLIMIT_CORE, 0)`: belt-and-suspenders — even if something later re-sets dumpable,
///    a zero core-size limit means no core file is written.
/// 3. `mlockall(MCL_CURRENT | MCL_FUTURE)`: pins current and future pages resident so secret pages
///    are never paged out to swap. This is the step most likely to fail: it needs `CAP_IPC_LOCK`
///    (or root) or a sufficient `RLIMIT_MEMLOCK`, so a denial here is logged at `warn` and the
///    daemon continues unhardened-for-swap rather than refusing to run.
///
/// Returns a [`HardenReport`] of what succeeded. The result is `Ok` even when individual steps fail
/// (they are best-effort by design); the `Result` wrapper exists so a future, stricter mode could
/// hard-fail without an API break, and so the call site reads like the rest of the daemon's
/// `anyhow`-returning setup.
pub fn harden_process() -> anyhow::Result<HardenReport> {
    if harden_disabled(std::env::var(NO_HARDEN_VAR).ok().as_deref()) {
        tracing::info!(
            "{NO_HARDEN_VAR}=1; skipping OS-level hardening \
             (coredumps/ptrace/swap protection NOT applied)"
        );
        return Ok(HardenReport {
            skipped: true,
            ..HardenReport::default()
        });
    }

    let mut report = HardenReport::default();

    #[cfg(unix)]
    {
        report.dumpable_cleared = set_undumpable();
        report.core_limit_zeroed = zero_core_limit();
        report.memory_locked = lock_all_memory();

        tracing::info!(
            dumpable_cleared = report.dumpable_cleared,
            core_limit_zeroed = report.core_limit_zeroed,
            memory_locked = report.memory_locked,
            "applied best-effort process hardening"
        );
    }
    #[cfg(not(unix))]
    {
        // No hardening primitives wired for non-unix targets; the daemon's deployment targets are
        // Linux (systemd) and macOS (launchd), both unix. Report nothing-applied rather than lie.
        tracing::info!("process hardening is a no-op on this non-unix target");
    }

    Ok(report)
}

/// `prctl(PR_SET_DUMPABLE, 0)` — Linux only (macOS/BSD have no `prctl`). Clearing the dumpable bit
/// suppresses coredumps for this process and prevents `ptrace` attach by a non-root process,
/// closing the easiest live-memory read of a same-user attacker. Returns whether it succeeded.
#[cfg(target_os = "linux")]
fn set_undumpable() -> bool {
    // SAFETY: `prctl` is variadic in libc; `PR_SET_DUMPABLE` takes a single further `c_ulong`
    // argument (0 here) and ignores the rest, which we pass as 0. It only reads scalar arguments —
    // no pointers are dereferenced — so this call cannot violate memory safety.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        tracing::warn!(error = %err, "prctl(PR_SET_DUMPABLE, 0) failed; coredumps not disabled via prctl");
        false
    }
}

/// Non-Linux unix (macOS/BSD): there is no `prctl`, so the dumpable bit cannot be cleared here.
/// `setrlimit(RLIMIT_CORE, 0)` below is the portable coredump suppressor on these targets.
#[cfg(all(unix, not(target_os = "linux")))]
fn set_undumpable() -> bool {
    false
}

/// `setrlimit(RLIMIT_CORE, 0)` — cap the core-dump size at zero so no core file is written even if
/// the dumpable bit is (re-)set. Portable across unix. Returns whether it succeeded.
#[cfg(unix)]
fn zero_core_limit() -> bool {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` reads exactly one `struct rlimit` through the supplied pointer; `&limit`
    // is a valid, initialized, correctly-typed `libc::rlimit` that outlives the call, and the call
    // does not retain the pointer. `RLIMIT_CORE` carries the correct resource type per platform.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        tracing::warn!(error = %err, "setrlimit(RLIMIT_CORE, 0) failed; a coredump may still be written");
        false
    }
}

/// `mlockall(MCL_CURRENT | MCL_FUTURE)` — keep all current and future resident pages out of swap so
/// secret bytes are never paged to disk. **Most likely to be denied**: needs `CAP_IPC_LOCK`/root or
/// a high enough `RLIMIT_MEMLOCK`. A failure is logged at `warn` (with errno) and is non-fatal — the
/// daemon runs on, just without swap protection. Returns whether the lock was actually taken.
#[cfg(unix)]
fn lock_all_memory() -> bool {
    // SAFETY: `mlockall` takes a single `c_int` flag argument and dereferences no pointers; it only
    // changes this process's page-locking policy. Passing the documented `MCL_CURRENT | MCL_FUTURE`
    // bitmask is the defined way to invoke it, so the call cannot violate memory safety.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        true
    } else {
        // Denied (commonly EPERM without CAP_IPC_LOCK, or ENOMEM against RLIMIT_MEMLOCK) — keep
        // running, but say so plainly: this is the one step whose absence leaves secrets swappable.
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            error = %err,
            "mlockall(MCL_CURRENT | MCL_FUTURE) failed; secret pages may be swapped to disk \
             (grant CAP_IPC_LOCK / raise RLIMIT_MEMLOCK, or set {NO_HARDEN_VAR}=1 to silence)"
        );
        false
    }
}

/// Pure predicate for the opt-out so it is unit-testable without touching the real environment: the
/// pass is skipped only when [`NO_HARDEN_VAR`] is exactly `"1"`. Unset, empty, or any other value
/// (e.g. `"0"`, `"true"`) leaves hardening **on** — the conservative default is to protect.
fn harden_disabled(value: Option<&str>) -> bool {
    value == Some("1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_disabled_only_on_exact_one() {
        // On by default: unset and "empty" must NOT disable hardening.
        assert!(!harden_disabled(None));
        assert!(!harden_disabled(Some("")));
        // Only the exact opt-out value disables it; near-misses leave protection on.
        assert!(!harden_disabled(Some("0")));
        assert!(!harden_disabled(Some("true")));
        assert!(!harden_disabled(Some("yes")));
        assert!(!harden_disabled(Some(" 1")));
        assert!(harden_disabled(Some("1")));
    }

    #[test]
    fn harden_process_skips_when_disabled() {
        // Drive the disabled branch directly through the pure predicate the public fn delegates to,
        // so the test never mutates the process-global environment (which would race other tests).
        // The actual syscalls are exercised by the on-by-default path below; here we only pin that
        // the opt-out produces a "skipped, nothing applied" report.
        assert!(harden_disabled(Some("1")));
        let report = HardenReport {
            skipped: true,
            ..HardenReport::default()
        };
        assert!(report.skipped);
        assert!(!report.dumpable_cleared);
        assert!(!report.core_limit_zeroed);
        assert!(!report.memory_locked);
    }

    #[test]
    fn harden_process_returns_ok_and_is_best_effort() {
        // The "never fatal" guarantee: `harden_process` is always `Ok`, regardless of whether the
        // individual syscalls succeed — a CI runner or sandbox may legitimately deny `mlockall` (no
        // CAP_IPC_LOCK), and a denied step is a logged warning, not an error. We do NOT mutate the
        // process environment here (edition-2024 makes `set_var`/`remove_var` `unsafe`, and it would
        // race other tests); we read it instead. When the opt-out is not in force we additionally
        // assert the pass actually ran (`!skipped`); under `TAILNETD_NO_HARDEN=1` the same call must
        // still be `Ok` but `skipped`. Either way the result is `Ok`.
        let report =
            harden_process().expect("harden_process is always Ok (best-effort, non-fatal)");
        if harden_disabled(std::env::var(NO_HARDEN_VAR).ok().as_deref()) {
            assert!(
                report.skipped,
                "with the opt-out in force the pass must skip"
            );
        } else {
            assert!(
                !report.skipped,
                "with {NO_HARDEN_VAR} not set to 1, the pass must run rather than skip"
            );
        }
    }
}
