# Security Policy

## Status: experimental — do not rely on this for data privacy yet

`tailscaled-rs` is early-days software. It builds on the `tailscale-rs` engine, which contains
**unaudited cryptography** (hand-rolled WireGuard `Noise_IKpsk2` and the Tailscale control-plane
Noise handshake) and has not undergone a third-party security review. The engine deliberately
requires `TS_RS_EXPERIMENT=this_is_unstable_software` to run, as an explicit acknowledgement of
this. **Do not deploy this where a key compromise or traffic disclosure would matter** until an
independent audit has been completed.

Known limitations relevant to security:

- **Unaudited crypto** in the engine's handshake paths.
- **Tailnet Lock is not enforced** in the engine — a malicious or compromised control plane could
  inject peer node-keys.
- **Key material at rest** (node/machine keys, pre-auth keys) is persisted by the engine without
  at-rest encryption. The daemon creates its state directory and enforces `0700` on it itself (it
  tightens the mode at startup if it finds the dir group/world-accessible), so the on-disk keys are
  not exposed to other local users. It does **not**, however, mitigate a root compromise, swap, or
  coredumps — use full-disk encryption and run the daemon with `UMask=0077` (the packaged units do)
  for defence in depth.

What the daemon **does** enforce on the LocalAPI socket:

- **`SO_PEERCRED`-based authorization is implemented** (`src/auth.rs`): the daemon reads the
  connecting peer's uid from the socket and authorizes per-command. **Reads** (`status`) succeed for
  anyone who can reach the socket; **writes** (`up`/`down`, prefs mutations) are restricted to root
  (uid 0) or the daemon's own uid, and an unidentifiable peer fails **closed** (read-only). This is
  in addition to the `0700` state directory, which already keeps the socket out of other users'
  reach in the default deployment.

For the full picture — trust boundaries, what each control does and does not cover, and the residual
risks above — see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the **Security** tab of this repository
2. Click **"Report a vulnerability"**
3. Fill out the form with details

I will respond within **48 hours** and work with you to understand and address the issue.

### What to Include

- Type of issue (e.g., key disclosure, handshake flaw, privilege escalation, traffic leak)
- Full paths of affected source files
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact assessment and potential attack scenarios

## Supported Versions

Only the latest version receives security updates. Please always use the most recent release.

## Security Best Practices for Contributors

1. **Never commit secrets** — pre-auth keys and tokens come from the environment or arguments,
   never source.
2. **Validate all external input** — especially anything crossing the control-protocol or LocalAPI
   boundary.
3. **Keep secret types non-`Copy` and zeroize-on-drop** where the engine exposes the option.
4. **Keep dependencies updated** — Dependabot is enabled on this repo.
5. **Follow the principle of least privilege** in all code.

## Contact

For security questions that aren't vulnerabilities, open a regular issue.
