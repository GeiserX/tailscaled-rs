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
  at-rest encryption. Protect the state directory (`0600`, full-disk encryption) yourself.
- The LocalAPI socket currently authorizes by filesystem permissions on the socket path; richer
  `SO_PEERCRED`-based authorization is planned, not yet implemented.

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
