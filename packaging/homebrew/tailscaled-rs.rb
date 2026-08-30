# Homebrew formula for tailscaled-rs — the daemon (`tailnetd`) and its CLI (`tnet`).
#
# It lives in this repository, not only in the tap, so it moves with the code it installs: the
# binaries it puts on PATH, the cargo features a distributed build has to carry, and the engine
# opt-in the daemon refuses to start without are each asserted against their source of truth by
# `tests/homebrew_formula.rs`. Publishing a release means copying this file to
# `Formula/tailscaled-rs.rb` in the tap repository (see `README.md` beside this file);
# `scripts/homebrew-formula.sh` rewrites the `url`/`sha256` pair for a new tag so the checksum is
# never typed by hand.
#
# UNOFFICIAL: this project is not affiliated with, endorsed by, or sponsored by Tailscale Inc. or
# the WireGuard project; those names are used nominatively (see NOTICE).
class TailscaledRs < Formula
  desc "Rust system daemon that joins a WireGuard-based mesh overlay network"
  homepage "https://github.com/GeiserX/tailscaled-rs"
  url "https://github.com/GeiserX/tailscaled-rs/archive/refs/tags/v0.52.2.tar.gz"
  sha256 "999fa5b2184e82ebc781b324b8f2bec4f57d89f31fa03edabce9d5242eb3cc97"
  license "BSD-3-Clause"
  head "https://github.com/GeiserX/tailscaled-rs.git", branch: "main"

  depends_on "rust" => :build

  def install
    # The engine acknowledges the experiment opt-in from the build environment as well (the release
    # workflow sets it for the same reason). The daemon's own refusal is a RUNTIME check — see
    # `caveats` and the service block below.
    ENV["TS_RS_EXPERIMENT"] = "this_is_unstable_software"

    # Build a FULL-featured daemon, matching the released binaries: without these, kernel-TUN mode,
    # the Tailscale SSH server, and ACME issuance for `tnet cert` / `serve --https` / `funnel` are
    # compiled out and fail closed. Each still gates at runtime (TUN and SSH need root; cert and
    # funnel need a SaaS tailnet), so a full build is not a privileged one.
    system "cargo", "install", "--features", "tun,ssh,acme", *std_cargo_args
  end

  service do
    run [opt_bin/"tailnetd"]
    # Runs as root, like the packaged systemd unit and launchd plist: as root the daemon resolves
    # the SYSTEM state dir (`/usr/local/var/tailnetd` on macOS, `/var/lib/tailnetd` on Linux), which
    # is the same path `sudo tnet` resolves — so the CLI finds the LocalAPI socket with no
    # `--socket` flag. Deliberately NOT relocated under the Homebrew prefix, which would break that
    # agreement for every documented `sudo tnet …` command.
    require_root true
    # Restart it if it dies, without fighting a clean `brew services stop`. Homebrew renders exactly
    # ONE keep-alive condition per platform, so this is deliberately the single key that is right on
    # both: launchd gets `KeepAlive = { Crashed: true }` and systemd `Restart=on-failure`. (The
    # committed launchd plist also restarts on a non-zero exit; brew's DSL cannot express both, and
    # of the two, not relaunching a daemon that exited on a fatal config error is the safer half.)
    keep_alive crashed: true
    # Starting the service IS the operator opting in to experimental, unaudited software; the daemon
    # never sets this for itself.
    environment_variables TS_RS_EXPERIMENT: "this_is_unstable_software"
    log_path var/"log/tailnetd.log"
    error_log_path var/"log/tailnetd.err.log"
  end

  def caveats
    state_dir = OS.mac? ? "/usr/local/var/tailnetd" : "/var/lib/tailnetd"
    <<~EOS
      tailscaled-rs is EXPERIMENTAL, unaudited software, and it is unofficial: not affiliated
      with, endorsed by, or sponsored by Tailscale Inc. Do not rely on it for data privacy yet.

      The engine refuses to run without an explicit opt-in, so tailnetd needs
      TS_RS_EXPERIMENT=this_is_unstable_software in its environment. The service sets it:

        sudo brew services start tailscaled-rs
        sudo tnet up --authkey-file /path/to/key
        sudo tnet status

      Running as root, the daemon keeps its state (node key + prefs) in #{state_dir} — outside
      the Homebrew prefix, so `sudo tnet` resolves the same socket with no --socket flag. To run
      it in the foreground instead:

        TS_RS_EXPERIMENT=this_is_unstable_software tailnetd

      `tnet update` refuses to replace a Homebrew-installed binary; upgrade with
      `brew upgrade tailscaled-rs`.
    EOS
  end

  test do
    # Both installed binaries are the version this formula claims. `tnet version` prints the
    # client's own version with no daemon running (it reports the daemon's too when one answers),
    # so the check needs nothing but the two files brew just installed.
    assert_match version.to_s, shell_output("#{bin}/tnet version")
    assert_match version.to_s, shell_output("#{bin}/tailnetd --version")

    # The error path the caveats promise: with no opt-in in the environment, the daemon refuses to
    # start (exit 1) and says which variable is missing, rather than running unaudited crypto.
    ENV.delete("TS_RS_EXPERIMENT")
    refusal = shell_output("#{bin}/tailnetd --statedir #{testpath}/state 2>&1", 1)
    assert_match "TS_RS_EXPERIMENT", refusal
  end
end
