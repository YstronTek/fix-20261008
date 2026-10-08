# Games Backdoor Repair

Interactive removal of the `games` account backdoor, root password rotation, and migration to key-only SSH.

**Run on the affected server. Take a snapshot and ensure rescue-console access first.** Removing this backdoor does not make a root-compromised system trustworthy; rebuilding and rotating other credentials remain recommended.

## Requirements

- Debian or Ubuntu, Python 3.9+, and a systemd-managed OpenSSH service (not socket activation).
- Root access, an interactive terminal, and standard OpenSSH, sudo, passwd, procps, util-linux, tar, and systemd tools.
- New SSH public keys, with their private keys kept on your own computer.

## Quick start

After publishing `fix-games.sh` to this repository, run in Bash:

```bash
set -o pipefail; curl --proto '=https' --tlsv1.2 -fsSL 'https://raw.githubusercontent.com/YstronTek/fix-20261008/main/fix-games.sh' | sudo bash
```

Remove `sudo` if already root. Review the code and preferably replace `main` with a trusted commit SHA. The raw URL must be accessible; private or unpublished content may return 404.

To pass options, replace the final `sudo bash` with:

- `sudo bash -s -- --check` — inspect without changing system configuration.
- `sudo bash -s -- --key-file /root/new-admin-keys.pub` — load public keys from a file.

Alternatively, keep the complete `tools/` directory and run from the repository:

```bash
sudo python3 tools/fix_games_backdoor.py --check
sudo python3 tools/fix_games_backdoor.py
```

## Repair workflow

1. Enter and confirm a new root password (at least 12 characters).
2. Paste public keys, one per line, ending with a blank line, or use `--key-file`.
3. Review the fingerprints and enter `APPLY`.
4. Keep the current connection open. Within **10 minutes**, use the displayed command to open a fresh SSH connection with a new key.
5. Return to the original terminal and enter `CONFIRM`. The script requires a matching successful public-key login in the journal before committing.

The launcher reads interactive input from `/dev/tty`, so piping the script does not consume password input. Passwords are not echoed or stored in plaintext logs.

## Changes and recovery

- Disables the local `games` account (UID 5), removes supplementary groups, restores its non-login shell/home, and terminates its processes.
- Quarantines `/etc/sudoers.d/games`; stops if other sudo grants remain.
- **Replaces all root authorized keys** with the supplied keys and sets the new root password.
- Enforces key-only SSH globally, disables SSH CA/external key-command authentication, and reloads SSH without restarting business services.
- Preserves logs and saves protected evidence under `/root/games-repair-*`. Backups contain sensitive password hashes: do not publish them or blindly restore the old backdoor configuration.

After success, the new password remains usable for the local console, not SSH. Old keys and password-based automation may stop working. SSH Include globs become explicit file lists, so newly added configuration files will not load automatically.

If verification fails, is cancelled, or times out after password rotation, recovery enables root SSH using **only the new password or new keys**. It does not restore old credentials or the `games` backdoor. Rerun successfully to return to key-only SSH. Earlier failures may leave partial cleanup; follow the reported status.

**Do not reboot during verification:** the recovery timer does not survive reboot. Unsupported account layouts, unsafe configuration paths, and custom SSH startup overrides require manual review. This is targeted remediation, not a complete forensic investigation.

## Development

Regenerate the standalone script after changing repair modules:

```bash
python3 tools/build_standalone.py
bash -n fix-games.sh
python3 -m unittest discover -s tests -v
```

Run isolated smoke tests as a regular user, **without sudo**:

```bash
python3 tests/fixtures/prepare_rootfs.py --output /tmp/games-smoke-rootfs
python3 tests/smoke_repair.py --rootfs /tmp/games-smoke-rootfs
python3 tests/smoke_repair.py --rootfs /tmp/games-smoke-rootfs --standalone
```

The fixture needs network access, user namespaces, subordinate UID/GID mappings, and `unshare`, `newuidmap`, `newgidmap`, `mount`, and `ip`. It uses real SSH and account tools, but adapts systemd/journal transport, disables SSH PAM sessions, and triggers the recovery timer early. These tests do not cover full systemd/PAM integration.
