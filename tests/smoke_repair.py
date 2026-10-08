#!/usr/bin/env python3
"""Destructive only inside a disposable, rootless Debian namespace.

Prepare with tests/fixtures/prepare_rootfs.py, then pass its --output directory
as --rootfs here. No production module is monkeypatched. Only systemd's service,
timer, and journal transport are adapted; SSH authentication and account changes
use the distribution's real binaries. See fixtures/sandbox_runtime.py.
"""
from __future__ import annotations

import argparse
import codecs
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time

FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(FIXTURES))


def run(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


class Terminal:
    def __init__(self, argv: list[str]):
        self.master, slave = pty.openpty()
        self.process = subprocess.Popen(
            ["setsid", "--ctty", "--wait", *argv],
            stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        self.buffer = ""
        self.transcript = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def expect(self, text: str, timeout: int = 45):
        deadline = time.monotonic() + timeout
        while text not in self.buffer:
            if time.monotonic() >= deadline:
                raise AssertionError(f"Prompt {text!r} absent:\n{self.transcript}")
            ready, _, _ = select.select([self.master], [], [], 0.2)
            if ready:
                try:
                    raw = os.read(self.master, 65536)
                except OSError:
                    raw = b""
                if not raw:
                    raise AssertionError(f"CLI exited before {text!r}:\n{self.transcript}")
                chunk = self.decoder.decode(raw)
                self.buffer += chunk
                self.transcript += chunk
        self.buffer = self.buffer.split(text, 1)[1]

    def send(self, text: str):
        os.write(self.master, text.encode() + b"\n")

    def finish(self, success: bool):
        deadline = time.monotonic() + 40
        while self.process.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], 0.1)
            if ready:
                try:
                    self.transcript += os.read(self.master, 65536).decode(errors="replace")
                except OSError:
                    break
        try:
            status = self.process.wait(timeout=5)
        finally:
            os.close(self.master)
        if success and status != 0:
            raise AssertionError(f"CLI failed ({status}):\n{self.transcript}")
        return status

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
        try:
            os.close(self.master)
        except OSError:
            pass


def ssh(key: str | None = None, password: str | None = None, user: str = "root"):
    env = os.environ.copy()
    env.update(SSH_ASKPASS="/run/smoke/askpass", SSH_ASKPASS_REQUIRE="force",
               DISPLAY=":smoke", SMOKE_PASSWORD=password or "")
    argv = ["ssh", "-F", "/dev/null", "-p", "22222", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
            "-o", "NumberOfPasswordPrompts=1", "-o", "IdentityAgent=none"]
    if key:
        argv += ["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-i", key,
                 "-o", "PreferredAuthentications=publickey"]
    else:
        argv += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password"]
    return subprocess.run(argv + [f"{user}@127.0.0.1", "id -u"], stdin=subprocess.DEVNULL,
                          text=True, capture_output=True, env=env, timeout=15,
                          start_new_session=True)


def assert_login(*, allowed: bool, **kwargs):
    result = ssh(**kwargs)
    if allowed:
        assert result.returncode == 0 and result.stdout.strip() == "0", result.stderr
    else:
        assert result.returncode != 0, "An obsolete or forbidden credential logged in"


def shadow_hash(user: str) -> str:
    rows = Path("/etc/shadow").read_text().splitlines()
    return next(row.split(":")[1] for row in rows if row.startswith(user + ":"))


def assert_accounts(password: str, newkey: str):
    from ctypes import CDLL, c_char_p
    import pwd
    entry = pwd.getpwnam("games")
    assert entry.pw_uid == 5 and entry.pw_dir == "/usr/games"
    assert entry.pw_shell.endswith("/nologin")
    assert shadow_hash("games").startswith("!")
    crypt = CDLL('libcrypt.so.1')
    crypt.crypt.argtypes = (c_char_p, c_char_p)
    crypt.crypt.restype = c_char_p
    root_hash = shadow_hash("root").encode()
    assert crypt.crypt(password.encode(), root_hash) == root_hash, "New root password not installed"
    groups = run("id", "-nG", "games").stdout.split()
    assert "sudo" not in groups and "adm" not in groups, groups
    assert not Path("/etc/sudoers.d/games").exists()
    run("visudo", "-c")
    sudo = subprocess.run(["sudo", "-n", "-l", "-U", "games"], text=True, capture_output=True)
    assert "not allowed to run sudo" in sudo.stdout + sudo.stderr
    remaining = subprocess.run(["pgrep", "-u", "5"], capture_output=True)
    assert remaining.returncode == 1, "Live or unreaped games process remains"
    actual = Path("/root/.ssh/authorized_keys").read_text().strip()
    expected = Path(newkey + ".pub").read_text().strip()
    assert actual.split()[:2] == expected.split()[:2] and len(actual.splitlines()) == 1
    assert Path("/root/.ssh").stat().st_mode & 0o777 == 0o700
    assert Path("/root/.ssh/authorized_keys").stat().st_mode & 0o777 == 0o600
    assert_login(allowed=False, password="OriginalSmokePassword-81!")
    assert_login(allowed=False, key="/run/smoke/old")
    assert_login(allowed=False, password="GamesSmokePassword-19!", user="games")


def repair_command(arguments, standalone):
    if standalone:
        return ["bash", "-o", "pipefail", "-c",
                'cat /opt/repair/fix-games.sh | bash -s -- "$@"',
                "standalone-smoke", *arguments]
    return ["python3", "/opt/repair/tools/fix_games_backdoor.py", *arguments]


def begin_repair(password: str, key: str, prompts: dict[str, str], *,
                 paste_keys=False, standalone=False) -> Terminal:
    arguments = [] if paste_keys else ["--key-file", key + ".pub"]
    terminal = Terminal(repair_command(arguments, standalone))
    terminal.expect(prompts["password"])
    terminal.send(password)
    terminal.expect(prompts["repeat"])
    terminal.send(password)
    if paste_keys:
        terminal.expect("公钥: ")
        terminal.send(Path(key + ".pub").read_text().strip())
        terminal.expect("公钥: ")
        terminal.send("")
    terminal.expect("输入 APPLY 开始修复: ")
    terminal.send("APPLY")
    terminal.expect(prompts["confirm"], timeout=90)
    return terminal




def assert_decision(success: bool):
    backup = max(Path("/root").glob("games-repair-*"), key=lambda p: p.stat().st_mtime_ns)
    assert not (backup / "pending").exists()
    assert (backup / ("COMPLETE" if success else "RECOVERED")).exists()
    assert not (backup / ("RECOVERED" if success else "COMPLETE")).exists()
    assert not list(Path("/run/smoke").glob("games-repair-*.json")), "Recovery timer remains armed"
    if success:
        assert not (backup / "recover.sh").exists()
        assert not list(backup.glob("recovery-source-*"))
    assert not list(Path("/tmp").glob("games-repair-run.*")), "Standalone code was not cleaned up"


def run_scenarios(prompts: dict[str, str], standalone=False):
    from sandbox_runtime import seed, service
    seed()
    service("start")
    protected = [Path(name) for name in ("/etc/passwd", "/etc/shadow", "/etc/group",
                 "/etc/gshadow", "/etc/ssh/sshd_config", "/root/.ssh/authorized_keys")]
    before = {path: path.read_bytes() for path in protected}
    check = subprocess.run(repair_command(["--check"], standalone),
                           capture_output=True, text=True)
    assert check.returncode == 1, check.stdout + check.stderr
    assert before == {path: path.read_bytes() for path in protected}, "--check changed account or SSH state"
    assert not list(Path("/root").glob("games-repair-*")), "--check created a mutation backup"
    assert_login(allowed=True, key="/run/smoke/old")
    assert_login(allowed=True, password="OriginalSmokePassword-81!")
    previous = "/run/smoke/old"
    for iteration in (1, 2):
        key = f"/run/smoke/new{iteration}"
        password = f"ReplacementConsolePassword-{iteration}-74!"
        terminal = begin_repair(password, key, prompts, paste_keys=iteration == 2,
                                standalone=standalone)
        try:
            assert_login(allowed=True, key=key)
            assert_login(allowed=False, password=password)
            assert_login(allowed=False, key=previous)
            terminal.send("CONFIRM")
            terminal.finish(success=True)
            assert password not in terminal.transcript, "Password leaked to terminal output"
        finally:
            terminal.close()
        assert_accounts(password, key)
        assert_decision(success=True)
        assert_login(allowed=False, password=password)
        previous = key
        print(f"PASS successful repair {iteration}: fresh key login, key-only SSH, rotated accounts", flush=True)

    for action in ("unverified-confirm", "abort", "timer"):
        key = "/run/smoke/recovery"
        password = f"RecoveryConsolePassword-{action}-74!"
        terminal = begin_repair(password, key, prompts, standalone=standalone)
        try:
            assert_login(allowed=False, password=password)
            if action == "timer":
                # Trigger the timer adapter's real queued recovery command early;
                # production still requests its full ten-minute deadline.
                run("python3", "/opt/repair/tests/fixtures/sandbox_runtime.py", "fire-timer")
                terminal.send("CONFIRM")
            else:
                terminal.send("CONFIRM" if action == "unverified-confirm" else "ABORT")
            assert terminal.finish(success=False) == 2, terminal.transcript
            assert password not in terminal.transcript, "Password leaked during recovery"
        finally:
            terminal.close()
        assert_accounts(password, key)
        assert_decision(success=False)
        assert_login(allowed=True, password=password)
        assert_login(allowed=True, key=key)
        assert_login(allowed=False, key="/run/smoke/new2")
        print(f"PASS recovery {action}: only new root password/new keys, games remains disabled", flush=True)

    backups = list(Path("/root").glob("games-repair-*"))
    assert len(backups) >= 5, "Evidence directories overwritten across runs"
    for backup in backups:
        assert backup.stat().st_mode & 0o777 == 0o700, backup
        archives = list(backup.glob("*.tar*"))
        assert archives, f"No evidence archive in {backup}"
        assert all(p.stat().st_mode & 0o777 == 0o600 for p in archives)
    print("PASS all real-CLI smoke scenarios (systemd transport is a test adapter)", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, help="Disposable rootfs built by fixtures/prepare_rootfs.py")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--standalone", action="store_true", help="Exercise the generated curl/pipe entry")
    parser.add_argument("--password-prompt", default="新 root 密码: ")
    parser.add_argument("--repeat-prompt", default="再次输入新 root 密码: ")
    parser.add_argument("--confirm-prompt", default="完成新的密钥登录后输入 CONFIRM（其他输入恢复新密码 SSH）: ")
    args = parser.parse_args()
    if args.inside:
        if os.getuid() != 0 or not Path("/run/smoke/isolation.json").exists():
            parser.error("Internal stage requires the verified disposable namespace")
        run_scenarios({"password": args.password_prompt, "repeat": args.repeat_prompt,
                       "confirm": args.confirm_prompt}, standalone=args.standalone)
    else:
        if args.rootfs is None:
            parser.error("--rootfs is required; host execution is deliberately impossible")
        from prepare_rootfs import launch_smoke
        forwarded = ["--password-prompt", args.password_prompt,
                     "--repeat-prompt", args.repeat_prompt,
                     "--confirm-prompt", args.confirm_prompt]
        if args.standalone:
            forwarded.append("--standalone")
        launch_smoke(args.rootfs, forwarded)


if __name__ == "__main__":
    main()
