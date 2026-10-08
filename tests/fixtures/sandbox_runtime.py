#!/usr/bin/env python3
"""Test-only systemd transport adapter for the disposable namespace.

This is NOT systemd integration coverage. It manages the real sshd listener,
actually executes recovery scripts, and converts actual sshd log lines to JSON.
It never invents login events or account/SSH command results. Unknown command
shapes fail closed. Production binaries are untouched outside the chroot.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import threading

STATE = Path("/run/smoke")
SELF = "/opt/repair/tests/fixtures/sandbox_runtime.py"
LOG = STATE / "sshd.log"
PID = STATE / "sshd.pid"


def require_isolation():
    marker = STATE / "isolation.json"
    if not marker.is_file() or os.getuid() != 0:
        raise RuntimeError("Test adapter requires disposable rootless namespace")
    mapping = Path("/proc/self/uid_map").read_text().splitlines()
    if len(mapping) < 2 or mapping[0].split()[1] == "0":
        raise RuntimeError("Refusing to run adapter with host root identity")


def run(*args: str, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return Path(f"/proc/{pid}/stat").read_text().split()[2] != "Z"
    except (ProcessLookupError, FileNotFoundError):
        return False


def daemon_pid() -> int:
    return int(PID.read_text()) if PID.exists() else 0


def wait_listener():
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 22222), timeout=0.2) as connection:
                if connection.recv(128).startswith(b"SSH-"):
                    return
        except OSError:
            pass
        time.sleep(0.05)
    raise RuntimeError("Real sshd did not listen:\n" + LOG.read_text())


def service(action: str):
    require_isolation()
    if action == "start":
        with LOG.open("ab", buffering=0) as log:
            process = subprocess.Popen(["/usr/sbin/sshd", "-D", "-E", str(LOG)],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       start_new_session=True)
        PID.write_text(str(process.pid))
    elif action == "reload":
        run("/usr/sbin/sshd", "-t")
        os.kill(daemon_pid(), signal.SIGHUP)
        time.sleep(0.15)
    else:
        raise RuntimeError("Unsupported SSH action: " + action)
    wait_listener()


def receive_syslog():
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    endpoint.bind("/dev/log")
    def consume():
        with (STATE / "syslog.log").open("ab", buffering=0) as output:
            while True:
                output.write(endpoint.recv(65536) + b"\n")
    threading.Thread(target=consume, daemon=True).start()


def seed():
    require_isolation()
    for backup in Path('/root').glob('games-repair-*'):
        if backup.is_symlink():
            raise RuntimeError('Unexpected symlink in disposable fixture backups')
        shutil.rmtree(backup)
    Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
    Path("/run/lock").mkdir(mode=0o755, exist_ok=True)
    Path("/run/systemd/system").mkdir(parents=True, exist_ok=True)
    STATE.mkdir(mode=0o700, exist_ok=True)
    receive_syslog()
    for binary in ("systemctl", "systemd-run", "journalctl"):
        target = Path("/usr/bin") / binary
        # Deliberately replace only the disposable image's transport commands.
        if target.is_symlink():
            target.unlink()
        target.write_text(f"#!/bin/sh\nexec /usr/bin/python3 {SELF} {binary} \"$@\"\n")
        target.chmod(0o755)
    (STATE / "askpass").write_text("#!/bin/sh\nprintf '%s\\n' \"$SMOKE_PASSWORD\"\n")
    (STATE / "askpass").chmod(0o700)
    for key in ("old", "new1", "new2", "recovery"):
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(STATE / key))
    sshdir = Path("/root/.ssh")
    sshdir.mkdir(mode=0o700, exist_ok=True)
    sshdir.chmod(0o700)
    (sshdir / "authorized_keys").write_text((STATE / "old.pub").read_text())
    (sshdir / "authorized_keys").chmod(0o600)
    run("ssh-keygen", "-A")
    Path("/etc/ssh/sshd_config.d").mkdir(exist_ok=True)
    Path("/etc/ssh/sshd_config").write_text(
        "Port 22222\nListenAddress 127.0.0.1\nPidFile /run/sshd/daemon.pid\n"
        "HostKey /etc/ssh/ssh_host_ed25519_key\nLogLevel VERBOSE\nUsePAM no\n"
        "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n"
        "PasswordAuthentication yes\nPubkeyAuthentication yes\n"
        "AuthorizedKeysFile .ssh/authorized_keys\nDenyUsers fixture-denied\n"
        "Match User root\n    PasswordAuthentication yes\n"
        "    AuthenticationMethods any\n")
    Path("/etc/ssh/sshd_config.d/10-insecure.conf").write_text(
        "PasswordAuthentication yes\nKbdInteractiveAuthentication yes\n"
        "Match User games\n    PasswordAuthentication yes\nMatch all\n")
    run("usermod", "--shell", "/bin/bash", "--home", "/usr/games", "--groups", "sudo,adm", "games")
    Path("/usr/games").mkdir(exist_ok=True)
    Path("/etc/sudoers.d/games").write_text("games ALL=(ALL:ALL) NOPASSWD: ALL\n")
    Path("/etc/sudoers.d/games").chmod(0o440)
    run("chpasswd", input="root:OriginalSmokePassword-81!\ngames:GamesSmokePassword-19!\n")
    # A real UID5 process proves remediation kills processes rather than only
    # editing account files. setpriv is real and confined to the PID namespace.
    sleeper = subprocess.Popen(["setpriv", "--reuid=5", "--regid=60", "--clear-groups",
                               "/bin/sleep", "3600"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (STATE / "games-process.pid").write_text(str(sleeper.pid))
    threading.Thread(target=sleeper.wait, daemon=True).start()


def timer_state(unit: str) -> Path:
    unit = unit.removesuffix(".timer").removesuffix(".service")
    if not re.fullmatch(r"games-repair-[A-Za-z0-9_-]+", unit):
        raise RuntimeError("Unexpected timer unit: " + unit)
    return STATE / (unit + ".json")


def start_timer(args: list[str]):
    unit = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--unit="))
    if "--on-active=10m" not in args or "--" not in args:
        raise RuntimeError("Expected actual production ten-minute recovery timer")
    command = args[args.index("--") + 1:]
    if len(command) != 2 or command[0] != "/bin/sh" or not command[1].startswith("/root/games-repair-"):
        raise RuntimeError("Unexpected recovery command")
    state = timer_state(unit)
    state.write_text(json.dumps({"command": command, "unit": unit, "pid": None}))
    process = subprocess.Popen(["python3", SELF, "timer-wait", str(state)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    state.write_text(json.dumps({"command": command, "unit": unit, "pid": process.pid}))


def stop_timer(unit: str):
    state = timer_state(unit)
    if state.exists():
        record = json.loads(state.read_text())
        if record["pid"] and alive(record["pid"]):
            os.kill(record["pid"], signal.SIGTERM)
        state.unlink(missing_ok=True)


def fire_timer():
    states = list(STATE.glob("games-repair-*.json"))
    if len(states) != 1:
        raise RuntimeError(f"Expected one armed recovery timer, found {len(states)}")
    state = states[0]
    record = json.loads(state.read_text())
    stop_timer(record["unit"])
    # Actually run exactly what production queued, including its flock/marker
    # decisions and sshd reload. No simulated recovery result is supplied.
    run(*record["command"])


def systemctl(args: list[str]) -> int:
    if args[0] == "is-active":
        name = args[-1]
        if name in ("ssh.service", "sshd.service"):
            active = daemon_pid() > 1 and alive(daemon_pid())
            if "--quiet" not in args:
                print("active" if active else "inactive")
            return 0 if active else 3
        if name.startswith("games-repair-") and name.endswith(".timer"):
            state = timer_state(name)
            if state.exists():
                pid = json.loads(state.read_text())["pid"]
                return 0 if pid and alive(pid) else 3
        return 3
    if args[0] == "show":
        if "--property=MainPID" in args:
            print(daemon_pid())
        elif "--property=ExecStart" in args:
            print("{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D -E /run/smoke/sshd.log ; }")
        else:
            raise RuntimeError("Unsupported systemctl show property")
        return 0
    if args[0] == "reload" and args[-1] in ("ssh.service", "sshd.service"):
        service("reload")
        return 0
    if args[0] == "stop":
        for unit in args[1:]:
            stop_timer(unit)
        return 0
    raise RuntimeError("Unsupported fixture systemctl command: " + repr(args))


def journal(args: list[str]):
    content = LOG.read_bytes()
    offset = 0
    if "--after-cursor" in args:
        cursor = args[args.index("--after-cursor") + 1]
        if not cursor.startswith("smoke-offset-"):
            raise RuntimeError("Unexpected journal cursor")
        offset = int(cursor.removeprefix("smoke-offset-"))
    lines = content[offset:].splitlines(keepends=True)
    records = []
    for line in lines:
        offset += len(line)
        records.append({"__CURSOR": f"smoke-offset-{offset}",
                        "SYSLOG_IDENTIFIER": "sshd", "MESSAGE": line.decode(errors="replace").strip()})
    if "-n" in args:
        records = records[-int(args[args.index("-n") + 1]):]
    for record in records:
        print(json.dumps(record))


def main():
    require_isolation()
    action, *args = sys.argv[1:]
    if action == "systemctl":
        return systemctl(args)
    if action == "systemd-run":
        start_timer(args)
    elif action == "journalctl":
        journal(args)
    elif action == "fire-timer":
        fire_timer()
    elif action == "timer-wait":
        time.sleep(600)
        state = Path(args[0])
        if state.exists():
            record = json.loads(state.read_text())
            run(*record["command"])
            state.unlink(missing_ok=True)
    else:
        raise RuntimeError("Unknown fixture action: " + action)
    return 0


if __name__ == "__main__":
    sys.exit(main())
