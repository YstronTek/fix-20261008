"""Timed recovery permits only the newly supplied root password, never old access."""

import fcntl
import os
import shlex
import shutil
import stat

from tools.repair_system import AUTHORIZED_KEYS, SAFE_PATH, atomic_write, run


def prepare_recovery(backup, plan, service, keys):
    def quote(value):
        return shlex.quote(str(value))

    def command(name):
        path = shutil.which(name, path=SAFE_PATH)
        if path is None:
            raise RuntimeError(f'Missing recovery command: {name}')
        return quote(path)

    commands = ['#!/bin/sh', 'set -eu', 'umask 077',
                'PATH=' + quote(SAFE_PATH), 'export PATH',
                f'exec 9>{quote(backup / "decision.lock")}',
                f'{command("flock")} -x 9',
                f'test -f {quote(backup / "pending")} || exit 0', 'temporary=',
                'trap \'test -z "$temporary" || rm -f -- "$temporary"\' EXIT',
                f'{command("install")} -d -o 0 -g 0 -m 700 /root/.ssh']
    for index, (target, content) in enumerate({AUTHORIZED_KEYS: keys, **plan}.items()):
        source = backup / f'recovery-source-{index}'
        atomic_write(source, content)
        info = target.stat() if target.exists() else None
        commands.extend([
            f'temporary=$({command("mktemp")} {quote(str(target) + ".repair.XXXXXX")})',
            f'{command("install")} -o 0 -g {info.st_gid if info and target != AUTHORIZED_KEYS else 0} -m '
            f'{stat.S_IMODE(info.st_mode) if info and target != AUTHORIZED_KEYS else 0o600:o} -- {quote(source)} "$temporary"',
            f'{command("mv")} -f -- "$temporary" {quote(target)}', 'temporary='])
    commands.extend([
        f'{command("sshd")} -t',
        f'{command("systemctl")} reload {quote(service)}',
        f': > {quote(backup / "RECOVERED")}',
        f'rm -f -- {quote(backup / "pending")}',
        f'{command("logger")} -t games-repair '
        "'SSH recovery enabled NEW root password; games remains disabled; old keys not restored.'",
    ])
    script = backup / 'recover.sh'
    atomic_write(script, '\n'.join(commands) + '\n', 0o700)
    return script


def arm_recovery(backup, script):
    unit = 'games-repair-' + backup.name.removeprefix('games-repair-')
    atomic_write(backup / 'pending', '')
    try:
        run(['systemd-run', '--unit=' + unit, '--on-active=10m',
             '--timer-property=AccuracySec=1s', '--', '/bin/sh', script])
        run(['systemctl', 'is-active', '--quiet', unit + '.timer'])
    except Exception:
        run(['systemctl', 'stop', unit + '.timer'], check=False)
        (backup / 'pending').unlink(missing_ok=True)
        raise
    return unit


def recover(backup, unit):
    script = backup / 'recover.sh'
    if (backup / 'pending').exists():
        run(['/bin/sh', script])
    if unit:
        run(['systemctl', 'stop', unit + '.timer'])
    if not (backup / 'RECOVERED').exists():
        raise RuntimeError('未能确认 SSH 恢复状态；请保留当前连接并使用控制台检查。')


def commit(backup, unit):
    # The timer uses the same advisory lock: exactly one side can decide the outcome.
    with (backup / 'decision.lock').open('a') as lock:
        os.chmod(backup / 'decision.lock', 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        if (backup / 'RECOVERED').exists() or not (backup / 'pending').exists():
            raise RuntimeError('恢复定时器已执行，不能宣称仅密钥切换成功；请重新运行。')
        (backup / 'pending').unlink()
        atomic_write(backup / 'COMPLETE', '')
    run(['systemctl', 'stop', unit + '.timer'])
    if run(['systemctl', 'is-active', '--quiet', unit + '.timer'], check=False).returncode == 0:
        raise RuntimeError('Recovery timer is still active')
    (backup / 'recover.sh').unlink()
    for path in backup.glob('recovery-source-*'):
        path.unlink()
    for directory in ('candidate', 'recovery-candidate'):
        shutil.rmtree(backup / directory)
