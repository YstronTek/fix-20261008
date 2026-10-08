"""Privileged operations for the narrowly scoped games-account remediation."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time


SSH_CONFIG = Path('/etc/ssh/sshd_config')
AUTHORIZED_KEYS = Path('/root/.ssh/authorized_keys')
SAFE_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


def run(arguments, *, check=True, input=None):
    result = subprocess.run(
        [str(arg) for arg in arguments], input=input, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, 'PATH': SAFE_PATH, 'LC_ALL': 'C'})
    if check and result.returncode:
        # Input may contain a password. Never include it or PAM's response in errors.
        detail = '' if input is not None else ': ' + result.stderr.strip()
        raise RuntimeError(f'{arguments[0]} failed ({result.returncode}){detail}')
    return result


def atomic_write(path, content, mode=0o600, gid=0):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError(f'Refusing symlink: {path}')
    descriptor, temporary = tempfile.mkstemp(prefix='.games-repair-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
            stream.write(content if isinstance(content, bytes) else content.encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_policy(output):
    policy = {}
    for line in output.splitlines():
        name, value = line.split(' ', 1)
        name = name.lower()
        policy[name] = policy[name] + ' ' + value if name in policy else value
    return policy


def effective_policy(config, user='root', address='127.0.0.1'):
    output = run(['sshd', '-T', '-f', config, '-C',
                  f'user={user},host=localhost,addr={address}']).stdout
    return parse_policy(output)


def verify_policy(config, *, recovery=False):
    run(['sshd', '-t', '-f', config])
    expected = {
        'passwordauthentication': 'yes' if recovery else 'no',
        'kbdinteractiveauthentication': 'no',
        'pubkeyauthentication': 'yes',
        'authenticationmethods': 'publickey password' if recovery else 'publickey',
        'authorizedkeysfile': '.ssh/authorized_keys',
        'authorizedkeyscommand': 'none',
        'trustedusercakeys': 'none',
    }
    root = effective_policy(config)
    for name, value in expected.items():
        if root.get(name) != value:
            raise RuntimeError(f'Unsafe candidate policy: {name}={root.get(name)!r}')
    root_login = {'yes'} if recovery else {'prohibit-password', 'without-password'}
    if root.get('permitrootlogin') not in root_login:
        raise RuntimeError('Unexpected PermitRootLogin in candidate policy')
    if 'games' not in root.get('denyusers', '').split():
        raise RuntimeError('Candidate does not deny games')
    if recovery:
        other = effective_policy(config, user='nobody')
        if other.get('passwordauthentication') != 'no':
            raise RuntimeError('Recovery must not enable passwords for other accounts')
    return root


def inspect_accounts():
    records = [line.split(':') for line in Path('/etc/passwd').read_text().splitlines()]
    games = next((record for record in records if record[0] == 'games'), None)
    root = next((record for record in records if record[0] == 'root'), None)
    if root is None or root[2] != '0' or root[5] != '/root':
        raise RuntimeError('Only a local root account with /root home is supported')
    if any(record[2] == '0' and record[0] != 'root' for record in records):
        raise RuntimeError('Additional UID 0 account found; investigate manually first')
    nss_games = run(['getent', 'passwd', 'games'], check=False)
    if nss_games.returncode == 0 and games is None:
        raise RuntimeError('Non-local games account requires manual investigation')
    if games is not None and games[2] != '5':
        raise RuntimeError('Unexpected games UID; refusing to change or terminate it')
    return games


def check_directory(path):
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f'Expected a real directory: {path}')
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f'Unsafe owner or writable directory: {path}')


def preflight():
    if os.geteuid() != 0:
        raise RuntimeError('请在目标服务器上以 root 运行；不要在开发电脑上执行修复。')
    release = Path('/etc/os-release').read_text()
    values = {}
    for line in release.splitlines():
        if '=' in line:
            name, value = line.split('=', 1)
            values[name] = value.strip('"')
    if values.get('ID') not in {'debian', 'ubuntu'}:
        raise RuntimeError('此脚本仅支持 Debian / Ubuntu + systemd + OpenSSH。')
    needed = ('sshd', 'ssh-keygen', 'sudo', 'visudo', 'usermod', 'chpasswd',
              'getent', 'pkill', 'pgrep', 'systemctl', 'systemd-run', 'journalctl',
              'flock', 'tar', 'install', 'mv', 'logger')
    missing = [name for name in needed if shutil.which(name, path=SAFE_PATH) is None]
    if missing:
        raise RuntimeError('Missing required commands: ' + ', '.join(missing))
    service = next((name for name in ('ssh.service', 'sshd.service')
                    if run(['systemctl', 'is-active', '--quiet', name],
                           check=False).returncode == 0), None)
    if service is None:
        raise RuntimeError('No active systemd SSH service found')
    for socket in ('ssh.socket', 'sshd.socket'):
        if run(['systemctl', 'is-active', '--quiet', socket], check=False).returncode == 0:
            raise RuntimeError('Socket-activated SSH is not supported; configure it manually')
    pid = run(['systemctl', 'show', '--property=MainPID', '--value', service]).stdout.strip()
    if not pid.isdigit() or int(pid) <= 1:
        raise RuntimeError('Cannot identify running SSH service')
    command = Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode()
    execution = run(['systemctl', 'show', '--property=ExecStart', '--value', service]).stdout
    if re.search(r'(?:^|\s)-[ofp](?:\s|\S)', command + ' ' + execution):
        raise RuntimeError('Custom sshd -o/-f/-p overrides require manual review')
    defaults = Path('/etc/default/ssh')
    if defaults.exists():
        for line in defaults.read_text().splitlines():
            if re.match(r'\s*(?:export\s+)?SSHD_OPTS\s*=', line):
                value = line.split('=', 1)[1].strip()
                if shlex.split(value, comments=True) not in ([], ['']):
                    raise RuntimeError('Nonempty SSHD_OPTS requires manual review')
    for directory in (Path('/root'), SSH_CONFIG.parent):
        check_directory(directory)
    if AUTHORIZED_KEYS.parent.exists():
        check_directory(AUTHORIZED_KEYS.parent)
    if AUTHORIZED_KEYS.is_symlink():
        raise RuntimeError('Root authorized_keys is a symlink; investigate manually')
    if AUTHORIZED_KEYS.exists() and not AUTHORIZED_KEYS.is_file():
        raise RuntimeError('Root authorized_keys is not a regular file')
    if not Path('/usr/sbin/nologin').is_file():
        raise RuntimeError('Missing /usr/sbin/nologin')
    run(['sshd', '-t'])
    run(['visudo', '-c'])
    games = inspect_accounts()
    return service, games


def account_report(games):
    result = {'games': ':'.join(games) if games else None,
              'games_sudo_file': Path('/etc/sudoers.d/games').exists()}
    if games:
        result['groups'] = run(['id', 'games']).stdout.strip()
        policy = run(['sudo', '-n', '-l', '-U', 'games'], check=False)
        result['sudo'] = (policy.stdout + policy.stderr).strip()
    result['ssh'] = effective_policy(SSH_CONFIG)
    return result


def make_backup(plan):
    directory = Path(tempfile.mkdtemp(prefix='games-repair-', dir='/root'))
    os.chmod(directory, 0o700)
    sources = {Path('/etc') / name for name in (
        'passwd', 'passwd-', 'shadow', 'shadow-', 'group', 'group-', 'gshadow',
        'gshadow-', 'sudoers', 'sudoers.d')}
    sources.update(plan)
    sources.update((AUTHORIZED_KEYS, Path('/root/.ssh/authorized_keys2'),
                    Path('/root/.bash_history'), Path('/var/log/wtmp')))
    paths = sorted(path for path in sources if path.exists() or path.is_symlink())
    archive = directory / 'before.tar'
    run(['tar', '--acls', '--xattrs', '-cpf', archive, '-C', '/',
         *[str(path).lstrip('/') for path in paths]])
    os.chmod(archive, 0o600)
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest() if hasattr(
            hashlib, 'file_digest') else _file_digest(stream)
    atomic_write(directory / 'before.tar.sha256', f'{digest}  before.tar\n')
    logs = run(['journalctl', '-n', '1000', '-o', 'export', '--no-pager'])
    atomic_write(directory / 'journal.export', logs.stdout)
    metadata = {str(path): {'mode': oct(path.lstat().st_mode),
                           'uid': path.lstat().st_uid, 'gid': path.lstat().st_gid,
                           'mtime_ns': path.lstat().st_mtime_ns,
                           'ctime_ns': path.lstat().st_ctime_ns} for path in paths}
    atomic_write(directory / 'metadata.json', json.dumps(metadata, indent=2) + '\n')
    return directory


def _file_digest(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
    return digest.hexdigest()


def disable_games(games, backup):
    if games is not None:
        run(['usermod', '--password', '!', '--groups', '', '--home', '/usr/games',
             '--shell', '/usr/sbin/nologin', 'games'])
        run(['pkill', '-TERM', '-u', '5'], check=False)
        for _ in range(15):
            if run(['pgrep', '-u', '5'], check=False).returncode == 1:
                break
            time.sleep(0.2)
        else:
            run(['pkill', '-KILL', '-u', '5'], check=False)
        if run(['pgrep', '-u', '5'], check=False).returncode != 1:
            raise RuntimeError('games processes remain; SSH cutover stopped')
    malicious = Path('/etc/sudoers.d/games')
    if malicious.exists() or malicious.is_symlink():
        malicious.rename(backup / 'games.sudoers.quarantined')
    run(['visudo', '-c'])
    if games is not None:
        output = run(['sudo', '-n', '-l', '-U', 'games'], check=False)
        if 'User games is not allowed to run sudo' not in output.stdout + output.stderr:
            raise RuntimeError('Residual games sudo authorization needs manual removal; '
                               'games remains disabled, SSH cutover stopped')


def install_keys(keys):
    AUTHORIZED_KEYS.parent.mkdir(mode=0o700, exist_ok=True)
    os.chown(AUTHORIZED_KEYS.parent, 0, 0)
    os.chmod(AUTHORIZED_KEYS.parent, 0o700)
    atomic_write(AUTHORIZED_KEYS, keys)


def install_plan(plan):
    for path, content in plan.items():
        original = path.stat()
        atomic_write(path, content, stat.S_IMODE(original.st_mode), original.st_gid)


def journal_cursor():
    result = run(['journalctl', '-n', '1', '-o', 'json', '--no-pager'])
    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    if not records or '__CURSOR' not in records[-1]:
        raise RuntimeError('Cannot obtain journal cursor for fresh-login verification')
    return records[-1]['__CURSOR']


def new_key_login(cursor, fingerprints):
    result = run(['journalctl', '--after-cursor', cursor, '-t', 'sshd', '-t',
                  'sshd-session', '-o', 'json', '--no-pager'])
    for line in result.stdout.splitlines():
        if not line.startswith('{'):
            continue
        record = json.loads(line)
        message = record.get('MESSAGE', '')
        if not isinstance(message, str) or not message.startswith('Accepted publickey for root from '):
            continue
        if any(fingerprint in message.split() for fingerprint in fingerprints):
            return True
    return False
