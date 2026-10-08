#!/usr/bin/env python3
"""Interactive games-backdoor removal with verified key-only SSH cutover."""

import argparse
import fcntl
import getpass
import json
import os
from pathlib import Path
import signal
import stat
import sys

if sys.version_info < (3, 9):
    raise SystemExit('需要 Python 3.9 或更新版本。')

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.key_input import validate_public_keys
from tools.repair_recovery import arm_recovery, commit, prepare_recovery, recover
from tools.repair_system import (
    SAFE_PATH, SSH_CONFIG, account_report, atomic_write, disable_games,
    install_keys, install_plan, journal_cursor, make_backup,
    new_key_login, preflight, run, verify_policy,
)
from tools.ssh_policy import password_recovery, plan_sshd, render_stage


def validate_password(password):
    if len(password) < 12:
        raise ValueError('新密码至少需要 12 个字符。')
    if any(ord(character) < 32 or ord(character) == 127 for character in password):
        raise ValueError('密码不能含换行、NUL 或控制字符。')


def collect_password():
    while True:
        password = getpass.getpass('新 root 密码: ')
        confirmation = getpass.getpass('再次输入新 root 密码: ')
        if password != confirmation:
            print('两次密码不一致，请重新输入。', file=sys.stderr)
            continue
        try:
            validate_password(password)
        except ValueError as error:
            print(error, file=sys.stderr)
            continue
        return password


def collect_keys(path):
    if path:
        text = path.read_text()
    else:
        print('粘贴新的 SSH 公钥，每行一把，空行结束；不要输入私钥或 URL。')
        lines = []
        while True:
            line = input('公钥: ')
            if not line.strip():
                break
            lines.append(line)
        text = '\n'.join(lines)
    return validate_public_keys(text)


def audit(games):
    report = account_report(games)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    suspect = report['games_sudo_file'] or bool(games and (
        games[5] == '/root' or games[6] not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false')
        or 'not allowed to run sudo' not in report.get('sudo', '')))
    policy = report['ssh']
    key_only = policy.get('authenticationmethods') == 'publickey' and policy.get(
        'passwordauthentication') == 'no' and policy.get('kbdinteractiveauthentication') == 'no'
    print(f'games 可疑配置: {suspect}；SSH 仅公钥策略: {key_only}。这不是完整入侵排查。')
    return 1 if suspect or not key_only else 0


def remediate(service, games, key_file):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise RuntimeError('修复必须在交互终端运行，以避免密码回显或无人确认锁死 SSH。')
    password = collect_password()
    keys, fingerprints = collect_keys(key_file)
    plan = plan_sshd(SSH_CONFIG)
    for path in plan:
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f'Unsafe SSH configuration ownership or permissions: {path}')
    print('将禁用 games 登录及 sudo 权限、终止其 UID 5 进程，替换 root 的全部公钥并设置新密码。')
    print('全局 SSH 仅允许公钥，停用 SSH CA / 外部公钥命令；可能影响现有 SSH 自动化。')
    print('失败恢复只使用新 root 密码和新公钥，不恢复旧密码/旧公钥。')
    print('新公钥指纹：\n' + '\n'.join(fingerprints))
    if input('输入 APPLY 开始修复: ').strip() != 'APPLY':
        print('已取消，没有修改系统配置。')
        return 1
    backup = make_backup(plan)
    print(f'变更前证据目录: {backup}', flush=True)
    candidate = render_stage(plan, backup / 'candidate', SSH_CONFIG)
    recovery_plan = password_recovery(plan, SSH_CONFIG)
    recovery_candidate = render_stage(recovery_plan, backup / 'recovery-candidate', SSH_CONFIG)
    candidate_policy = verify_policy(candidate)
    verify_policy(recovery_candidate, recovery=True)
    script = prepare_recovery(backup, recovery_plan, service, keys)
    unit = None
    password_changed = False
    try:
        disable_games(games, backup)
        run(['chpasswd'], input='root:' + password + '\n')
        password_changed = True
        password = None
        # A timer can now recover using only the new credentials, even if installing
        # the live key file or config is interrupted. Its sources contain public keys only.
        unit = arm_recovery(backup, script)
        install_keys(keys)
        cursor = journal_cursor()
        install_plan(plan)
        verify_policy(SSH_CONFIG)
        run(['systemctl', 'reload', service])
        print('SSH 已切换为仅密钥。请保持此终端连接，在 10 分钟内另开窗口登录。', flush=True)
        print('新窗口命令（替换私钥路径和服务器地址）：', flush=True)
        print('ssh -o ControlMaster=no -o ControlPath=none '
              '-o PreferredAuthentications=publickey -o PasswordAuthentication=no '
              '-o IdentitiesOnly=yes -i /path/to/private_key '
              f'-p {candidate_policy["port"].split()[0]} root@SERVER', flush=True)
        answer = input('完成新的密钥登录后输入 CONFIRM（其他输入恢复新密码 SSH）: ').strip()
        if answer != 'CONFIRM':
            raise RuntimeError('用户未确认密钥登录。')
        if not new_key_login(cursor, fingerprints):
            raise RuntimeError('未找到切换后使用指定新公钥完成 root 登录的记录，拒绝提交。')
        verify_policy(SSH_CONFIG)
        if Path('/root/.ssh/authorized_keys').read_text() != keys:
            raise RuntimeError('授权公钥在修复期间被其他进程修改，拒绝提交。')
        commit(backup, unit)
    except BaseException:
        password = None
        if password_changed and not (backup / 'COMPLETE').exists():
            try:
                if not (backup / 'RECOVERED').exists():
                    atomic_write(backup / 'pending', '')
                recover(backup, unit)
                print('已恢复使用新 root 密码或新公钥的 SSH 登录；games 后门仍禁用。',
                      file=sys.stderr)
            except Exception as recovery_error:
                print(f'自动恢复失败：{recovery_error}。不要断开现有连接；'
                      f'使用可信控制台检查 {backup}/recover.sh。', file=sys.stderr)
        print(f'证据保留在 {backup}；不要全量恢复 before.tar。', file=sys.stderr)
        raise
    print('修复完成：已验证新的 root 密钥登录，SSH 密码认证已禁用；新密码保留用于控制台。')
    print(f'备份: {backup}。已停止恢复定时器并删除恢复脚本；未清理原有日志。')
    print('这只移除已知后门，不能证明曾被 root 控制的系统可信；仍建议重建并轮换其他凭据。')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='交互清理 games 后门，要求新 root 密码和新 SSH 公钥；仅限 Debian/Ubuntu + systemd。')
    parser.add_argument('--check', action='store_true', help='只检查当前账号与 SSH 状态，不修改配置')
    parser.add_argument('--key-file', type=Path, help='读取用户提供的公钥文件；省略则交互粘贴')
    args = parser.parse_args(argv)
    os.environ['PATH'] = SAFE_PATH
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    try:
        service, games = preflight()
        if args.check:
            return audit(games)
        # Do not let concurrent operators race credential or rollback changes.
        descriptor = os.open('/run/lock/games-backdoor-repair.lock',
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('已有另一个修复进程运行。') from None
            return remediate(service, games, args.key_file)
    except (Exception, KeyboardInterrupt) as error:
        print(f'修复未完成：{error or "用户中断"}', file=sys.stderr)
        return 2


def interrupted(signum, frame):
    raise KeyboardInterrupt('收到终止信号')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    raise SystemExit(main())
