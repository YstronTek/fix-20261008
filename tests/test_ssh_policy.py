import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.ssh_policy import password_recovery, plan_sshd, render_stage
from tools.repair_system import parse_policy


class SSHPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / 'sshd_config'
        self.sshd = shutil.which('sshd')
        if not self.sshd:
            self.fail('Real sshd is required for policy tests')
        self.host_key = self.root / 'host_ed25519'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                        '-f', str(self.host_key)], check=True)

    def effective(self, config, user='root', address='192.0.2.1'):
        syntax = subprocess.run(
            [self.sshd, '-t', '-h', str(self.host_key), '-f', str(config)],
            capture_output=True, text=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        result = subprocess.run(
            [self.sshd, '-T', '-h', str(self.host_key), '-f', str(config), '-C',
             f'user={user},host=example.test,addr={address}'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return parse_policy(result.stdout)

    def stage(self, plan, name='stage'):
        return render_stage(plan, self.root / name, self.config)

    def assert_key_only(self, policy):
        expected = {
            'passwordauthentication': 'no',
            'kbdinteractiveauthentication': 'no',
            'pubkeyauthentication': 'yes',
            'authenticationmethods': 'publickey',
            'authorizedkeysfile': '.ssh/authorized_keys',
            'authorizedkeyscommand': 'none',
            'trustedusercakeys': 'none',
            'hostbasedauthentication': 'no',
            'gssapiauthentication': 'no',
            'permitemptypasswords': 'no',
        }
        for name, value in expected.items():
            self.assertEqual(policy[name], value, name)
        self.assertIn('games', policy['denyusers'].split())

    def test_match_and_include_cannot_reenable_root_password_authentication(self):
        includes = self.root / 'sshd_config.d'
        includes.mkdir()
        self.config.write_text('Port 22222\nInclude sshd_config.d/*.conf\n'
                               'Match User root\nPasswordAuthentication yes\n'
                               'AuthenticationMethods any\n')
        (includes / 'cloud.conf').write_text('PermitRootLogin yes\n'
                                            'PasswordAuthentication yes\n')
        plan = plan_sshd(self.config)
        policy = self.effective(self.stage(plan))
        self.assert_key_only(policy)
        self.assertIn(policy['permitrootlogin'], ('without-password', 'prohibit-password'))
        self.assertEqual(policy['port'], '22222')

    def test_nested_sorted_include_alias_equals_and_match_policies(self):
        directory = self.root / 'conf space'
        directory.mkdir()
        self.config.write_text(
            '# retain this comment\nPort 22345\n'
            'Include="conf space/*.conf"\nDenyUsers=blocked\n'
            'Match User root\n  ChallengeResponseAuthentication=yes\n'
            '  PasswordAuthentication = yes\n  PubkeyAuthentication=no\n'
            '  AuthorizedKeysFile /tmp/attacker\n'
            '  AuthorizedKeysCommand /bin/true\n'
            '  AuthorizedKeysCommandUser root\n'
            '  AuthenticationMethods=any\n  PermitRootLogin=yes\n'
            '  DenyUsers another\n  X11Forwarding no\n'
            'Match User games\n  DenyUsers other\n'
            '  PasswordAuthentication yes\n')
        (directory / '20-second.conf').write_text('ClientAliveInterval 71\n')
        (directory / '10-first.conf').write_text(
            'ClientAliveInterval 37\nInclude nested.conf\n')
        nested = self.root / 'nested.conf'
        nested.write_text(
            '"PasswordAuthentication" yes\n'
            'KbdInteractiveAuthentication yes\nPubkeyAuthentication no\n'
            'HostbasedAuthentication yes\nGSSAPIAuthentication yes\n'
            'PermitEmptyPasswords yes\n'
            'Match Address 192.0.2.0/24\n'
            '  PasswordAuthentication yes\n  AuthenticationMethods any\n')
        plan = plan_sshd(self.config)
        staged = self.stage(plan)
        for user in ('root', 'games', 'nobody'):
            with self.subTest(user=user):
                policy = self.effective(staged, user)
                self.assert_key_only(policy)
                self.assertEqual(policy['clientaliveinterval'], '37')
                self.assertEqual(policy['port'], '22345')
        self.assertIn('another', self.effective(staged)['denyusers'].split())
        self.assertIn('other', self.effective(staged, 'games')['denyusers'].split())
        self.assertIn('blocked', self.effective(staged, 'nobody', '198.51.100.4')['denyusers'].split())
        self.assertEqual(self.effective(staged)['x11forwarding'], 'no')

    def test_stage_is_self_contained_and_live_plan_has_same_effective_policy(self):
        child = self.root / 'child.conf'
        child.write_text('ClientAliveInterval 43\nPasswordAuthentication yes\n')
        self.config.write_text('Include child.conf missing-*.conf\nPort 22444\n')
        original = {self.config: self.config.read_text(), child: child.read_text()}
        plan = plan_sshd(self.config)
        staged = self.stage(plan)
        self.assertEqual({p: p.read_text() for p in original}, original)
        staged_policy = self.effective(staged)
        child.write_text('UnknownBrokenDirective yes\n')
        self.assertEqual(self.effective(staged), staged_policy)
        # New files cannot silently enter the already validated frozen graph.
        (self.root / 'missing-new.conf').write_text('PasswordAuthentication yes\n')
        for path, contents in plan.items():
            path.write_text(contents)
        self.assertEqual(self.effective(self.config), staged_policy)

    def test_repeated_execution_does_not_grow_policy_or_drop_denials(self):
        self.config.write_text('Port 22222\nDenyUsers blocked\n'
                               'Match User root\nDenyUsers other games\n')
        first = plan_sshd(self.config)
        for path, contents in first.items():
            path.write_text(contents)
        second = plan_sshd(self.config)
        self.assertEqual(first, second)
        self.assert_key_only(self.effective(self.stage(second)))

    def test_recovery_is_root_only_and_preserves_key_policy_for_everyone_else(self):
        child = self.root / 'root.conf'
        child.write_text('Match User root\nPasswordAuthentication yes\n'
                         'AuthenticationMethods any\nPermitRootLogin yes\n')
        self.config.write_text('Include root.conf\nMatch All\n'
                               'DenyUsers blocked\nX11Forwarding no\n')
        plan = plan_sshd(self.config)
        untouched = dict(plan)
        recovery = password_recovery(plan, self.config)
        self.assertEqual(plan, untouched)
        self.assertEqual(password_recovery(recovery, self.config), recovery)
        staged = self.stage(recovery)
        root = self.effective(staged)
        self.assertEqual(root['passwordauthentication'], 'yes')
        self.assertEqual(root['permitrootlogin'], 'yes')
        self.assertEqual(set(root['authenticationmethods'].split()), {'publickey', 'password'})
        self.assertEqual(root['kbdinteractiveauthentication'], 'no')
        self.assertEqual(root['authorizedkeysfile'], '.ssh/authorized_keys')
        self.assertIn('games', root['denyusers'].split())
        for user in ('games', 'nobody'):
            self.assert_key_only(self.effective(staged, user))

    def test_cycles_and_excessive_include_depth_fail_without_mutation(self):
        child = self.root / 'child.conf'
        self.config.write_text('Include child.conf\n')
        child.write_text('Include sshd_config\n')
        original = {p: p.read_bytes() for p in (self.config, child)}
        with self.assertRaises(ValueError):
            plan_sshd(self.config)
        self.assertEqual({p: p.read_bytes() for p in original}, original)
        self.config.write_text('Include depth0.conf\n')
        for number in range(18):
            (self.root / f'depth{number}.conf').write_text(
                f'Include depth{number + 1}.conf\n' if number < 17 else '# end\n')
        with self.assertRaises(ValueError):
            plan_sshd(self.config)

    def test_symlink_files_and_directories_and_out_of_tree_patterns_are_refused(self):
        with tempfile.TemporaryDirectory() as outside_directory:
            outside = Path(outside_directory)
            (outside / 'external.conf').write_text('PasswordAuthentication yes\n')
            (self.root / 'link.conf').symlink_to(outside / 'external.conf')
            (self.root / 'link-dir').symlink_to(outside, target_is_directory=True)
            for include in ('link.conf', 'link-dir/*.conf',
                            str(outside / '*.conf'), str(outside / 'absent-*.conf')):
                with self.subTest(include=include):
                    self.config.write_text(f'Include {include}\n')
                    with self.assertRaises(ValueError):
                        plan_sshd(self.config)
            self.config.unlink()
            self.config.symlink_to(outside / 'external.conf')
            with self.assertRaises(ValueError):
                plan_sshd(self.config)

    def test_malformed_graph_and_stage_collisions_fail_before_writes(self):
        for text in ('Include\n', 'Include "unclosed\n', 'Include ~root/config\n',
                     'Include sshd_config.d\n', 'PasswordAuthentication\x00 yes\n'):
            with self.subTest(text=text):
                (self.root / 'sshd_config.d').mkdir(exist_ok=True)
                self.config.write_text(text)
                with self.assertRaises(ValueError):
                    plan_sshd(self.config)
        self.config.write_text('Port 22222\n')
        plan = plan_sshd(self.config)
        stage = self.root / 'stage'
        stage.mkdir()
        occupied = stage / 'existing'
        occupied.write_text('do not overwrite')
        with self.assertRaises(ValueError):
            render_stage(plan, stage, self.config)
        self.assertEqual(occupied.read_text(), 'do not overwrite')
        with self.assertRaises(ValueError):
            render_stage({self.config: 'Include /outside.conf\n'}, self.root / 'bad', self.config)
        self.assertFalse((self.root / 'bad').exists())


if __name__ == '__main__':
    unittest.main()
