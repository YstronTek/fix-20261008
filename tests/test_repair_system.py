import unittest

from tools.repair_system import parse_policy


class EffectivePolicyTests(unittest.TestCase):
    def test_repeated_deny_entries_keep_every_denied_account(self):
        policy = parse_policy('DenyUsers blocked\nDenyUsers games\n'
                              'PasswordAuthentication no\n')
        self.assertEqual(set(policy['denyusers'].split()), {'blocked', 'games'})
        self.assertEqual(policy['passwordauthentication'], 'no')

    def test_older_combined_list_and_lowercase_names_remain_supported(self):
        policy = parse_policy('denyusers blocked games\npasswordauthentication no\n')
        self.assertEqual(set(policy['denyusers'].split()), {'blocked', 'games'})
        self.assertEqual(policy['passwordauthentication'], 'no')


if __name__ == '__main__':
    unittest.main()
