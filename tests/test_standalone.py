import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class StandaloneTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.bundle = self.directory / 'repair.sh'
        subprocess.run([sys.executable, str(ROOT / 'tools/build_standalone.py'),
                        '--output', str(self.bundle)], check=True, capture_output=True)

    def execute(self, script, *arguments):
        result = subprocess.run(['bash', '-x', '-s', '--', *arguments],
                                input=script, text=True, capture_output=True,
                                cwd=self.directory, start_new_session=True)
        workspaces = set(re.findall(r'/tmp/games-repair-run\.[A-Za-z0-9]+', result.stderr))
        for workspace in workspaces:
            self.assertFalse(Path(workspace).exists(), 'Extracted code remained after exit')
        return result

    def test_piped_bundle_works_without_checkout_and_cleans_up_on_cli_error(self):
        script = self.bundle.read_text()
        self.assertEqual(self.execute(script, '--help').returncode, 0)
        self.assertEqual(self.execute(script, '--check', '--unknown-option').returncode, 2)
        self.assertEqual(list(self.directory.iterdir()), [self.bundle])

    def test_corrupted_download_is_rejected_before_running_repair(self):
        script = self.bundle.read_text()
        # Damage encoded archive data, not a Python module or a mocked command.
        match = re.search(r'(?m)^[A-Za-z0-9+/]{80,}={0,2}$', script)
        self.assertIsNotNone(match, 'No embedded archive found')
        start = match.start()
        replacement = 'A' if script[start] != 'A' else 'B'
        corrupted = script[:start] + replacement + script[start + 1:]
        result = self.execute(corrupted, '--check')
        self.assertEqual(result.returncode, 65)

    def test_interactive_execution_without_a_terminal_is_refused(self):
        result = self.execute(self.bundle.read_text())
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
