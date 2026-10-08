import base64
import hashlib
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.key_input import validate_public_keys


class PublicKeyInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.keygen = shutil.which('ssh-keygen')
        if not cls.keygen:
            raise RuntimeError('Real ssh-keygen is required for public-key tests')
        cls.keys = {}
        cls.fingerprints = {}
        for kind in ('ed25519', 'rsa', 'ecdsa'):
            path = cls.root / kind
            arguments = [cls.keygen, '-q', '-t', kind, '-N', '', '-C', 'test key', '-f', str(path)]
            if kind == 'rsa':
                arguments += ['-b', '2048']
            subprocess.run(arguments, capture_output=True, check=True)
            cls.keys[kind] = path.with_suffix('.pub').read_text().strip()
            result = subprocess.run(
                [cls.keygen, '-l', '-E', 'sha256', '-f', str(path.with_suffix('.pub'))],
                capture_output=True, text=True, check=True)
            cls.fingerprints[kind] = result.stdout.split()[1]

    def test_all_supported_software_key_types_are_validated_by_real_keygen(self):
        text = '\n\n'.join(self.keys.values())
        normalized, fingerprints = validate_public_keys(text)
        self.assertEqual(normalized, '\n'.join(self.keys.values()) + '\n')
        self.assertEqual(fingerprints, list(self.fingerprints.values()))

    def test_duplicate_material_ignores_comments_and_preserves_first_order(self):
        first = self.keys['ed25519']
        material = ' '.join(first.split()[:2])
        normalized, fingerprints = validate_public_keys(
            f'\n  {first}  \n{material} other comment\n{self.keys["rsa"]}\n')
        self.assertEqual(normalized, first + '\n' + self.keys['rsa'] + '\n')
        self.assertEqual(fingerprints, [self.fingerprints['ed25519'], self.fingerprints['rsa']])

    def test_empty_private_key_options_urls_and_mixed_invalid_input_fail_closed(self):
        private = (self.root / 'ed25519').read_text()
        valid = self.keys['ed25519']
        invalid_inputs = [
            '', ' \n\t\n', private, valid + '\n' + private,
            'https://example.test/key.pub', '# comment rather than a public key',
            'ssh-ed25519 not-base64', 'ssh-ed25519 AAAA',
            'command="/bin/sh" ' + valid, 'no-pty ' + valid,
            'cert-authority ' + valid, 'restrict ' + valid,
            valid + '\nnot a key', valid + '\nssh-rsa AAAA',
            valid + '\x00', valid + '\rcommand injection',
            valid + '\u2028ssh-ed25519 AAAA',
        ]
        for text in invalid_inputs:
            with self.subTest(prefix=text[:40]):
                with self.assertRaises(ValueError):
                    validate_public_keys(text)

    def test_declared_key_type_must_match_binary_key_material(self):
        material = self.keys['ed25519'].split()[1]
        with self.assertRaises(ValueError):
            validate_public_keys(f'ssh-rsa {material}')
        with self.assertRaises(ValueError):
            validate_public_keys('ssh-ed25519 ' + base64.b64encode(b'not a key').decode())

    def test_certificate_keys_do_not_delegate_authorization_to_a_ca(self):
        target = self.root / 'certificate-target.pub'
        target.write_text(self.keys['rsa'] + '\n')
        subprocess.run(
            [self.keygen, '-q', '-s', str(self.root / 'ed25519'), '-I', 'test',
             '-n', 'root', str(target)], capture_output=True, check=True)
        certificate = (self.root / 'certificate-target-cert.pub').read_text()
        with self.assertRaises(ValueError):
            validate_public_keys(certificate)
        with self.assertRaises(ValueError):
            validate_public_keys(self.keys['rsa'] + '\n' + certificate)

    def test_fido_public_key_format_is_checked_without_requiring_hardware(self):
        # A FIDO public key is public material plus its application binding;
        # generating a hardware signature is outside this input-validation seam.
        ed_blob = base64.b64decode(self.keys['ed25519'].split()[1])
        ed_type_length = struct.unpack('>I', ed_blob[:4])[0]
        public_field = ed_blob[4 + ed_type_length:]
        kind = b'sk-ssh-ed25519@openssh.com'
        application = b'ssh:test'
        blob = (struct.pack('>I', len(kind)) + kind + public_field
                + struct.pack('>I', len(application)) + application)
        line = kind.decode() + ' ' + base64.b64encode(blob).decode() + ' hardware'
        normalized, fingerprints = validate_public_keys(line)
        self.assertEqual(normalized, line + '\n')
        expected = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        self.assertEqual(fingerprints, [expected])

    def test_crlf_and_missing_comment_are_normalized(self):
        bare = ' '.join(self.keys['ed25519'].split()[:2])
        normalized, fingerprints = validate_public_keys('\r\n' + bare + '\r\n')
        self.assertEqual(normalized, bare + '\n')
        self.assertEqual(fingerprints, [self.fingerprints['ed25519']])


if __name__ == '__main__':
    unittest.main()
