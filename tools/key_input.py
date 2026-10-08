"""Validate bare OpenSSH public keys, never authorized_keys options or secrets."""

import base64
import binascii
import hashlib
import os
import struct
import subprocess
import tempfile
from pathlib import Path


_KEYGEN = '/usr/bin/ssh-keygen'
_KEY_TYPES = {
    'ssh-ed25519', 'ssh-rsa',
    'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com',
}


def _parse_line(line: str, number: int) -> tuple[str, bytes, str]:
    fields = line.split(None, 2)
    if len(fields) < 2 or fields[0] not in _KEY_TYPES:
        raise ValueError(f'Line {number}: supply a bare supported SSH public key, without options')
    kind, encoded = fields[:2]
    try:
        blob = base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f'Line {number}: invalid public-key encoding') from error
    if len(blob) < 4:
        raise ValueError(f'Line {number}: incomplete public-key data')
    length = struct.unpack('>I', blob[:4])[0]
    if blob[4:4 + length] != kind.encode('ascii'):
        raise ValueError(f'Line {number}: public-key type does not match encoded material')
    canonical = kind + ' ' + base64.b64encode(blob).decode('ascii')
    comment = fields[2].strip() if len(fields) == 3 else ''
    return canonical, blob, comment


def validate_public_keys(text: str) -> tuple[str, list[str]]:
    """Validate every nonblank line with real ssh-keygen, then deduplicate.

    Returns newline-terminated authorized_keys content and ordered unique SHA256
    fingerprints. Errors return no partial result and contain no supplied key
    data. Only temporary public-key files are created; no live key file is read
    or modified. Hardware-backed public keys need no local hardware to inspect.
    """
    if not isinstance(text, str):
        raise ValueError('Public keys must be text')
    text = text.replace('\r\n', '\n')
    if any((ord(char) < 32 and char not in '\t\n') or ord(char) == 127
           or char in '\u0085\u2028\u2029' for char in text):
        raise ValueError('Control characters are not permitted in public-key input')
    lines = [(number, line.strip()) for number, line in enumerate(text.split('\n'), 1)
             if line.strip()]
    if not lines:
        raise ValueError('At least one new SSH public key is required')
    parsed = [(number, *_parse_line(line, number)) for number, line in lines]
    normalized = []
    fingerprints = []
    seen = set()
    try:
        with tempfile.TemporaryDirectory(prefix='games-repair-public-') as directory:
            public_file = Path(directory) / 'key.pub'
            for number, canonical, blob, comment in parsed:
                descriptor = os.open(public_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'w', encoding='ascii') as stream:
                    stream.write(canonical + '\n')
                result = subprocess.run(
                    [_KEYGEN, '-l', '-E', 'sha256', '-f', str(public_file)],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
                    timeout=15, check=False)
                fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('=')
                output = result.stdout.strip().splitlines()
                if (result.returncode != 0 or len(output) != 1
                        or len(output[0].split()) < 2 or output[0].split()[1] != fingerprint):
                    raise ValueError(f'Line {number}: ssh-keygen rejected the public key')
                if blob not in seen:
                    normalized.append(canonical + (' ' + comment if comment else ''))
                    fingerprints.append(fingerprint)
                    seen.add(blob)
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise ValueError('Cannot validate public keys using /usr/bin/ssh-keygen') from error
    return '\n'.join(normalized) + '\n', fingerprints
