"""Build and stage a closed OpenSSH configuration graph without editing live files.

Include globs are frozen to their current sorted file lists. Unsupported path
syntax, symlinks, escaping the main configuration directory, and include cycles
fail closed. Actual sshd -t/-T validation remains the caller's responsibility.
"""

import glob
import os
import stat
from pathlib import Path


_POLICY = (
    ('PermitRootLogin', 'prohibit-password'),
    ('PasswordAuthentication', 'no'),
    ('KbdInteractiveAuthentication', 'no'),
    ('PubkeyAuthentication', 'yes'),
    ('AuthenticationMethods', 'publickey'),
    ('AuthorizedKeysFile', '.ssh/authorized_keys'),
    ('AuthorizedKeysCommand', 'none'),
    ('TrustedUserCAKeys', 'none'),
    ('HostbasedAuthentication', 'no'),
    ('GSSAPIAuthentication', 'no'),
    ('PermitEmptyPasswords', 'no'),
)
_AUTH = {name.lower() for name, _ in _POLICY} | {
    'challengeresponseauthentication', 'dsaauthentication',
    'authorizedkeysfile2', 'authorizedkeyscommanduser',
    'authorizedprincipalsfile', 'authorizedprincipalscommand',
    'authorizedprincipalscommanduser', 'rsaauthentication',
    'rhostsrsaauthentication', 'rhostsauthentication',
    'kerberosauthentication',
}
_BEGIN = '# games-repair: begin key-only policy'
_END = '# games-repair: end key-only policy'
_HEADER = (_BEGIN + '\n' + ''.join(f'{key} {value}\n' for key, value in _POLICY)
           + 'DenyUsers games\n' + _END + '\n')
_RECOVERY = ('# games-repair: root-password recovery\n'
             'Match User root\n'
             '    PermitRootLogin yes\n'
             '    PasswordAuthentication yes\n'
             '    AuthenticationMethods publickey password\n')
_MAX_DEPTH = 16


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _no_symlinks(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            break
        if stat.S_ISLNK(mode):
            raise ValueError(f'Symlink configuration path is not supported: {current}')


def _in_tree(path: Path, base: Path) -> None:
    if not path.is_relative_to(base):
        raise ValueError(f'Include outside configuration directory: {path}')
    _no_symlinks(path)


def _words(text: str) -> list[str]:
    """OpenSSH argv_split rules, not shell/shlex comment or escape rules."""
    result = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index] in ' \t':
            index += 1
        if index == len(text) or text[index] == '#':
            break
        word = []
        quote = None
        while index < len(text):
            char = text[index]
            if char == '\\' and index + 1 < len(text):
                following = text[index + 1]
                if following in "\\\"'" or (quote is None and following == ' '):
                    word.append(following)
                    index += 2
                    continue
            if quote is None and char in ' \t':
                break
            if quote is None and char in "\"'":
                quote = char
            elif char == quote:
                quote = None
            else:
                word.append(char)
            index += 1
        if quote is not None:
            raise ValueError('Unterminated quote in SSH configuration')
        result.append(''.join(word))
    return result


def _directive(line: str) -> tuple[str, list[str]]:
    text = line.rstrip('\n').rstrip(' \t\r\f').lstrip(' \t')
    if not text or text.startswith('#'):
        return '', []
    if any(ord(char) < 32 and char != '\t' for char in text):
        raise ValueError('Control character in SSH configuration')
    index = 0
    while index < len(text) and text[index] not in ' \t="':
        index += 1
    keyword = text[:index]
    if index < len(text) and text[index] == '"':
        end = text.find('"', index + 1)
        if end < 0:
            raise ValueError('Unterminated SSH directive name')
        keyword += text[index + 1:end]
        arguments = text[end + 1:].lstrip(' \t')
    else:
        arguments = text[index:].lstrip(' \t')
        if arguments.startswith('='):
            arguments = arguments[1:].lstrip(' \t')
    if not keyword.isascii() or not keyword[:1].isalpha() or not keyword.isalnum():
        raise ValueError(f'Unsupported SSH directive name: {keyword!r}')
    words = _words(arguments)
    if not words:
        raise ValueError(f'Missing argument for SSH directive: {keyword}')
    return keyword.lower(), words


def _quote(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _path_syntax(path: Path, *, pattern: bool = False) -> None:
    text = str(path)
    if (any(ord(char) < 32 for char in text) or '\\' in text
            or '..' in path.parts or '[^' in text
            or (not pattern and glob.has_magic(text))):
        raise ValueError(f'Unsupported configuration path: {path}')


def _expand(selector: str, base: Path) -> list[Path]:
    if not selector or selector.startswith('~'):
        raise ValueError(f'Unsupported Include selector: {selector!r}')
    path = Path(selector)
    _path_syntax(path, pattern=True)
    path = path if path.is_absolute() else base / path
    _in_tree(path, base)
    # Check the literal prefix even when the glob has no matches.
    prefix = Path(path.anchor)
    for part in path.parts[1:]:
        if glob.has_magic(part):
            break
        prefix /= part
    _no_symlinks(prefix)
    matches = [Path(name) for name in sorted(glob.glob(str(path)))]
    for match in matches:
        _path_syntax(match)
        _in_tree(match, base)
    return matches


def _read_config(path: Path) -> str:
    _no_symlinks(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'r', encoding='utf-8', newline='') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError(f'Configuration is not a regular file: {path}')
        content = stream.read()
    if '\x00' in content:
        raise ValueError(f'NUL byte in SSH configuration: {path}')
    return content


def _without_recovery(content: str) -> str:
    return content[:-len(_RECOVERY)] if content.endswith(_RECOVERY) else content


def plan_sshd(main: Path) -> dict[Path, str]:
    """Return a complete key-only plan; never modify any source configuration."""
    main = _absolute(main)
    _path_syntax(main)
    base = main.parent
    sources: dict[Path, str] = {}
    edges: dict[Path, dict[int, list[Path]]] = {}
    heights: dict[Path, int] = {}
    visiting: set[Path] = set()

    def inspect(path: Path, depth: int) -> int:
        if path in visiting:
            raise ValueError(f'Include cycle at {path}')
        if depth > _MAX_DEPTH:
            raise ValueError('SSH Include nesting exceeds OpenSSH limit')
        if path in heights:
            if depth + heights[path] > _MAX_DEPTH:
                raise ValueError('SSH Include nesting exceeds OpenSSH limit')
            return heights[path]
        _in_tree(path, base)
        content = _without_recovery(_read_config(path))
        sources[path] = content
        edges[path] = {}
        visiting.add(path)
        height = 0
        for number, line in enumerate(content.splitlines(keepends=True)):
            keyword, arguments = _directive(line)
            if keyword != 'include':
                continue
            included = []
            for selector in arguments:
                included.extend(_expand(selector, base))
            edges[path][number] = included
            for child in included:
                height = max(height, 1 + inspect(child, depth + 1))
        visiting.remove(path)
        heights[path] = height
        return height

    try:
        inspect(main, 0)
    except (OSError, UnicodeError) as error:
        raise ValueError(f'Cannot inspect SSH configuration: {error}') from error
    plan = {}
    for path, content in sources.items():
        output = []
        for number, line in enumerate(content.splitlines(keepends=True)):
            keyword, arguments = _directive(line)
            if keyword in _AUTH or line.rstrip('\r\n') in (_BEGIN, _END):
                continue
            if keyword == 'denyusers':
                if arguments == ['games']:
                    continue
                if 'games' not in arguments:
                    line = 'DenyUsers ' + ' '.join(_quote(x) for x in [*arguments, 'games']) + '\n'
            elif keyword == 'include':
                included = edges[path][number]
                line = ('Include ' + ' '.join(_quote(str(child)) for child in included) + '\n'
                        if included else '# games-repair: inactive ' + line.strip() + '\n')
            output.append(line if line.endswith('\n') else line + '\n')
        plan[path] = (_HEADER if path == main else '') + ''.join(output)
    return plan


def _closed_plan(plan: dict[Path, str], main: Path) -> dict[Path, list[list[Path]]]:
    if main not in plan:
        raise ValueError('Main configuration is absent from plan')
    graph = {}
    for path, content in plan.items():
        if not path.is_absolute() or path != _absolute(path):
            raise ValueError('Configuration plan paths must be canonical absolute paths')
        _path_syntax(path)
        _in_tree(path, main.parent)
        includes = []
        for line in content.splitlines(keepends=True):
            keyword, arguments = _directive(line)
            if keyword != 'include':
                continue
            children = []
            for argument in arguments:
                child = Path(argument)
                _path_syntax(child)
                if not child.is_absolute() or child not in plan:
                    raise ValueError(f'Include is absent from closed plan: {child}')
                children.append(child)
            includes.append(children)
        graph[path] = includes
    visiting = set()
    reached = set()

    def visit(path: Path, depth: int) -> None:
        if depth > _MAX_DEPTH or path in visiting:
            raise ValueError('Unsafe include nesting in configuration plan')
        visiting.add(path)
        reached.add(path)
        for children in graph[path]:
            for child in children:
                visit(child, depth + 1)
        visiting.remove(path)

    visit(main, 0)
    if reached != set(plan):
        raise ValueError('Configuration plan contains unreachable files')
    return graph


def render_stage(plan: dict[Path, str], stage_dir: Path, main: Path) -> Path:
    """Write a closed candidate into a new/empty directory, never live sources."""
    main = _absolute(main)
    stage_dir = _absolute(stage_dir)
    try:
        graph = _closed_plan(plan, main)
        _path_syntax(stage_dir)
        _no_symlinks(stage_dir)
        if stage_dir.exists() and (not stage_dir.is_dir() or any(stage_dir.iterdir())):
            raise ValueError('Stage directory must be new or empty')
        mapping = {path: stage_dir / f'{number:04d}.conf'
                   for number, path in enumerate(sorted(plan))}
        if set(mapping.values()) & set(plan):
            raise ValueError('Stage paths overlap source configuration')
        rendered = {}
        for path, content in plan.items():
            includes = iter(graph[path])
            output = []
            for line in content.splitlines(keepends=True):
                keyword, _ = _directive(line)
                if keyword == 'include':
                    line = 'Include ' + ' '.join(_quote(str(mapping[p])) for p in next(includes)) + '\n'
                output.append(line)
            rendered[mapping[path]] = ''.join(output)
        stage_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(stage_dir, 0o700)
        for path, content in rendered.items():
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='') as stream:
                stream.write(content)
        return mapping[main]
    except (OSError, UnicodeError) as error:
        raise ValueError(f'Cannot stage SSH configuration: {error}') from error


def password_recovery(plan: dict[Path, str], main: Path) -> dict[Path, str]:
    """Allow only root to use its newly rotated password during recovery."""
    main = _absolute(main)
    _closed_plan(plan, main)
    recovery = dict(plan)
    content = _without_recovery(recovery[main])
    recovery[main] = content + ('' if content.endswith('\n') else '\n') + _RECOVERY
    return recovery
