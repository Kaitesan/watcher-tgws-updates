"""Versioned, integrity-checked Watcher CLI distributions; never overwrite bundled files."""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

BUNDLED_VERSION = '1.11.4'
BUNDLED = 'bundled'
EXE = 'WatcherTgWsProxy.exe'
CONTRACT = 1
MAX_ARCHIVE = 200 * 1024 * 1024
MAX_UNPACKED = 500 * 1024 * 1024


def version(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not re.fullmatch(r'\d{1,6}\.\d{1,6}\.\d{1,6}', value):
        raise ValueError('Invalid proxy version')
    return tuple(map(int, value.split('.')))


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        h = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
        return h.hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class VersionStore:
    def __init__(self, root: Path):
        self.root = root
        self.state_path = root / 'version-state.json'
        self.versions = root / 'versions'

    def state(self) -> dict:
        try:
            result = json.loads(self.state_path.read_text(encoding='utf-8'))
            for key in ('active', 'previous', 'pending'):
                v = result[key]
                if v is not None and v != BUNDLED:
                    version(v)
            if result['active'] is None:
                raise ValueError('Missing active version')
            return result
        except (OSError, ValueError, KeyError, TypeError):
            return {'active': BUNDLED, 'previous': None, 'pending': None}

    def save(self, active: str, previous: str | None, pending: str | None = None) -> None:
        for v in (active, previous, pending):
            if v is not None and v != BUNDLED:
                version(v)
        atomic_json(self.state_path, {'active': active, 'previous': previous, 'pending': pending})

    def info(self) -> dict:
        state = self.state()
        return {'bundled_version': BUNDLED_VERSION,
                'active_version': BUNDLED_VERSION if state['active'] == BUNDLED else state['active'],
                'active_is_bundled': state['active'] == BUNDLED,
                'previous_version': BUNDLED_VERSION if state['previous'] == BUNDLED else state['previous'],
                'has_previous': state['previous'] is not None and state['previous'] != state['active']}

    def executable(self, v: str) -> Path:
        version(v)
        folder = self.versions / v
        if folder.is_symlink() or folder.resolve().parent != self.versions.resolve():
            raise ValueError('Invalid proxy version directory')
        index = json.loads((folder / '.watcher-files.json').read_text(encoding='utf-8'))
        if index['version'] != v or index['contract'] != CONTRACT or EXE not in index['files']:
            raise ValueError('Invalid installed proxy manifest')
        actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
        if actual != set(index['files']) | {'.watcher-files.json'}:
            raise ValueError('Unexpected files in proxy distribution')
        for name, sha in index['files'].items():
            file = folder / safe_name(name)
            if file.is_symlink() or not file.resolve().is_relative_to(folder.resolve()) or digest(file) != sha:
                raise ValueError('Installed proxy integrity check failed')
        return (folder / EXE).resolve()

    def install(self, archive: Path, v: str, sha: str) -> Path:
        version(v)
        if archive.stat().st_size > MAX_ARCHIVE or digest(archive) != sha:
            raise ValueError('Proxy archive SHA-256 mismatch or size limit exceeded')
        self.versions.mkdir(parents=True, exist_ok=True)
        target = self.versions / v
        if target.exists():
            # Never overwrite a version which may be active or available for rollback.
            existing = json.loads((target / '.watcher-files.json').read_text(encoding='utf-8'))
            if existing.get('archive_sha256') != sha:
                raise ValueError('Version already exists with a different digest')
            return self.executable(v)
        staging = Path(tempfile.mkdtemp(prefix='.staging-', dir=self.versions))
        try:
            files = {}
            seen = set()
            with zipfile.ZipFile(archive) as z:
                entries = z.infolist()
                if len(entries) > 4000 or sum(i.file_size for i in entries) > MAX_UNPACKED:
                    raise ValueError('Proxy archive exceeds limits')
                for item in entries:
                    name = safe_name(item.filename.rstrip('/'))
                    key = name.casefold()
                    if key in seen or key == '.watcher-files.json':
                        raise ValueError('Duplicate/reserved archive path')
                    seen.add(key)
                    if stat.S_ISLNK(item.external_attr >> 16):
                        raise ValueError('Symlinks are forbidden in proxy package')
                    dest = staging / name
                    if item.is_dir():
                        dest.mkdir(parents=True, exist_ok=True)
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(item) as src, dest.open('xb') as out:
                        shutil.copyfileobj(src, out)
                    files[name] = digest(dest)
            if EXE not in files:
                raise ValueError('Watcher CLI executable missing')
            atomic_json(staging / '.watcher-files.json', {'version': v, 'contract': CONTRACT,
                         'archive_sha256': sha, 'files': files})
            staging.rename(target)
            return self.executable(v)
        finally:
            if staging.exists():
                shutil.rmtree(staging)


def safe_name(name: str) -> str:
    # Reject Windows aliases, traversal, ADS, reserved device names and paths.
    parts = name.split('/')
    if not name or '\\' in name or any(not p or p in ('.', '..') or p.endswith((' ', '.')) or
            re.search(r'[<>:"|?*\x00-\x1f]', p) or
            p.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1,10)), *(f'LPT{i}' for i in range(1,10))}
            for p in parts):
        raise ValueError('Unsafe archive path')
    return PurePosixPath(name).as_posix()


def probe(exe: Path, expected: str) -> None:
    """Execute only the already verified package, with a non-network CLI probe."""
    import subprocess
    flags = ('--host', '--port', '--secret', '--log-file', '--log-max-mb', '--log-backups',
             '--pool-size', '--buf-kb', '--no-cfproxy', '--no-secure', '--fake-tls-domain',
             '--cfproxy-domain', '--cfproxy-worker-domain', '--dc-ip', '--verbose')
    with tempfile.TemporaryDirectory() as tmp:
        result = Path(tmp) / 'probe.json'
        subprocess.run([str(exe), '--watcher-probe', str(result)], cwd=exe.parent,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=20, check=True, creationflags=0x08000000 if os.name == 'nt' else 0)
        data = json.loads(result.read_text(encoding='utf-8'))
        if data['contract'] != CONTRACT or data['version'] != expected or not all(flag in data['help'] for flag in flags):
            raise ValueError('CLI version or required options are incompatible')


def canonical_manifest(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')


def verify_manifest(envelope: dict, public_key_hex: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    payload = envelope['payload']
    if not isinstance(payload, dict):
        raise ValueError('Invalid signed manifest')
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    try:
        key.verify(bytes.fromhex(envelope['signature']), canonical_manifest(payload))
    except InvalidSignature as exc:
        raise ValueError('CLI update manifest signature is invalid') from exc
    return payload
