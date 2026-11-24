"""Trusted release channel helper. Build and sign on separate runners."""
from __future__ import annotations
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.services.tgws_version_store import (BUNDLED_VERSION, CONTRACT, EXE, VersionStore,
    canonical_manifest, digest, probe, verify_manifest, version)

UPSTREAM = 'Flowseal/tg-ws-proxy'


def repository(value):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value):
        raise ValueError('Expected owner/repository')
    return value


def api(path, *, missing=False):
    req = urllib.request.Request('https://api.github.com/' + path, headers={
        'Accept': 'application/vnd.github+json', 'User-Agent': 'Watcher-TGWS-CI',
        'X-GitHub-Api-Version': '2022-11-28'})
    if os.getenv('GH_TOKEN'):
        req.add_header('Authorization', 'Bearer ' + os.environ['GH_TOKEN'])
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if missing and exc.code == 404:
            return None
        raise


def discover(repo):
    latest = api(f'repos/{UPSTREAM}/releases/latest')
    tag = latest['tag_name']
    if not re.fullmatch(r'v\d{1,6}\.\d{1,6}\.\d{1,6}', tag) or latest['draft'] or latest['prerelease']:
        raise ValueError('Unsupported upstream release tag')
    ver = tag[1:]
    current = api(f'repos/{repository(repo)}/releases/latest', missing=True)
    previous = BUNDLED_VERSION
    if current:
        if not current['tag_name'].startswith('proxy-v'):
            raise ValueError('Use a dedicated repository for proxy releases')
        previous = current['tag_name'][7:]
        version(previous)
    if version(ver) <= version(previous):
        return {'needed': 'false', 'version': ver, 'commit': ''}
    obj = api(f'repos/{UPSTREAM}/git/ref/tags/{tag}')['object']
    for _ in range(5):
        if not re.fullmatch(r'[0-9a-f]{40}', obj['sha']):
            raise ValueError('Invalid upstream object SHA')
        if obj['type'] == 'commit':
            return {'needed': 'true', 'version': ver, 'commit': obj['sha']}
        if obj['type'] != 'tag':
            break
        obj = api(f"repos/{UPSTREAM}/git/tags/{obj['sha']}")['object']
    raise ValueError('Upstream tag does not resolve to a commit')


def archive_name(ver):
    version(ver)
    return f'WatcherTgWsProxy-{ver}-windows-x64.zip'


def smoke(exe, *, extra=()):
    """Start only on a temporary localhost port, verify the child owns the listener."""
    import psutil
    with tempfile.TemporaryDirectory(prefix='tgws-smoke-') as tmp:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        log = Path(tmp) / 'proxy.log'
        proc = subprocess.Popen([str(exe), '--host', '127.0.0.1', '--port', str(port),
            '--secret', '0123456789abcdef0123456789abcdef', '--log-file', str(log),
            '--log-max-mb', '2', '--log-backups', '2', '--pool-size', '1',
            '--buf-kb', '256', *extra], cwd=tmp, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000 if os.name == 'nt' else 0)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f'Proxy exited during smoke test ({proc.returncode})')
                listeners = psutil.Process(proc.pid).net_connections(kind='tcp')
                if any(c.status == psutil.CONN_LISTEN and c.laddr.ip == '127.0.0.1' and c.laddr.port == port for c in listeners):
                    with socket.create_connection(('127.0.0.1', port), timeout=2):
                        pass
                    time.sleep(2)
                    if proc.poll() is None:
                        return
                    raise RuntimeError('Proxy exited after smoke connection')
                time.sleep(.5)
            raise TimeoutError('Proxy did not listen on localhost')
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
            if log.exists():
                print(log.read_text(encoding='utf-8', errors='replace')[-3000:])


def build(source, ver, commit, out):
    import platform
    if os.name != 'nt' or sys.version_info[:2] != (3, 12) or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise RuntimeError('Requires Windows x64 Python 3.12')
    source = source.resolve()
    actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != commit or not (source / 'LICENSE').is_file():
        raise ValueError('Wrong upstream source commit or missing license')
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='watcher-tgws-') as tmp:
        tmp = Path(tmp)
        subprocess.run([sys.executable, '-m', 'pip', 'install', str(source)], check=True)
        entry = tmp / 'tgws_entry.py'
        shutil.copy2(ROOT / 'tgws_entry.py', entry)
        subprocess.run([sys.executable, '-m', 'nuitka', '--mode=standalone', '--msvc=latest',
            '--assume-yes-for-downloads', '--windows-console-mode=disable', f'--output-dir={tmp}',
            f'--output-filename={EXE}', '--include-package=proxy', str(entry)], check=True, cwd=tmp)
        dist = tmp / 'tgws_entry.dist'
        shutil.copy2(source / 'LICENSE', dist / 'UPSTREAM-LICENSE.txt')
        probe(dist / EXE, ver)
        smoke(dist / EXE)
        smoke(dist / EXE, extra=('--no-secure',))
        archive = out / archive_name(ver)
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for p in sorted(dist.rglob('*')):
                if p.is_file():
                    z.write(p, p.relative_to(dist).as_posix())
        # Test actual packaged files with the exact client extraction and probe.
        exe = VersionStore(tmp / 'store').install(archive, ver, digest(archive))
        probe(exe, ver)
        smoke(exe, extra=('--no-cfproxy', '--no-secure'))
    (out / 'build.json').write_text(json.dumps({'version': ver, 'commit': commit,
        'sha256': digest(archive)}), encoding='utf-8')


def config(repo, public):
    repository(repo)
    if not re.fullmatch(r'[0-9a-f]{64}', public):
        raise ValueError('Expected Ed25519 public key in hex')
    return {'public_key': public, 'manifest_url': f'https://github.com/{repo}/releases/latest/download/latest.json'}


def create_key(repo, key_file, config_file):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    repository(repo)
    key = Ed25519PrivateKey.generate()
    with os.fdopen(os.open(key_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    public = key.public_key().public_bytes_raw().hex()
    config_file.write_text(json.dumps(config(repo, public), indent=2), encoding='utf-8')
    print('Public key (TGWS_PUBLIC_KEY):', public)
    print('Private key file:', key_file, '\nPublic Watcher configuration:', config_file)


def sign(repo, ver, commit, out, key_pem, expected_public):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    archive = out / archive_name(ver)
    meta = json.loads((out / 'build.json').read_text(encoding='utf-8'))
    sha = digest(archive)
    if meta != {'version': ver, 'commit': commit, 'sha256': sha} or not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Artifact metadata mismatch')
    # Signer checks package structure and size but NEVER runs upstream code or binaries.
    with tempfile.TemporaryDirectory() as tmp:
        VersionStore(Path(tmp)).install(archive, ver, sha)
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey) or key.public_key().public_bytes_raw().hex() != expected_public:
        raise ValueError('Signing key does not match provisioned public key')
    payload = {'contract': CONTRACT, 'platform': 'windows-x64', 'version': ver, 'sha256': sha,
        'archive_url': f'https://github.com/{repository(repo)}/releases/download/proxy-v{ver}/{archive.name}',
        'upstream_commit': commit}
    envelope = {'payload': payload, 'signature': key.sign(canonical_manifest(payload)).hex()}
    verify_manifest(envelope, expected_public)
    (out / 'latest.json').write_text(json.dumps(envelope, indent=2), encoding='utf-8')
    (out / 'update-feed.json').write_text(json.dumps(config(repo, expected_public), indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    d = sub.add_parser('discover'); d.add_argument('--repo', required=True)
    b = sub.add_parser('build'); b.add_argument('--source', type=Path, required=True)
    s = sub.add_parser('sign'); s.add_argument('--repo', required=True)
    for p in (b, s):
        p.add_argument('--version', required=True); p.add_argument('--commit', required=True); p.add_argument('--out', type=Path, required=True)
    k = sub.add_parser('setup'); k.add_argument('--repo', required=True); k.add_argument('--key', type=Path, required=True); k.add_argument('--config', type=Path, required=True)
    a = parser.parse_args()
    if a.action == 'discover':
        values = discover(a.repo)
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as f:
            for key, val in values.items(): f.write(f'{key}={val}\n')
        print(values)
    elif a.action == 'build': build(a.source, a.version, a.commit, a.out)
    elif a.action == 'sign': sign(a.repo, a.version, a.commit, a.out, os.environ['TGWS_SIGNING_KEY'], os.environ['TGWS_PUBLIC_KEY'])
    else: create_key(a.repo, a.key, a.config)

if __name__ == '__main__': main()
