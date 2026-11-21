"""Offline bootstrap from the release's pinned wheels; never creates a case DB."""

from pathlib import Path
import hashlib
import json
import os
import sys
import zipfile


def verify_package(root):
    path = root.parent / 'RUNTIME_FILES.json'
    if not path.is_file():
        if root.name == 'APP':
            raise ValueError('CURRENT_RUNTIME_MANIFEST_REQUIRED_NO_FALLBACK')
        return None
    value = json.loads(path.read_text('utf8'))
    for name, digest in value['files'].items():
        target = (root.parent / name).resolve(strict=True)
        if (
            not target.is_relative_to(root.parent.resolve())
            or target.is_symlink()
            or hashlib.sha256(target.read_bytes()).hexdigest() != digest
        ):
            raise ValueError('CURRENT_RUNTIME_FILE_CHANGED_NO_OLD_VERSION_FALLBACK')
    actual = {
        str(p.relative_to(root.parent)).replace('\\', '/')
        for p in root.rglob('*.py')
        if '__pycache__' not in p.parts
    }
    if actual != {n for n in value['files'] if n.endswith('.py')}:
        raise ValueError('UNREGISTERED_RUNTIME_SOURCE_NO_FALLBACK')
    return value


def loaded_sources(root):
    result = {}
    for name, module in list(sys.modules.items()):
        if name.startswith('ILA_ECA_REAL_DISCOVERY_LAB') or name in {
            'ILA_ECA_REAL_DISCOVERY_LAB.core.storage',
            'ILA_ECA_REAL_DISCOVERY_LAB.knowledge.index',
            'workflow_v04',
            'incident_bridge_v06',
            'ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts',
        }:
            filename = getattr(module, '__file__', None)
            if not filename:
                continue
            path = Path(filename).resolve(strict=True)
            if not path.is_relative_to(root):
                raise ValueError('OLD_OR_EXTERNAL_RUNTIME_SOURCE_DENIED')
            result[name] = {
                'path': str(path),
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            }
    return result


def prepare_dependencies(root, runtime):
    """Expand only the release-pinned wheels, offline, into an explicit host path."""
    runtime.mkdir(exist_ok=True)
    manifest = json.loads((root / 'WEB_DEPENDENCIES.json').read_text('utf8'))
    for name, digest in manifest.items():
        wheel = root / 'wheelhouse' / name
        if hashlib.sha256(wheel.read_bytes()).hexdigest() != digest:
            raise ValueError('PINNED_DEPENDENCY_HASH_CHANGED')
        with zipfile.ZipFile(wheel) as z:
            for item in z.infolist():
                parts = Path(item.filename).parts
                if any(p in {'tests', 'test', '__pycache__'} for p in parts) or Path(
                    item.filename
                ).name.startswith('test_'):
                    continue
                target = (runtime / item.filename).resolve()
                if not target.is_relative_to(runtime.resolve()) or target.is_symlink():
                    raise PermissionError('DEPENDENCY_PATH_DENIED')
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                raw = z.read(item)
                if target.exists() and target.read_bytes() != raw:
                    raise ValueError('RUNTIME_DEPENDENCY_CHANGED')
                if not target.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw)


def main():
    root = Path(__file__).resolve().parent
    release = verify_package(root)
    config = Path(os.environ.get('ILA_ECA_WEB_CONFIG', str(root.parent / 'runtime.json'))).resolve(
        strict=True
    )
    cfg = json.loads(config.read_text('utf-8-sig'))
    db = Path(cfg['db'])
    if not db.is_absolute():
        db = config.parent / db
    cfg['db'] = str(db.resolve(strict=True))
    if not db.is_file():
        raise ValueError('EXISTING_DATABASE_REQUIRED_NO_INITIALIZATION')
    if sys.version_info[:2] != (3, 12):
        raise ValueError('PINNED_WINDOWS_PYTHON_312_REQUIRED')
    runtime = config.parent / 'runtime_deps'
    prepare_dependencies(root, runtime)
    sys.path.insert(0, str(runtime))
    sys.path.insert(0, str(root))
    from ILA_ECA_REAL_DISCOVERY_LAB.webapp.portal import Portal
    from ILA_ECA_REAL_DISCOVERY_LAB.run_web_ui import Server

    if cfg.get('host', '127.0.0.1') != '127.0.0.1':
        raise PermissionError('LOCALHOST_ONLY')
    p = Portal(cfg)
    server = Server(('127.0.0.1', cfg.get('port', 8766)), p)
    source_map = loaded_sources(root)
    url = 'http://127.0.0.1:' + str(server.server_port) + '/'
    print('ILA/ECA UI: ' + url, flush=True)
    print(
        'Mode: ' + p.mode + '. Ctrl+C stops this server. Existing commands are unchanged.',
        flush=True,
    )
    if release:
        report = {
            'release_id': release['release_id'],
            'process_id': os.getpid(),
            'runtime_manifest_sha256': hashlib.sha256(
                (root.parent / 'RUNTIME_FILES.json').read_bytes()
            ).hexdigest(),
            'application_root': str(root),
            'configuration_path': str(config),
            'database_path': str(cfg['db']),
            'code_fallback_to_older_release': False,
            'generation_enabled': bool(cfg.get('generation_enabled')),
            'collaboration_configured': bool(cfg.get('collaboration_config')),
            'loaded_application_modules': source_map,
            'url': url,
        }
        target = root.parent / 'ACTIVE_RUNTIME.json'
        temporary = target.with_suffix('.tmp')
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf8')
        temporary.replace(target)
        print(
            'Active release: ' + release['release_id'] + ' (verified local files only)', flush=True
        )
    if cfg.get('open_browser', True):
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        p.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        import re

        code = str(exc) if re.fullmatch('[A-Z][A-Z0-9_]*', str(exc)) else type(exc).__name__
        print('STOPPED: ' + code + '. No automatic retry or old-version fallback.', flush=True)
        raise SystemExit(1)
