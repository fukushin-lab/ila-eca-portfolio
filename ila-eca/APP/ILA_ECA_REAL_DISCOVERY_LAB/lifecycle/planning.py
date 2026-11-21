"""ILA/ECA v5: bounded LAB-only agent execution + evidence capture.

Existing lifecycle is authoritative. Local LLM suggests an ORDER, never a command,
change or approval. The only write is to an explicitly isolated lab workspace.
Snapshots/command logs are persisted before importing an UNAUTHENTICATED V4 record.
No enterprise approvals, no external infrastructure writes, no HF2 modifications.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from tempfile import gettempdir

from zipfile import ZipFile, ZIP_STORED, BadZipFile
import json
import re
import subprocess
import sys
import uuid

from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.changes import (
    SCOPE,
    begin_implementation,
    report_completion,
    report_work_failure,
    get_change,
    current_baseline,
)
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.external_records import (
    SCHEMA as EXTERNAL_SCHEMA,
    import_record,
)

ROOT = Path(__file__).resolve().parents[1]
LAB_RUNS = ROOT / 'data' / 'ila_agent_v5_runs'
MARKER = '.ila_lab_agent_v5'
MARKER_BYTES = b'ILA_ISOLATED_AGENT_LAB_V5\n'
SAFE_SERVICE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,60}$')


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(obj) -> bytes:
    return (
        json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n'
    ).encode('utf-8')


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _write_once(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise PermissionError('Symlink evidence/output forbidden')
    with path.open('xb') as out:
        out.write(data)


def _root_allowed(root: Path) -> Path:
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir() or not root.name.startswith('ila_agent_v5_'):
        raise PermissionError('Only isolated ila_agent_v5_ LAB run folders allowed')
    # User project data runs or a direct OS temporary directory, never arbitrary paths.
    permitted = {LAB_RUNS.resolve(), Path(gettempdir()).resolve()}
    if root.parent.resolve() not in permitted or root.resolve() != root:
        raise PermissionError('LAB root must be directly below the isolated run directory')
    return root


def init_run(root: Path) -> Path:
    root = _root_allowed(root)
    marker = root / MARKER
    if marker.exists() or marker.is_symlink():
        raise FileExistsError('Run cannot be reused')
    if any(root.iterdir()):
        raise ValueError('New run directory must be empty')
    _write_once(marker, MARKER_BYTES)
    for name in ('workspace', 'evidence', 'inbox'):
        (root / name).mkdir()
    return root


def _valid_run(root: Path) -> Path:
    root = _root_allowed(root)
    marker = root / MARKER
    if marker.is_symlink() or not marker.is_file() or marker.read_bytes() != MARKER_BYTES:
        raise PermissionError('LAB marker is missing, modified, or symlinked')
    for sub in ('workspace', 'evidence', 'inbox'):
        p = root / sub
        if p.is_symlink() or not p.is_dir():
            raise PermissionError('Invalid LAB run directory')
    return root


def _snapshot(root: Path, name: str) -> dict:
    """Snapshot all declared workspace files, with byte-identical copies under evidence/.
    No user or outside file can be captured or modified.
    """
    root = _valid_run(root)
    ws, ev = root / 'workspace', root / 'evidence'
    if name not in ('before', 'after'):
        raise ValueError('Invalid snapshot name')
    snap_dir = ev / ('snapshot_' + name)
    snap_dir.mkdir(exist_ok=False)
    entries = []
    for p in sorted(ws.iterdir()):
        if (
            p.is_symlink()
            or not p.is_file()
            or not SAFE_SERVICE.fullmatch(p.stem)
            or p.suffix != '.json'
        ):
            raise ValueError('Unsupported workspace entry')
        if p.stat().st_size > 64 * 1024:
            raise ValueError('Snapshot too large')
        b = p.read_bytes()
        _write_once(snap_dir / p.name, b)
        entries.append({'name': p.name, 'sha256': _sha(b), 'size': len(b)})
    manifest = {
        'schema': 'ila.agent-snapshot.v1',
        'stage': name,
        'captured_at_utc': _utc(),
        'files': entries,
    }
    content = _json(manifest)
    _write_once(snap_dir / 'snapshot_manifest.json', content)
    return {
        'manifest': f'evidence/snapshot_{name}/snapshot_manifest.json',
        'sha256': _sha(content),
        'files': entries,
    }


def deterministic_order(spec: dict) -> list[str]:
    deps = {s['id']: set(s['depends_on']) for s in spec['services']}
    if any(not SAFE_SERVICE.fullmatch(s) for s in deps):
        raise ValueError('Unsupported service ID for LAB executor')
    order = []
    while deps:
        ready = sorted(s for s, d in deps.items() if not d)
        if not ready:
            raise ValueError('Cyclic dependencies cannot be executed')
        for s in ready:
            order.append(s)
            del deps[s]
        for d in deps.values():
            d.difference_update(ready)
    return order


def validate_plan(spec: dict, proposed: dict) -> list[str]:
    if not isinstance(proposed, dict) or set(proposed) != {'order', 'note'}:
        raise ValueError('AI plan must contain ONLY order and note')
    note = proposed['note']
    if not isinstance(note, str):
        raise ValueError('Invalid planner note')
    order = proposed['order']
    services = {s['id']: s for s in spec['services']}
    if (
        not isinstance(order, list)
        or len(order) != len(services)
        or any(not isinstance(n, str) for n in order)
        or len(set(order)) != len(order)
        or set(order) != set(services)
    ):
        raise ValueError('AI plan incomplete, duplicated or contains unauthorized targets')
    seen = set()
    for sid in order:
        if not set(services[sid]['depends_on']).issubset(seen):
            raise ValueError('AI plan violates declared dependencies')
        seen.add(sid)
    return order


def _cmd_validate(path: Path) -> tuple[int, bytes]:
    """Fixed, read-only Python JSON parser; no shell/user/model command allowed."""
    cp = subprocess.run(
        [sys.executable, '-m', 'json.tool', str(path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=12,
        shell=False,
        check=False,
    )
    stdout, stderr = cp.stdout[:8192], cp.stderr[:8192]
    data = (
        (
            f'COMMAND: python -m json.tool <isolated-file>\nEXIT_CODE: {cp.returncode}\n'
            'STDOUT:\n'
        ).encode()
        + stdout
        + b'\nSTDERR:\n'
        + stderr
    )
    return cp.returncode, data


def _bundle(root: Path, receipt: dict) -> Path:
    """Make a capped, deterministic evidence bundle in inbox without touching source."""
    root = _valid_run(root)
    path = root / 'inbox' / 'agent_work_evidence.zip'
    if path.exists():
        raise FileExistsError('Evidence bundle already exists')
    sources = sorted((root / 'evidence').rglob('*'))
    if any(p.is_symlink() for p in sources):
        raise PermissionError('Evidence symlink forbidden')
    with ZipFile(path, 'x', compression=ZIP_STORED) as z:
        for p in sources:
            if p.is_file():
                z.write(p, p.relative_to(root).as_posix())
        z.writestr('work_receipt.json', _json(receipt))
    if path.stat().st_size > 1024 * 1024:
        path.unlink()
        raise ValueError('V4 attachment size exceeded')
    return path


def _check_executable(ch: dict, root: Path, actor: str) -> None:
    _valid_run(root)
    if ch['scope'] != SCOPE or ch['status'] != 'APPROVED_LAB_ONLY':
        raise PermissionError('Explicit lab review required before any agent work')
    if actor in {ch['review_actor'], ch['design_author']}:
        raise PermissionError('Agent executor must not be design author or reviewer')
    if not isinstance(actor, str) or not actor or len(actor) > 100:
        raise ValueError('Invalid agent ID')


def execute_agent_lab(
    db_path: Path,
    change_id: str,
    root: Path,
    *,
    actor: str,
    plan: dict,
    planner: str,
    explicit_lab_only: bool = False,
) -> dict:
    """Execute a narrow real file change after explicit LAB review; capture evidence.

    Only materializes canonical approved service configs inside an empty lab sandbox.
    Never runs model-generated shell commands; cannot mutate Docker/AWS/host systems.
    Reports a failure via existing shared lifecycle on failure after implementation start.
    """
    if not explicit_lab_only:
        raise PermissionError('Real execution authorization is NOT implemented')
    root = _valid_run(root)
    ch = get_change(db_path, change_id)
    _check_executable(ch, root, actor)
    if current_baseline(db_path)['version'] != ch['base_version']:
        raise ValueError('Stale baseline; refuse execute')
    order = validate_plan(ch['intended_spec'], plan)
    ws, ev = root / 'workspace', root / 'evidence'
    if any(ws.iterdir()) or any(ev.iterdir()) or any((root / 'inbox').iterdir()):
        raise ValueError('Work folder already used')
    begin_implementation(db_path, change_id=change_id, executor=actor, execution_mode='AGENT')
    try:
        before = _snapshot(root, 'before')
        actions = []
        services = {s['id']: s for s in ch['intended_spec']['services']}
        revision = ch['intended_spec']['documents']['architecture_revision']
        # No arbitrary paths; only approved properties are written.
        for sid in order:
            path = ws / (sid + '.json')
            payload = {
                'id': sid,
                'depends_on': sorted(services[sid]['depends_on']),
                'architecture_revision': revision,
                'mode': 'LAB_FILE_ONLY',
            }
            _write_once(path, _json(payload))
            rc, log = _cmd_validate(path)
            log_name = f'command_{len(actions)+1:03d}_{sid}.txt'
            _write_once(ev / log_name, log)
            actions.append(
                {
                    'service': sid,
                    'config_sha256': _sha(path.read_bytes()),
                    'command_log': 'evidence/' + log_name,
                    'command_sha256': _sha(log),
                    'exit_code': rc,
                }
            )
            if rc:
                raise RuntimeError(f'Allowlisted validation failed for {sid}: exit={rc}')
        after = _snapshot(root, 'after')
        receipt = {
            'schema': 'ila.agent-execution.v5',
            'change_id': change_id,
            'actor': actor,
            'planner': planner,
            'plan': plan,
            'design_sha256': ch['design_sha256'],
            'base_version': ch['base_version'],
            'before': before,
            'after': after,
            'actions': actions,
            'outcome': 'REPORTED_COMPLETE_NOT_VERIFIED',
            'recorded_at_utc': _utc(),
            'authority': 'LAB_FILE_EXECUTION_NOT_ENTERPRISE_APPROVAL',
        }
        _write_once(ev / 'execution_receipt.json', _json(receipt))
        bundle = _bundle(root, receipt)
        m = {
            'schema': EXTERNAL_SCHEMA,
            'scope': SCOPE,
            'change_id': change_id,
            'kind': 'COMPLETION_REPORT',
            'source_system': 'ILA_AGENT_V5_LAB_ONLY',
            'external_id': f'{change_id}-AI-{uuid.uuid4().hex[:12]}',
            'actor_claim': actor,
            'role_claim': 'IMPLEMENTER',
            'issued_at_utc': _utc(),
            'base_version': ch['base_version'],
            'design_sha256': ch['design_sha256'],
            'claimed_result': 'COMPLETE',
            'details': {
                'receipt_sha256': _sha(_json(receipt)),
                'bundle_sha256': _sha(bundle.read_bytes()),
                'note': 'Untrusted until independent verification; LAB-only',
            },
            'attachment_filename': bundle.name,
        }
        _write_once(root / 'inbox' / 'completion_manifest.json', _json(m))
        imported = import_record(db_path, root / 'inbox', 'completion_manifest.json')
        report_completion(
            db_path,
            change_id=change_id,
            reporter=actor,
            summary='LAB-only agent wrote approved service files; independent verification PENDING',
            work_references=[str(bundle)],
            actual_design_sha256=ch['design_sha256'],
        )
        return {
            'status': 'REPORTED_COMPLETE_NOT_VERIFIED',
            'root': str(root),
            'change_id': change_id,
            'planner': planner,
            'before': before,
            'after': after,
            'actions': actions,
            'bundle': str(bundle),
            'bundle_sha256': _sha(bundle.read_bytes()),
            'v4_record_status': imported['status'],
            'baseline_version': current_baseline(db_path)['version'],
        }
    except Exception as e:
        # Preserve any captured evidence. Failed actions never count as success.
        failure = {
            'schema': 'ila.agent-execution-error.v5',
            'error': type(e).__name__,
            'detail': str(e)[:1000],
            'at_utc': _utc(),
        }
        if not (ev / 'execution_failure.json').exists():
            _write_once(ev / 'execution_failure.json', _json(failure))
        report_work_failure(
            db_path,
            change_id=change_id,
            reporter=actor,
            failure_summary=f'{type(e).__name__}: {str(e)[:200]}',
            work_references=[str(ev / 'execution_failure.json')],
        )
        raise


def verify_agent_lab(db_path: Path, change_id: str, root: Path, *, verifier: str) -> dict:
    """Independent rules-based file/snapshot verifier, NEVER lifecycle acceptance."""
    root = _valid_run(root)
    ch = get_change(db_path, change_id)
    if not verifier or verifier in {ch['implementation_actor'], ch['design_author']}:
        raise PermissionError('Independent verifier identity required')
    if ch['status'] != 'REPORTED_COMPLETE' or ch['implementation_mode'] != 'AGENT':
        raise ValueError('Completed AGENT work required')
    ev = root / 'evidence'
    reasons = []
    receipt_path = ev / 'execution_receipt.json'
    if receipt_path.is_symlink() or not receipt_path.is_file():
        return {'status': 'HOLD', 'reasons': ['missing_receipt'], 'baseline_updated': False}
    try:
        receipt = json.loads(receipt_path.read_bytes())
        if receipt['change_id'] != change_id or receipt['design_sha256'] != ch['design_sha256']:
            reasons.append('receipt_change_or_design_mismatch')
        order = validate_plan(ch['intended_spec'], receipt['plan'])
        if [a['service'] for a in receipt['actions']] != order:
            reasons.append('action_order_mismatch')
        service_map = {s['id']: s for s in ch['intended_spec']['services']}
        rev = ch['intended_spec']['documents']['architecture_revision']
        after = receipt['after']
        if receipt['before']['files'] != []:
            reasons.append('before_snapshot_not_empty')
        listed = after.get('files', [])
        if {f['name'] for f in listed} != {s + '.json' for s in order}:
            reasons.append('after_snapshot_manifest_file_set_mismatch')
        manifest_path = ev / 'snapshot_after' / 'snapshot_manifest.json'
        if (
            manifest_path.is_symlink()
            or not manifest_path.is_file()
            or _sha(manifest_path.read_bytes()) != after['sha256']
        ):
            reasons.append('snapshot_manifest_tampered')
        else:
            manifest_obj = json.loads(manifest_path.read_bytes())
            if manifest_obj.get('files') != after.get('files'):
                reasons.append('after_snapshot_manifest_content_mismatch')
        expected_names = {s + '.json' for s in order}
        ws = root / 'workspace'
        if {p.name for p in ws.iterdir()} != expected_names:
            reasons.append('workspace_file_set_mismatch')
        for a in receipt['actions']:
            sid = a['service']
            expected = _json(
                {
                    'id': sid,
                    'depends_on': sorted(service_map[sid]['depends_on']),
                    'architecture_revision': rev,
                    'mode': 'LAB_FILE_ONLY',
                }
            )
            for path in (ws / (sid + '.json'), ev / 'snapshot_after' / (sid + '.json')):
                if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
                    reasons.append('observed_or_snapshot_mismatch:' + sid)
            if a['config_sha256'] != _sha(expected):
                reasons.append('action_digest_mismatch:' + sid)
            logpath = ev / (
                'command_' + str(receipt['actions'].index(a) + 1).zfill(3) + '_' + sid + '.txt'
            )
            if (
                logpath.is_symlink()
                or not logpath.is_file()
                or _sha(logpath.read_bytes()) != a['command_sha256']
                or a['exit_code'] != 0
            ):
                reasons.append('command_log_or_exit_mismatch:' + sid)
        before_path = ev / 'snapshot_before' / 'snapshot_manifest.json'
        if (
            before_path.is_symlink()
            or not before_path.is_file()
            or _sha(before_path.read_bytes()) != receipt['before']['sha256']
        ):
            reasons.append('before_snapshot_tampered')
        else:
            before_manifest = json.loads(before_path.read_bytes())
            if before_manifest.get('files') != []:
                reasons.append('before_snapshot_manifest_nonempty')
        if current_baseline(db_path)['version'] != ch['base_version']:
            reasons.append('baseline_advanced')
        bundle = root / 'inbox' / 'agent_work_evidence.zip'
        if bundle.is_symlink() or not bundle.is_file():
            reasons.append('missing_evidence_bundle')
        else:
            # Compare the on-disk bundle against V4's independently retained byte copy.
            with closing(connect(db_path)) as con:
                row = con.execute(
                    '''SELECT content_sha256, content_bytes, actor_claim, design_sha256,
                          linkage_status FROM external_record_v4 WHERE change_id=?
                          AND source_system='ILA_AGENT_V5_LAB_ONLY' AND kind='COMPLETION_REPORT' ''',
                    (change_id,),
                ).fetchall()
            if (
                len(row) != 1
                or row[0][0] != _sha(bundle.read_bytes())
                or row[0][1] != bundle.read_bytes()
                or row[0][2] != ch['implementation_actor']
                or row[0][3] != ch['design_sha256']
                or row[0][4] != 'RECEIVED_UNAUTHENTICATED'
            ):
                reasons.append('v4_retained_evidence_not_matching_disk_bundle')
            with ZipFile(bundle) as z:
                if z.read('work_receipt.json') != _json(receipt):
                    reasons.append('evidence_bundle_receipt_mismatch')
                for f in sorted(ev.rglob('*')):
                    if f.is_file() and z.read(f.relative_to(root).as_posix()) != f.read_bytes():
                        reasons.append('evidence_bundle_file_mismatch:' + f.name)
    except (
        KeyError,
        IndexError,
        ValueError,
        TypeError,
        OSError,
        BadZipFile,
        json.JSONDecodeError,
    ) as e:
        reasons.append('malformed_or_tampered_evidence:' + type(e).__name__)
    return {
        'status': 'PASS_LAB_FILE_ONLY' if not reasons else 'HOLD',
        'reasons': sorted(set(reasons)),
        'verifier': verifier,
        'authority': 'INDEPENDENT_LOCAL_FILE_RULES_NOT_ENTERPRISE_VERIFICATION',
        'baseline_updated': False,
        'baseline_version': current_baseline(db_path)['version'],
    }
