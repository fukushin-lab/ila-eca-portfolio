"""Related current design operations; existing contracts are retained."""

from __future__ import annotations
import copy


import json


from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest


SCHEMA = 'ila.eca.common-change-design.v1'


MISSING = object()


def _escape(value):
    return str(value).replace('~', '~0').replace('/', '~1')


def resolve(document, pointer):
    if pointer == '':
        return document
    if not isinstance(pointer, str) or not pointer.startswith('/'):
        raise ValueError('DESIGN_POINTER_INVALID')
    current = document
    for part in pointer[1:].split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        if isinstance(current, list):
            if not part.isdigit() or str(int(part)) != part:
                raise ValueError('DESIGN_POINTER_INVALID')
            current = current[int(part)]
        else:
            current = current[part]
    return current


def differences(before, after, path=''):
    """Preserve absent, explicit null, strings, rights and connections separately."""
    if isinstance(before, dict) and isinstance(after, dict):
        rows = []
        for key in sorted(set(before) | set(after)):
            rows += differences(
                before.get(key, MISSING), after.get(key, MISSING), path + '/' + _escape(key)
            )
        return rows
    if (
        before is not MISSING
        and after is not MISSING
        and canonical_json(before) == canonical_json(after)
    ):
        return []
    return [
        {
            'path': path,
            'before_present': before is not MISSING,
            'after_present': after is not MISSING,
            **({'before': copy.deepcopy(before)} if before is not MISSING else {}),
            **({'after': copy.deepcopy(after)} if after is not MISSING else {}),
        }
    ]


def adapt_design(change_id, purpose, baseline, proposed, *, details=None, revision=1):
    """Adapt existing specs without changing the execution/verification schema.

    Details are authored input, never generated configuration. Unknown fields are
    retained in full, so an adapter cannot silently cut off unprocessed material.
    """
    if type(details) not in (dict, type(None)) or type(revision) is not int or revision < 1:
        raise ValueError('DESIGN_DETAILS_INVALID')
    details = copy.deepcopy(details or {})
    mappings = details.get('mappings', [])
    if not isinstance(mappings, list):
        raise ValueError('DESIGN_MAPPINGS_INVALID')
    for item in mappings:
        if not isinstance(item, dict) or not {'source_paths', 'target_paths'} <= item.keys():
            raise ValueError('DESIGN_MAPPING_INVALID')
        if not item['source_paths'] and not item['target_paths']:
            raise ValueError('DESIGN_MAPPING_EMPTY')
        for key, document in [('source_paths', baseline['spec']), ('target_paths', proposed)]:
            if not isinstance(item[key], list):
                raise ValueError('DESIGN_MAPPING_PATHS_INVALID')
            for pointer in item[key]:
                try:
                    resolve(document, pointer)
                except (KeyError, IndexError, TypeError, ValueError) as exc:
                    raise ValueError('DESIGN_MAPPING_SOURCE_NOT_FOUND') from exc
    data = {
        'schema': SCHEMA,
        'design_id': change_id,
        'revision': revision,
        'change_request_id': change_id,
        'scope': proposed.get('scope'),
        'purpose': purpose,
        'baseline': copy.deepcopy(baseline),
        'target': copy.deepcopy(proposed),
        'baseline_spec_sha256': data_digest(baseline['spec']),
        'target_spec_sha256': data_digest(proposed),
        'differences': differences(baseline['spec'], proposed),
        'details': details,
        'review_state': 'AWAITING_REVIEW',
        'evidence_assessment': details.get('evidence_assessment', 'NOT_ASSESSED'),
        'execution_state': 'NOT_REPORTED',
        'baseline_updated': False,
    }
    # Fails on NaN/non-JSON objects rather than silently dropping or normalizing input.
    canonical_json(data)
    return data


def markdown_sections(data):
    """Render supplied data verbatim in JSON blocks, including nested unknowns.

    Variable fences ensure source text containing Markdown fences cannot hide
    unknowns or manufacture a second section. No product-specific configurations.
    """

    def block(value):
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        fence = '`' * max(
            3, max((len(x) for x in __import__('re').findall(r'`+', raw)), default=0) + 1
        )
        return fence + 'json\n' + raw + '\n' + fence

    parts = [
        ('設計ID・版', {'design_id': data['design_id'], 'revision': data['revision']}),
        ('既存環境（入力原形）', data['baseline']),
        ('目標構成（入力原形）', data['target']),
        ('差分（不在と明示的nullを区別）', data['differences']),
    ]
    details = data['details']
    for key, title in [
        ('mappings', '既存と目標の対応（分割・統合・新設・廃止）'),
        ('evidence', '根拠・適用条件・情報源'),
        ('unknowns', '未知事項'),
        ('impact', '影響範囲'),
        ('construction', '構築手順・実施状態'),
        ('migration', '移行手順・実施状態'),
        ('verification', '確認手順・確認状態'),
        ('rollback', '切戻し手順・復旧確認'),
    ]:
        parts.append((title, details[key] if key in details else {'state': 'UNKNOWN_NOT_PROVIDED'}))
    parts.append(('入力された設計詳細の全項目', details))
    parts.append(
        (
            '状態（文書生成時）',
            {
                k: data[k]
                for k in (
                    'review_state',
                    'evidence_assessment',
                    'execution_state',
                    'baseline_updated',
                )
            },
        )
    )
    return '\n\n'.join('## ' + title + '\n' + block(value) for title, value in parts)


def reconcile(before, intended, observed, *, covered_paths):
    """Compare observations only within explicitly collected JSON-pointer scopes.

    An omitted value means absent only under a covered scope. Else it is UNOBSERVED.
    This is a comparison, never authorization or a generic verification adapter.
    """
    if not isinstance(covered_paths, list) or any(
        not isinstance(p, str) or (p and not p.startswith('/')) for p in covered_paths
    ):
        raise ValueError('OBSERVATION_COVERAGE_INVALID')
    paths = {r['path'] for r in differences(before, intended)} | {
        r['path'] for r in differences(intended, observed)
    }

    def get(doc, pointer):
        try:
            return resolve(doc, pointer)
        except (KeyError, IndexError, TypeError):
            return MISSING

    def same(a, b):
        return a is b if a is MISSING or b is MISSING else canonical_json(a) == canonical_json(b)

    result = []
    for path in sorted(paths):
        old, want, actual = (get(doc, path) for doc in (before, intended, observed))
        covered = any(p == '' or path == p or path.startswith(p + '/') for p in covered_paths)
        state = (
            'UNOBSERVED'
            if not covered
            else (
                'INTENDED_CHANGE'
                if not same(old, want) and same(actual, want)
                else (
                    'NOT_IMPLEMENTED'
                    if not same(old, want) and same(actual, old)
                    else 'MATCH' if same(actual, want) else 'ADDITIONAL_CHANGE'
                )
            )
        )
        result.append(
            {
                'path': path,
                'classification': state,
                **{
                    name: {
                        'present': value is not MISSING,
                        **({'value': copy.deepcopy(value)} if value is not MISSING else {}),
                    }
                    for name, value in [('before', old), ('intended', want), ('observed', actual)]
                },
            }
        )
    return result


from contextlib import closing


from datetime import datetime, timezone


from hashlib import sha256


from pathlib import Path


import sqlite3
import uuid


from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import (
    render_template,
    register_document,
    validate_record,
)


from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect


from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.changes import (
    SCOPE,
    init_lifecycle,
    current_baseline,
    get_change,
    submit_design,
    work_progress,
    proposal_kind,
    proposal_document_baseline,
)


ROOT = Path(__file__).resolve().parent.parent


TEMPLATE = ROOT / 'templates/design_document_v2.md.tpl'


TEMPLATE_VERSION = 'design-document-v2'


def digest(data):
    return sha256(data).hexdigest()


def render_change_document(
    change_id, purpose, baseline, proposed, template_path=TEMPLATE, *, details=None
):
    data = adapt_design(change_id, purpose, baseline, proposed, details=details)
    return render_template(
        Path(template_path).read_bytes(),
        {
            'change_id': change_id,
            'baseline_version': baseline['version'],
            'baseline_hash': data['baseline_spec_sha256'],
            'spec_hash': data['target_spec_sha256'],
            'common_sections': markdown_sections(data),
        },
        template_version=TEMPLATE_VERSION,
        provenance={
            'baseline_version': baseline['version'],
            'baseline_sha256': data['baseline_spec_sha256'],
            'proposed_sha256': data['target_spec_sha256'],
            'structured_data_sha256': data_digest(data),
        },
    )


def init_artifact_registry(db_path):
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con, con:
        con.execute(
            '''CREATE TABLE IF NOT EXISTS lifecycle_design_artifact_v2 (
            artifact_id TEXT PRIMARY KEY, change_id TEXT NOT NULL,
            revision INTEGER NOT NULL, template_version TEXT NOT NULL,
            template_sha256 TEXT NOT NULL, base_version INTEGER NOT NULL,
            base_spec_sha256 TEXT NOT NULL, proposed_spec_sha256 TEXT NOT NULL,
            document_sha256 TEXT NOT NULL, relative_path TEXT NOT NULL,
            design_origin TEXT NOT NULL, author TEXT NOT NULL, created_at_utc TEXT NOT NULL,
            UNIQUE(change_id, revision))'''
        )
        columns = {r[1] for r in con.execute('PRAGMA table_info(lifecycle_design_artifact_v2)')}
        for name in ('structured_path', 'structured_sha256', 'record_json'):
            if name not in columns:
                con.execute(f'ALTER TABLE lifecycle_design_artifact_v2 ADD COLUMN {name} TEXT')


def prepare_details(db_path, change_id, details):
    details = dict(details or {})
    plan = [
        {k: row[k] for k in ('step_id', 'description')} for row in work_progress(db_path, change_id)
    ]
    if plan:
        if 'work_plan' in details and details['work_plan'] != plan:
            raise ValueError('Document work plan differs from registered work')
        details['work_plan'] = plan
    if 'evidence_requests' in details:
        from ILA_ECA_REAL_DISCOVERY_LAB.core.evidence import collect_evidence

        change = get_change(db_path, change_id)
        evidence = collect_evidence(
            db_path, scope=change['scope'], selections=details['evidence_requests']
        )
        evidence.pop(
            'elapsed_ms'
        )  # Telemetry is not design content; identical evidence renders identically.
        details['collected_evidence'] = evidence
    if details.get('document_reviews'):
        from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import (
            verify_attached_document_from_connection,
        )

        change = get_change(db_path, change_id)
        with closing(connect(db_path)) as con:
            bindings = []
            for review in details['document_reviews']:
                bound = verify_attached_document_from_connection(
                    con, db_path, review['design_id'], review['revision'], change['scope']
                )
                bindings.append({**review, 'artifact_sha256': bound['record']['artifact_sha256']})
            if (
                'document_review_bindings' in details
                and details['document_review_bindings'] != bindings
            ):
                raise ValueError('DOCUMENT_REVIEW_BINDINGS_CHANGED')
            details['document_review_bindings'] = bindings
    if details.get('incident_investigation_binding'):
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.artifacts import verify_repair_binding

        change = get_change(db_path, change_id)
        with closing(connect(db_path)) as con:
            verify_repair_binding(con, db_path, details['incident_investigation_binding'], change)
    return details


def create_template_draft(
    db_path,
    change_id,
    *,
    author='DETERMINISTIC_RENDERER',
    details=None,
    design_origin='TEMPLATE',
    model_id=None,
):
    """Persist JSON, Markdown, registry and submission as one logical operation.

    Origin denotes the design decision author; deterministic formatting does not
    change AI/HUMAN authorship into TEMPLATE authorship. Revised submitted designs
    use a new change request, matching the existing lifecycle contract.
    """
    db_path = Path(db_path)
    init_artifact_registry(db_path)
    change = get_change(db_path, change_id)
    if change['status'] != 'DRAFT':
        raise ValueError('Design already submitted; create a new change for revision')
    typed = proposal_kind(change) != 'DOCKER_LAB'
    if change['scope'] != ('lab' if typed else SCOPE):
        raise ValueError('Cross-scope design denied')
    baseline = proposal_document_baseline(db_path, change)
    if baseline['version'] != change['base_version']:
        raise ValueError('Effective baseline changed; rebase proposal before generating')
    details = prepare_details(db_path, change_id, details)
    structured = adapt_design(
        change_id, change['purpose'], baseline, change['intended_spec'], details=details
    )
    content, metadata = render_change_document(
        change_id, change['purpose'], baseline, change['intended_spec'], details=details
    )
    structured_bytes = canonical_json(structured).encode('utf-8')
    folder = db_path.resolve().parent / 'design_drafts_lab'
    folder.mkdir(parents=True, exist_ok=True)
    artifact_id = str(uuid.uuid4())
    stem = f'{change_id}_{artifact_id}_DRAFT'
    target, json_path = folder / (stem + '.md'), folder / (stem + '.json')
    created = []
    try:
        for path, data in [(target, content), (json_path, structured_bytes)]:
            with path.open('xb') as stream:
                created.append(path)
                stream.write(data)
        with closing(connect(db_path)) as con, con:
            con.execute('BEGIN IMMEDIATE')
            con.row_factory = sqlite3.Row
            current = con.execute(
                'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,)
            ).fetchone()
            head = (
                con.execute(
                    'SELECT version FROM lifecycle_current_v1 WHERE scope=?', (SCOPE,)
                ).fetchone()
                if not typed
                else None
            )
            if (
                current['status'] != 'DRAFT'
                or (not typed and head['version'] != baseline['version'])
                or current['intended_spec_json'] != change['intended_spec_json']
                or current['proposal_kind'] != change['proposal_kind']
                or current['proposal_context_json'] != change['proposal_context_json']
            ):
                raise ValueError('Design input changed during generation')
            submit_design(
                db_path,
                change_id=change_id,
                design_text=content.decode('utf-8'),
                design_origin=design_origin,
                author=author,
                model_id=model_id,
                _connection=con,
            )
            record = register_document(
                con,
                domain_id='lab' if typed else 'CLOSED_LAB',
                design_id=change_id,
                document_kind='CHANGE_DESIGN',
                content=content,
                structured_data=structured,
                render_metadata=metadata,
                relative_path='design_drafts_lab/' + target.name,
                baseline_ref={
                    'kind': 'OBSERVED_SNAPSHOT' if typed else 'LAB_BASELINE',
                    'version': baseline['version'],
                    'sha256': metadata['baseline_sha256'],
                    'origin': baseline['origin'],
                },
                change_request_ref=change_id,
                evidence_assessment=structured['evidence_assessment'],
            )
            con.execute(
                '''INSERT INTO lifecycle_design_artifact_v2
                (artifact_id,change_id,revision,template_version,template_sha256,base_version,
                 base_spec_sha256,proposed_spec_sha256,document_sha256,relative_path,
                 design_origin,author,created_at_utc,structured_path,structured_sha256,record_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    artifact_id,
                    change_id,
                    record['revision'],
                    metadata['template_version'],
                    metadata['template_sha256'],
                    baseline['version'],
                    metadata['baseline_sha256'],
                    metadata['proposed_sha256'],
                    metadata['document_sha256'],
                    target.name,
                    design_origin,
                    author,
                    datetime.now(timezone.utc).isoformat(),
                    json_path.name,
                    digest(structured_bytes),
                    canonical_json(record),
                ),
            )
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return {
        **metadata,
        'artifact_id': artifact_id,
        'change_id': change_id,
        'revision': record['revision'],
        'path': str(target),
        'structured_path': str(json_path),
        'status': 'AWAITING_REVIEW',
        'document_record': record,
    }


def verify_artifact_content(db_path, row):
    """Pure file verification, safe inside an existing lifecycle transaction."""
    folder = (Path(db_path).resolve().parent / 'design_drafts_lab').resolve()

    def read(name):
        if not isinstance(name, str) or Path(name).name != name or '/' in name or '\\' in name:
            raise ValueError('Artifact path invalid')
        raw_path = folder / name
        path = raw_path.resolve(strict=True)
        if raw_path.is_symlink() or not path.is_relative_to(folder) or not path.is_file():
            raise ValueError('Artifact path invalid')
        return path.read_bytes()

    try:
        content = read(row['relative_path'])
        if digest(content) != row['document_sha256']:
            return False
        if 'structured_path' not in row.keys() or not row['structured_path']:
            return True
        raw = read(row['structured_path'])
        structured, record = json.loads(raw), json.loads(row['record_json'])
        validate_record(record, content=content, structured_data=structured)
        return (
            digest(raw) == row['structured_sha256']
            and structured['design_id'] == row['change_id']
            and structured['revision'] == row['revision'] == record['revision']
            and record['change_request_ref'] == row['change_id']
            and structured['baseline']['version'] == row['base_version']
            and data_digest(structured['target']) == row['proposed_spec_sha256']
            and data_digest(structured['baseline']['spec']) == row['base_spec_sha256']
        )
    except (OSError, ValueError, KeyError, TypeError):
        return False


