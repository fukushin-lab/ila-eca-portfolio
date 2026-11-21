"""Immutable registered artifacts -> one review MR; approvals are observations.

Never merges, approves through GitLab, executes infrastructure or activates Baseline.
"""

from pathlib import Path
from hashlib import sha256
from urllib.parse import urlsplit
import copy
import json
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import Store, authorize, safe
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.adapters import ServiceError
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest, validate_record
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import document_paths
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import utc
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle import changes as lc


def packet(db, *, case_id, design_id, revision, scope='lab', change_id=None):
    if scope not in {'lab', lc.SCOPE}:
        raise PermissionError('DOCUMENT_EXPORT_SCOPE_DENIED')
    store = Store(db)
    store.case(case_id)
    with store.open() as c:
        row = c.execute(
            'SELECT * FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
            (scope, design_id, revision),
        ).fetchone()
    if not row:
        raise ValueError('REGISTERED_DOCUMENT_REQUIRED')
    record = json.loads(row['record_json'])
    md, default_struct = document_paths(db, row['relative_path'])
    folder = md.parent
    structured = folder / 'design.json' if (folder / 'design.json').is_file() else default_struct
    data = json.loads(structured.read_bytes())
    validate_record(record, content=md.read_bytes(), structured_data=data)
    prefix = 'ila-eca/' + data_digest(design_id)[:16] + '/r' + str(revision) + '/'
    files = {prefix + 'design.md': md.read_bytes(), prefix + 'design.json': structured.read_bytes()}
    if (folder / 'main.tf.json').is_file():
        raw = (folder / 'main.tf.json').read_bytes()
        if json.loads(raw) != data.get('proposal', {}).get('terraform'):
            raise ValueError('REGISTERED_IAC_CHANGED')
        files[prefix + 'main.tf.json'] = raw
    if change_id:
        ch = lc.get_change(db, change_id)
        lc.assert_change_integrity(db, change_id)
        with store.open() as c:
            art = c.execute(
                'SELECT structured_path,revision,record_json FROM lifecycle_design_artifact_v2 WHERE change_id=? ORDER BY revision DESC LIMIT 1',
                (change_id,),
            ).fetchone()
        if not art:
            raise ValueError('EXISTING_CHANGE_DOCUMENT_ATTACHMENT_REQUIRED')
        annex = json.loads((Path(db).parent / 'design_drafts_lab' / art[0]).read_bytes())
        native = (
            design_id == change_id
            and scope == ch['scope']
            and revision == art['revision']
            and art['record_json']
            and json.loads(art['record_json']) == record
        )
        if not native and {'design_id': design_id, 'revision': revision} not in annex[
            'details'
        ].get('document_reviews', []):
            raise ValueError('CHANGE_DOCUMENT_ATTACHMENT_MISMATCH')
        binding = {
            'change_id': change_id,
            'design_sha256': ch['design_sha256'],
            'base_version': ch['base_version'],
            'author': ch['design_author'],
        }
    else:
        binding = None
    manifest = {
        'case_id': case_id,
        'scope': scope,
        'design_id': design_id,
        'revision': revision,
        'artifact_sha256': record['artifact_sha256'],
        'change_binding': binding,
        'files': {p: sha256(b).hexdigest() for p, b in files.items()},
    }
    files[prefix + 'ila-eca-manifest.json'] = canonical_json(manifest).encode()
    safe(manifest)
    for raw in files.values():
        safe(raw.decode('utf8'))
    return manifest, files


def prepare(db, config, api, **selection):
    authorize(config, 'gitlab_prepare', selection['case_id'])
    manifest, files = packet(db, **selection)
    target = config['gitlab']
    if api.origin != target['base_url'].rstrip('/') or api.project != str(target['project_id']):
        raise PermissionError('GITLAB_TARGET_MISMATCH')
    envelope = {
        'destination': api.base,
        'target_branch': target['target_branch'],
        'manifest': manifest,
        'service_execution_kind': api.execution_kind,
        'files': {p: sha256(b).hexdigest() for p, b in files.items()},
    }
    return {'export_sha256': data_digest(envelope), 'envelope': envelope, 'files': files}


def _unchanged(db, config, api, saved):
    m = saved['prepared']['envelope']['manifest']
    prepared = prepare(
        db,
        config,
        api,
        case_id=m['case_id'],
        design_id=m['design_id'],
        revision=m['revision'],
        scope=m['scope'],
        change_id=(m['change_binding'] or {}).get('change_id'),
    )
    if prepared['envelope'] != saved['prepared']['envelope']:
        raise ValueError('SUBMITTED_ARTIFACT_CHANGED')
    return prepared['files']


def _remote_files(api, saved, files, sha):
    if api.branch(saved['branch']) != sha:
        raise ValueError('GITLAB_COMMIT_CHANGED')
    info = api.commit_info(sha)
    if (
        info.get('id') != sha
        or info.get('parent_ids') != [saved['base_commit_sha']]
        or not info.get('message', '').startswith(saved['marker'])
    ):
        raise ValueError('GITLAB_COMMIT_PROVENANCE_MISMATCH')
    for name, body in files.items():
        if api.file(name, sha) != body:
            raise ValueError('GITLAB_ARTIFACT_HASH_MISMATCH')


def _mr_matches(api, saved, mr):
    if (
        str(mr.get('project_id')) != api.project
        or mr.get('source_branch') != saved['branch']
        or mr.get('target_branch') != saved['prepared']['envelope']['target_branch']
        or mr.get('description') != saved['marker']
        or mr.get('sha') != saved['commit_sha']
    ):
        raise ValueError('GITLAB_MR_BINDING_MISMATCH')
    if (
        urlsplit(mr.get('web_url', '')).scheme != 'https'
        or urlsplit(mr['web_url']).netloc != urlsplit(api.origin).netloc
    ):
        raise ValueError('GITLAB_MR_LINK_ORIGIN_MISMATCH')


def submit(db, config, api, *, selection=None, submission_id=None, reconcile=False):
    store = Store(db)
    if submission_id:
        saved = store.submission(submission_id)
        case = saved['case_id']
        authorize(config, 'gitlab_submit', case, payload_sha256=saved['prepared']['export_sha256'])
        files = _unchanged(db, config, api, saved)
    else:
        p = prepare(db, config, api, **selection)
        case = selection['case_id']
        authorize(config, 'gitlab_submit', case, payload_sha256=p['export_sha256'])
        files = p['files']
        sid = data_digest({'export': p['export_sha256']})
        saved = {
            'submission_id': sid,
            'case_id': case,
            'prepared': {k: v for k, v in p.items() if k != 'files'},
            'branch': 'ila-eca/' + sid[:32],
            'marker': 'ILA-ECA-REVIEW:' + sid,
            'commit_sha': None,
            'mr_iid': None,
            'review': None,
            'approval_policy_at_submission': None,
        }
        with store.open() as c, c:
            c.execute(
                "INSERT OR IGNORE INTO collaboration_submission_v1 VALUES(?,?,'RESERVED',?)",
                (sid, case, canonical_json(saved)),
            )
        saved = store.submission(sid)
    sid = saved['submission_id']
    state = saved['state']
    if state in {'COMMIT_REJECTED', 'MR_REJECTED'}:
        if not reconcile:
            raise ValueError('WRITE_REJECTED_EXPLICIT_RECONCILE_REQUIRED')
        # Only a definite authentication/permission rejection permits an explicit retry.
        # First check for visible effects; uncertain transport failures never take this path.
        if state == 'COMMIT_REJECTED':
            try:
                api.branch(saved['branch'])
            except ServiceError as e:
                if e.status != 404:
                    raise
                next_state = 'RESERVED'
            else:
                next_state = 'COMMIT_PENDING'
        else:
            found = api.mrs(saved['branch'])
            if len(found) > 1:
                raise ValueError('GITLAB_MR_RECONCILIATION_AMBIGUOUS')
            next_state = 'MR_PENDING' if found else 'COMMITTED'
        store.update(sid, state, next_state, saved)
        saved['state'] = state = next_state
    if state in {'COMMIT_PENDING', 'MR_PENDING'} and not reconcile:
        raise ValueError('WRITE_RESULT_UNKNOWN_RECONCILE_REQUIRED')
    if state == 'RESERVED':
        # MCP capabilities are a read-only preflight. A missing MR tool must not
        # leave a committed branch or an unattempted write marked result-unknown.
        preflight = getattr(api, 'preflight_submission', None)
        if preflight is not None:
            preflight()
        start = api.branch(config['gitlab']['target_branch'])
        saved['base_commit_sha'] = start
        policy = None
        if not config['gitlab'].get('review_only', False):
            try:
                policy = api.approval_policy()
            except ServiceError as e:
                policy = {'unavailable': e.code}
        saved['approval_policy_at_submission'] = policy
        # Reservation becomes pending before the single write; a crash cannot silently redispatch.
        store.update(sid, 'RESERVED', 'COMMIT_PENDING', saved)
        saved['state'] = 'COMMIT_PENDING'
        try:
            sha = api.commit(saved['branch'], start, files, saved['marker'])
            saved['commit_sha'] = sha
            _remote_files(api, saved, files, sha)
            store.update(sid, 'COMMIT_PENDING', 'COMMITTED', saved)
            saved['state'] = 'COMMITTED'
        except BaseException as exc:
            # Keep pending even on a response parse failure or interruption. No write retry.
            saved['last_write_error'] = {
                'phase': 'COMMIT',
                'reason': getattr(exc, 'code', type(exc).__name__),
            }
            store.update(
                sid,
                'COMMIT_PENDING',
                (
                    'COMMIT_REJECTED'
                    if isinstance(exc, ServiceError) and exc.status in {401, 403}
                    else 'COMMIT_PENDING'
                ),
                saved,
            )
            raise
    elif state == 'COMMIT_PENDING':
        sha = api.branch(saved['branch'])
        saved['commit_sha'] = sha
        _remote_files(api, saved, files, sha)
        store.update(sid, 'COMMIT_PENDING', 'COMMITTED', saved)
        saved['state'] = 'COMMITTED'
    if saved['state'] in {'COMMITTED', 'MR_PENDING'}:
        _remote_files(api, saved, files, saved['commit_sha'])
        matches = api.mrs(saved['branch'])
        if len(matches) > 1:
            raise ValueError('GITLAB_MR_RECONCILIATION_AMBIGUOUS')
        if matches:
            mr = matches[0]
        elif saved['state'] == 'MR_PENDING':
            raise ValueError('MR_RESULT_STILL_UNKNOWN_NO_RESEND')
        else:
            store.update(sid, 'COMMITTED', 'MR_PENDING', saved)
            saved['state'] = 'MR_PENDING'
            try:
                mr = api.create_mr(
                    saved['branch'], config['gitlab']['target_branch'], saved['marker']
                )
            except BaseException as exc:
                saved['last_write_error'] = {
                    'phase': 'MR',
                    'reason': getattr(exc, 'code', type(exc).__name__),
                }
                store.update(
                    sid,
                    'MR_PENDING',
                    (
                        'MR_REJECTED'
                        if isinstance(exc, ServiceError) and exc.status in {401, 403}
                        else 'MR_PENDING'
                    ),
                    saved,
                )
                raise
        _mr_matches(api, saved, mr)
        saved.update(mr_iid=mr['iid'], web_url=mr['web_url'])
        store.update(sid, saved['state'], 'SUBMITTED', saved)
        saved['state'] = 'SUBMITTED'
    if saved['state'] == 'SUBMITTED':
        store.link(
            case,
            'GITLAB_MR',
            sid,
            {
                'submission_id': sid,
                'mr_url': saved['web_url'],
                'design_id': saved['prepared']['envelope']['manifest']['design_id'],
                'revision': saved['prepared']['envelope']['manifest']['revision'],
                'commit_sha': saved['commit_sha'],
            },
        )
    return saved


def _content_check(api, saved, db, files, observed):
    """Review evidence is bound to content, independently of GitLab's approval tier."""
    mr = api.mr(saved['mr_iid'])
    _mr_matches(api, saved, mr)
    observed['mr'] = {
        k: mr.get(k)
        for k in (
            'iid',
            'project_id',
            'sha',
            'state',
            'updated_at',
            'detailed_merge_status',
            'web_url',
        )
    }
    if mr.get('state') != 'opened':
        return False, ['MR_NOT_OPEN_REVIEW_IS_NOT_MERGE'], mr
    if mr.get('detailed_merge_status') in {'checking', 'approvals_syncing'}:
        return False, ['APPROVALS_STILL_SYNCING'], mr
    _remote_files(api, saved, files, saved['commit_sha'])
    m = saved['prepared']['envelope']['manifest']
    with Store(db).open() as c:
        latest = c.execute(
            'SELECT MAX(revision) FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=?',
            (m['scope'], m['design_id']),
        ).fetchone()[0]
    if latest != m['revision']:
        return False, ['DESIGN_REVISED_OLD_APPROVAL_NOT_REUSED'], mr
    if m['change_binding']:
        lc.assert_change_integrity(db, m['change_binding']['change_id'])
        change = lc.get_change(db, m['change_binding']['change_id'])
        expected = m['change_binding']
        if (
            change['design_sha256'] != expected['design_sha256']
            or change['base_version'] != expected['base_version']
            or change['design_author'] != expected['author']
        ):
            raise ValueError('LIFECYCLE_REVIEW_BINDING_CHANGED')
    return True, [], mr


def _review_only_check(api, saved, db, files, observed):
    ok, reasons, mr = _content_check(api, saved, db, files, observed)
    if not ok:
        return ok, reasons, []
    after = api.mr(saved['mr_iid'])
    _mr_matches(api, saved, after)
    if after.get('state') != 'opened' or after.get('updated_at') != mr.get('updated_at'):
        return False, ['MR_CHANGED_DURING_APPROVAL_CHECK'], []
    # The optional Approve button, CI, comments and merge state confer no authority.
    return True, [], []


def _approval_check(api, saved, config, db, files, observed):
    ok, reasons, mr = _content_check(api, saved, db, files, observed)
    if not ok:
        return False, reasons, []
    m = saved['prepared']['envelope']['manifest']
    policy = api.approval_policy()
    observed['project_approval_policy'] = policy
    if policy != saved['approval_policy_at_submission']:
        return False, ['APPROVAL_POLICY_CHANGED'], []
    if (
        policy.get('reset_approvals_on_push') is not True
        or policy.get('merge_requests_author_approval') is not False
        or policy.get('merge_requests_disable_committers_approval') is not True
    ):
        return False, ['APPROVAL_VERSION_OR_INDEPENDENCE_NOT_PROVEN'], []
    approval = api.approvals(saved['mr_iid'])
    rules = approval.get('rules')
    observed['approval_state'] = approval
    if not isinstance(rules, list) or not rules:
        return False, ['APPROVAL_RULES_UNAVAILABLE_OR_EMPTY'], []
    expected = set(config['gitlab'].get('required_rule_ids', []))
    if not expected or not expected.issubset({r.get('id') for r in rules}):
        return False, ['EXPECTED_APPROVAL_RULES_NOT_CONFIRMED'], []
    actors = []
    mapping = config['gitlab'].get('reviewer_identities', {})
    for rule in rules:
        count = rule.get('approvals_required')
        if type(count) is not int or count < 0 or rule.get('approved') is not True:
            return False, ['APPROVAL_RULE_UNSATISFIED'], []
        if count == 0 and rule.get('id') in expected:
            return False, ['REQUIRED_RULE_REQUIRES_NO_APPROVER'], []
        people = rule.get('approved_by', [])
        ids = {p['id'] for p in people if isinstance(p, dict) and type(p.get('id')) is int}
        if len(ids) < count:
            return False, ['APPROVER_COUNT_UNCONFIRMED'], []
        for uid in ids:
            who = mapping.get(str(uid))
            if not who or who == (m['change_binding'] or {}).get('author'):
                return False, ['REVIEWER_IDENTITY_OR_INDEPENDENCE_UNCONFIRMED'], []
            actors.append(who)
    after = api.mr(saved['mr_iid'])
    _mr_matches(api, saved, after)
    if after.get('state') != 'opened' or after.get('updated_at') != mr.get('updated_at'):
        return False, ['MR_CHANGED_DURING_APPROVAL_CHECK'], []
    return True, [], sorted(set(actors))


def refresh(db, config, api, *, submission_id):
    store = Store(db)
    saved = store.submission(submission_id)
    authorize(config, 'gitlab_read', saved['case_id'])
    if saved['state'] != 'SUBMITTED':
        raise ValueError('SUBMISSION_NOT_COMPLETE')
    actors = []
    observed = {}
    review_only = config['gitlab'].get('review_only', False)
    try:
        files = _unchanged(db, config, api, saved)
        ok, reasons, actors = (
            _review_only_check(api, saved, db, files, observed)
            if review_only
            else _approval_check(api, saved, config, db, files, observed)
        )
    except Exception as e:
        import re

        ok = False
        reasons = [
            (
                e.code
                if isinstance(e, ServiceError)
                else (str(e) if re.fullmatch('[A-Z][A-Z0-9_]*', str(e)) else type(e).__name__)
            )
        ]
    m = saved['prepared']['envelope']['manifest']
    binding = m['change_binding']
    review = {
        'observed_at': utc(),
        'gitlab_approval_verified': ok and not review_only,
        'reasons': reasons,
        'reviewers': actors,
        'design_id': m['design_id'],
        'revision': m['revision'],
        'artifact_sha256': m['artifact_sha256'],
        'commit_sha': saved['commit_sha'],
        'lifecycle_conditions_satisfied': False,
        'approval_granted': False,
        'baseline_updated': False,
        'fresh_refresh_required_before_use': True,
    }
    review['provider_evidence'] = observed
    review['service_execution_kind'] = api.execution_kind
    if review_only:
        review.update(
            review_only=True,
            review_content_verified=ok,
            gitlab_approval_required=False,
            formal_approval_status='REQUIRES_GITLAB_FORMAL_STATUS',
            formal_approval_granted=False,
            approval_location='ILA_ECA',
            existing_ila_eca_approval_scope='GITLAB_HUMAN_DESIGN_APPROVAL',
            review_target={
                'design_id': m['design_id'],
                'revision': m['revision'],
                'artifact_sha256': m['artifact_sha256'],
                'commit_sha': saved['commit_sha'],
                'change_binding': binding,
            },
        )
    if binding and ok and not review_only:
        try:
            for actor in actors:
                lc.check_review_binding(
                    db,
                    change_id=binding['change_id'],
                    reviewer=actor,
                    design_sha256=binding['design_sha256'],
                )
            ch = lc.get_change(db, binding['change_id'])
            if ch['status'] != 'AWAITING_REVIEW' or ch['base_version'] != binding['base_version']:
                raise ValueError('LIFECYCLE_REVIEW_BINDING_CHANGED')
            review['lifecycle_conditions_satisfied'] = True
        except (ValueError, PermissionError) as e:
            review['reasons'].append(str(e))
    elif not binding:
        review['reasons'].append('LIFECYCLE_CHANGE_ATTACHMENT_NOT_PROVIDED')
    # Existing lifecycle review evidence, not the LAB simulation approval gate.
    if binding:
        with store.open() as c, c:
            lc._event(c, binding['change_id'], 'EXTERNAL_REVIEW_OBSERVED', config['actor'], review)
        if not ok:
            from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.approval import invalidate_submission

            invalidate_submission(
                db, submission_id, reasons[0] if reasons else 'REVIEW_CONTENT_NOT_VERIFIED'
            )
    store.evidence(saved['case_id'], 'gitlab_review_observation_v1', review)
    saved['review'] = review
    store.update(submission_id, 'SUBMITTED', 'SUBMITTED', saved)
    return review
