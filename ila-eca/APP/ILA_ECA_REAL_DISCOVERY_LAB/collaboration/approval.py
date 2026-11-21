"""GitLab Free reviewer -> signed human approval -> existing DESIGN lifecycle.

No login/password prompt, approval impersonation, merge, execution or new ledger.
The operator policy defines authority; GitLab proves the user's action and identity.
"""

from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
import base64
import hashlib
import hmac
import json
import os
import re
import uuid
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle import changes as lc
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import Store, authorize
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.adapters import Q, origin
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.llm.cloud import parse


SOURCE = 'GITLAB_SIGNED_MR_APPROVAL'
DECISION_CONTRACT = 'individual-approval-evidence.v2'
OPS = {'formal_prepare', 'formal_reconcile', 'formal_status', 'formal_receive', 'formal_resume'}


def now():
    return datetime.now(timezone.utc)


class GitLabApprovalHost:
    execution_kind = 'LIVE'

    def __init__(self, policy_path):
        self.path = Path(policy_path) if policy_path else None

    def load_policy(self):
        if not self.path:
            raise PermissionError('GITLAB_APPROVAL_POLICY_REQUIRED')
        return parse(self.path.read_bytes())

    def signing_key(self):
        return os.environ.get('ILA_GITLAB_WEBHOOK_SIGNING_TOKEN', '')


class GitLabAccountTestHost(GitLabApprovalHost):
    def __init__(self, policy_path, authorization_path):
        super().__init__(policy_path)
        self.account_test_authorization_path = Path(authorization_path)


def policy(host):
    p = host.load_policy()
    if (
        type(p) is not dict
        or set(p)
        != {
            'schema',
            'policy_id',
            'expires_at',
            'approvers',
            'author_person_ids',
            'gitlab_person_ids',
        }
        or p['schema'] != 'ila.eca.gitlab-design-approval-policy.v1'
        or not p['policy_id']
        or _time(p['expires_at']) <= now()
    ):
        raise PermissionError('GITLAB_APPROVAL_POLICY_INVALID_OR_EXPIRED')
    if type(p['approvers']) is not list or not p['approvers']:
        raise PermissionError('GITLAB_APPROVER_NOT_CONFIGURED')
    seen = set()
    for g in p['approvers']:
        if (
            type(g) is not dict
            or set(g)
            != {'user_id', 'origin', 'project_id', 'case_ids', 'document_scopes', 'valid_until'}
            or type(g['user_id']) is not int
            or g['user_id'] <= 0
            or type(g['project_id']) is not str
            or not g['project_id']
            or not g['project_id'].isdigit()
        ):
            raise PermissionError('GITLAB_APPROVER_GRANT_INVALID')
        origin(g['origin'])
        _time(g['valid_until'])
        key = (g['origin'], g['project_id'], g['user_id'])
        if key in seen:
            raise PermissionError('GITLAB_APPROVER_GRANT_AMBIGUOUS')
        seen.add(key)
        for k in ('case_ids', 'document_scopes'):
            if (
                type(g[k]) is not list
                or not g[k]
                or any(type(s) is not str or not s or s == '*' for s in g[k])
            ):
                raise PermissionError('GITLAB_APPROVAL_EXPLICIT_SCOPE_REQUIRED')
    for k in ('author_person_ids', 'gitlab_person_ids'):
        if type(p[k]) is not dict or any(
            type(a) is not str or not a or type(b) is not str or not b for a, b in p[k].items()
        ):
            raise PermissionError('GITLAB_APPROVAL_PERSON_MAPPING_REQUIRED')
    return p, data_digest(p)


def grant(p, uid, t):
    gs = [
        g
        for g in p['approvers']
        if g['user_id'] == uid
        and g['origin'] == t['gitlab_origin']
        and g['project_id'] == t['project_id']
        and t['case_id'] in g['case_ids']
        and t['document_scope'] in g['document_scopes']
        and _time(g['valid_until']) > now()
    ]
    if len(gs) != 1:
        raise PermissionError('GITLAB_APPROVAL_ROLE_OR_SCOPE_DENIED')
    identity = lambda n: p['gitlab_person_ids'].get(t['gitlab_origin'] + '|' + str(n))
    author = p['author_person_ids'].get(t['design_author'])
    submitter = identity(t['gitlab_author_id'])
    reviewer = identity(uid)
    if not all((author, submitter, reviewer)):
        raise PermissionError('GITLAB_APPROVAL_INDEPENDENCE_MAPPING_REQUIRED')
    if uid == t['gitlab_author_id']:
        raise PermissionError('GITLAB_INDEPENDENT_APPROVER_REQUIRED')
    if t.get('account_test'):
        _account_identity_exception(p, uid, t, t['account_test'], author, submitter, reviewer)
    elif reviewer in {author, submitter}:
        raise PermissionError('GITLAB_INDEPENDENT_APPROVER_REQUIRED')
    return gs[0]


def member(api, uid):
    m = api.member(uid)
    if (
        type(m) is not dict
        or m.get('id') != uid
        or m.get('state') != 'active'
        or m.get('locked') is True
        or m.get('bot') is True
        or type(m.get('access_level')) is not int
        or m['access_level'] < 30
    ):
        raise PermissionError('GITLAB_ACTIVE_DEVELOPER_OR_HIGHER_REQUIRED')
    if m.get('expires_at') and str(m['expires_at'])[:10] <= now().date().isoformat():
        raise PermissionError('GITLAB_MEMBERSHIP_EXPIRED')
    return m


def reviewers(mr):
    ids = [u.get('id') for u in mr.get('reviewers', []) if type(u) is dict]
    if any(type(x) is not int for x in ids):
        raise ValueError('GITLAB_REVIEWER_IDS_INVALID')
    return ids


def approval(api, uid, iid):
    state = api.user_approvals(iid)
    rows = [a for a in state.get('approved_by', []) if a.get('user', {}).get('id') == uid]
    if (
        len(rows) != 1
        or rows[0]['user'].get('state') != 'active'
        or rows[0]['user'].get('locked') is True
        or rows[0]['user'].get('bot') is True
    ):
        raise PermissionError('GITLAB_CURRENT_USER_APPROVAL_NOT_PRESENT')
    _time(rows[0].get('approved_at'))
    return rows[0], state


def assignments(con, cid):
    return _events(con, cid, 'GITLAB_REVIEW_ASSIGNED')


def latest_assignment(con, cid):
    rows = assignments(con, cid)
    if not rows:
        raise ValueError('GITLAB_REVIEW_HANDOFF_REQUIRED')
    return rows[-1]


def event_invalidates(event, saved, reviewer_id):
    a = event['object_attributes']
    action = a.get('action')
    if action == 'unapproval':
        return a.get('system') is True or event.get('user', {}).get('id') == reviewer_id
    if action in {'unapproved', 'close', 'merge'}:
        return True
    if action != 'update':
        return False
    if a.get('last_commit', {}).get('id') != saved['commit_sha']:
        return True
    if a.get('oldrev') and a['oldrev'] != saved['commit_sha']:
        return True
    if (
        'target_branch' in a
        and a['target_branch'] != saved['prepared']['envelope']['target_branch']
    ):
        return True
    if 'source_branch' in a and a['source_branch'] != saved['branch']:
        return True
    if 'reviewer_ids' in a and reviewer_id not in a['reviewer_ids']:
        return True
    return False


def bound_submission(cfg, api, saved):
    target = cfg['gitlab']
    envelope = saved['prepared']['envelope']
    if (
        api.origin != origin(target['base_url'])
        or api.project != str(target['project_id'])
        or envelope['destination'] != api.base
        or envelope['service_execution_kind'] != api.execution_kind
    ):
        raise PermissionError('GITLAB_RECEIPT_DESTINATION_OR_PROVENANCE_MISMATCH')


def context(db, cfg, api, host, sid):
    if host.execution_kind not in {'LIVE', 'MOCK'} or api.execution_kind != host.execution_kind:
        raise PermissionError('GITLAB_APPROVAL_PROVENANCE_MISMATCH')
    try:
        _account_guard(db, cfg, api, host, sid)
        p, ph = policy(host)
        t = _target(db, cfg, api, sid)
        test = _account_guard(db, cfg, api, host, sid, t)
        if test:
            t['account_test'] = test
        return p, ph, t
    except Exception as exc:
        invalidate_submission(db, sid, _reason(exc))
        raise


def assign(db, cfg, api, host, case, payload, reconcile=False):
    expected = (
        {'submission_id', 'request_id'}
        if reconcile
        else {'submission_id', 'reviewer_id', 'request_id'}
    )
    if set(payload) != expected or not re.fullmatch('[A-Za-z0-9_-]{8,100}', payload['request_id']):
        raise ValueError('GITLAB_HANDOFF_REQUEST_INVALID')
    sid = payload['submission_id']
    pol, ph, t = context(db, cfg, api, host, sid)
    store = Store(db)
    if t['case_id'] != case:
        raise PermissionError('SUBMISSION_CASE_MISMATCH')
    with store.open() as c:
        rows = [
            d
            for _, d in _events(c, t['change_id'], 'GITLAB_REVIEW_ASSIGNMENT_PENDING')
            if d['request_id'] == payload['request_id']
        ]
    pending = rows[-1] if rows else None
    uid = pending['reviewer_id'] if reconcile and pending else payload.get('reviewer_id')
    if type(uid) is not int:
        raise ValueError('GITLAB_REVIEWER_ID_REQUIRED')
    grant(pol, uid, t)
    membership = member(api, uid)
    existing_reviewers = reviewers(api.mr(t['mr_iid']))
    if pending and (
        pending['target'] != t or pending['policy_sha256'] != ph or pending['reviewer_id'] != uid
    ):
        raise ValueError('GITLAB_HANDOFF_REQUEST_CONFLICT')
    with store.open() as c, c:
        c.execute('BEGIN IMMEDIATE')
        _local_unchanged(c, db, t)
        ready = [
            d for _, d in assignments(c, t['change_id']) if d['request_id'] == payload['request_id']
        ]
        if ready:
            if uid not in existing_reviewers:
                raise ValueError('GITLAB_ASSIGNED_REVIEWER_REMOVED')
            return {
                **ready[-1],
                'duplicate': True,
                'approval_granted': False,
                'requires_fresh_formal_status': True,
            }
        if not pending:
            if any(
                d['request_id'] == payload['request_id']
                for _, d in _events(c, t['change_id'], 'GITLAB_REVIEW_ASSIGNMENT_PENDING')
            ):
                raise ValueError('GITLAB_HANDOFF_RESULT_UNKNOWN_RECONCILE_REQUIRED')
            if reconcile:
                raise ValueError('GITLAB_PENDING_HANDOFF_REQUIRED')
            pending = {
                'request_id': payload['request_id'],
                'target': t,
                'policy_sha256': ph,
                'reviewer_id': uid,
                'assignment_id': uuid.uuid4().hex,
                'service_execution_kind': api.execution_kind,
                'preserved_reviewer_ids': existing_reviewers,
            }
            _invalidate(c, t['change_id'], 'NEW_REVIEW_HANDOFF')
            lc._event(c, t['change_id'], 'GITLAB_REVIEW_ASSIGNMENT_PENDING', cfg['actor'], pending)
        elif not reconcile:
            raise ValueError('GITLAB_HANDOFF_RESULT_UNKNOWN_RECONCILE_REQUIRED')
    if not reconcile:
        api.assign_reviewer(
            t['mr_iid'], uid, pending['preserved_reviewer_ids']
        )  # never approve/merge
    mr = api.mr(t['mr_iid'])
    if uid not in reviewers(mr):
        raise ValueError('GITLAB_HANDOFF_NOT_OBSERVED_NO_AUTOMATIC_RESEND')
    if context(db, cfg, api, host, sid) != (pol, ph, t):
        raise ValueError('GITLAB_HANDOFF_TARGET_OR_POLICY_CHANGED')
    ready = {
        **pending,
        'armed_at': now().isoformat(),
        'member': membership,
        'mr_url': mr['web_url'],
        'approval_granted': False,
        'execution_allowed': False,
        'baseline_updated': False,
    }
    with store.open() as c, c:
        c.execute('BEGIN IMMEDIATE')
        _local_unchanged(c, db, t)
        latest_pending = _events(c, t['change_id'], 'GITLAB_REVIEW_ASSIGNMENT_PENDING')[-1][1]
        if latest_pending['assignment_id'] != pending['assignment_id']:
            raise ValueError('GITLAB_HANDOFF_SUPERSEDED')
        if not any(
            d['request_id'] == payload['request_id'] for _, d in assignments(c, t['change_id'])
        ):
            lc._event(c, t['change_id'], 'GITLAB_REVIEW_ASSIGNED', cfg['actor'], ready)
    return ready


def signature(host, raw, headers, received_at):
    if type(raw) is not bytes or not 0 < len(raw) <= 1048576:
        raise ValueError('GITLAB_WEBHOOK_BODY_INVALID')
    if set(headers) != {'webhook-id', 'webhook-timestamp', 'webhook-signature'}:
        raise PermissionError('GITLAB_SIGNED_HEADERS_REQUIRED')
    mid = headers['webhook-id']
    ts = headers['webhook-timestamp']
    sig = headers['webhook-signature']
    if (
        not re.fullmatch('[A-Za-z0-9_-]{8,128}', mid)
        or not re.fullmatch('[0-9]{1,12}', ts)
        or abs(received_at.timestamp() - int(ts)) > 300
    ):
        raise PermissionError('GITLAB_WEBHOOK_TIMESTAMP_OR_ID_INVALID')
    key = host.signing_key()
    try:
        if not key.startswith('whsec_'):
            raise ValueError()
        decoded = base64.b64decode(key[6:], validate=True)
        if len(decoded) < 32:
            raise ValueError()
    except Exception:
        raise PermissionError('GITLAB_SIGNING_KEY_UNAVAILABLE') from None
    expected = (
        'v1,'
        + base64.b64encode(
            hmac.new(
                decoded, mid.encode() + b'.' + ts.encode() + b'.' + raw, hashlib.sha256
            ).digest()
        ).decode()
    )
    if not any(hmac.compare_digest(expected, s) for s in sig.split(' ')):
        raise PermissionError('GITLAB_WEBHOOK_SIGNATURE_INVALID')
    return parse(raw)


def receive(db, cfg, api, host, case, sid, raw, headers, *, defer_reflection=False):
    authorize(cfg, 'formal_receive', case)
    store = Store(db)
    saved = store.submission(sid)
    if saved['case_id'] != case:
        raise PermissionError('SUBMISSION_CASE_MISMATCH')
    if api.execution_kind != host.execution_kind or api.execution_kind not in {'LIVE', 'MOCK'}:
        raise PermissionError('GITLAB_APPROVAL_PROVENANCE_MISMATCH')
    bound_submission(cfg, api, saved)
    _account_guard(db, cfg, api, host, sid)
    received = now()
    event = signature(host, raw, headers, received)
    m = saved['prepared']['envelope']['manifest']
    if not m['change_binding']:
        raise ValueError('FORMAL_APPROVAL_EXISTING_CHANGE_REQUIRED')
    cid = m['change_binding']['change_id']
    a = event.get('object_attributes', {})
    if (
        event.get('object_kind') != 'merge_request'
        or event.get('project', {}).get('id') != int(api.project)
        or a.get('target_project_id') != int(api.project)
        or a.get('iid') != saved['mr_iid']
    ):
        raise PermissionError('GITLAB_WEBHOOK_TARGET_MISMATCH')
    rid = headers['webhook-id']
    digest = hashlib.sha256(raw).hexdigest()
    with store.open() as c, c:
        c.execute('BEGIN IMMEDIATE')
        old = [d for _, d in _events(c, cid, 'GITLAB_APPROVAL_RECEIVED') if d['receipt_id'] == rid]
        if old:
            if old[0]['sha256'] != digest or old[0]['submission_id'] != sid:
                raise ValueError('GITLAB_WEBHOOK_ID_CONFLICT')
            return {
                'receipt_id': rid,
                'duplicate': True,
                'approval_granted': False,
                'requires_explicit_resume_or_status': True,
            }
        receipt = {
            'receipt_id': rid,
            'submission_id': sid,
            'received_at': received.isoformat(),
            'sha256': digest,
            'body_base64': base64.b64encode(raw).decode(),
            'headers': headers,
            'service_execution_kind': api.execution_kind,
        }
        lc._event(c, cid, 'GITLAB_APPROVAL_RECEIVED', SOURCE, receipt)
        # Withdrawing or changing a review invalidates before any API read (including outages).
        ready = assignments(c, cid)
        reviewer_id = ready[-1][1]['reviewer_id'] if ready else None
        if event_invalidates(event, saved, reviewer_id):
            _invalidate(c, cid, 'GITLAB_REVIEW_EVENT_' + a['action'].upper())
    if defer_reflection:
        return {'receipt_id':rid,'approval_granted':False,'reflection_pending':True}
    return reflect(db, cfg, api, host, case, sid, rid)


def reflect(db, cfg, api, host, case, sid, rid, *, reconsider_ignored=False):
    store = Store(db)
    saved = store.submission(sid)
    if saved['case_id'] != case:
        raise PermissionError('SUBMISSION_CASE_MISMATCH')
    bound_submission(cfg, api, saved)
    _account_guard(db, cfg, api, host, sid)
    cid = saved['prepared']['envelope']['manifest']['change_binding']['change_id']
    with store.open() as c:
        receipts = [
            d
            for _, d in _events(c, cid, 'GITLAB_APPROVAL_RECEIVED')
            if d['receipt_id'] == rid and d['submission_id'] == sid
        ]
        done = [d for _, d in _events(c, cid, 'GITLAB_APPROVAL_DECIDED') if d['receipt_id'] == rid]
    if len(receipts) != 1:
        raise ValueError('GITLAB_VERIFIED_RECEIPT_REQUIRED')
    reconsider = bool(
        reconsider_ignored
        and done
        and done[-1].get('action') == 'approved'
        and done[-1].get('reason') == 'NOT_AN_INDIVIDUAL_APPROVAL_ACTION'
        and done[-1].get('decision_contract') != DECISION_CONTRACT
    )
    if done and not reconsider:
        return {
            **done[-1],
            'duplicate': True,
            'approval_granted': False,
            'test_approval_granted': False,
            'requires_fresh_formal_status': True,
        }
    r = receipts[0]
    raw = base64.b64decode(r['body_base64'], validate=True)
    if (
        r['service_execution_kind'] != api.execution_kind
        or host.execution_kind != api.execution_kind
    ):
        raise PermissionError('GITLAB_APPROVAL_PROVENANCE_MISMATCH')
    if hashlib.sha256(raw).hexdigest() != r['sha256']:
        raise ValueError('GITLAB_RECEIPT_CHANGED')
    ev = signature(host, raw, r['headers'], _time(r['received_at']))
    a = ev['object_attributes']
    result = {
        'receipt_id': rid,
        'approval_granted': False,
        'execution_allowed': False,
        'baseline_updated': False,
        'action': a.get('action'),
        'decision_contract': DECISION_CONTRACT,
    }
    if reconsider:
        result['reconsidered_decision_sha256'] = data_digest(done[-1])
    candidate = a.get('action') == 'approval'
    if a.get('action') == 'approved':
        # Overall MR state is only a trigger. Require this actor's timestamped
        # individual approval from the official API, then ALL ordinary checks below.
        uid = ev.get('user', {}).get('id')
        if type(uid) is int:
            try:
                approval(api, uid, saved['mr_iid'])
                candidate = True
            except PermissionError as exc:
                if str(exc) != 'GITLAB_CURRENT_USER_APPROVAL_NOT_PRESENT':
                    raise
    if not candidate:
        result['reason'] = 'NOT_AN_INDIVIDUAL_APPROVAL_ACTION'
    else:
        try:
            pol, ph, t = context(db, cfg, api, host, sid)
            uid = ev.get('user', {}).get('id')
            if type(uid) is not int:
                raise PermissionError('GITLAB_APPROVER_ID_REQUIRED')
            g = grant(pol, uid, t)
            with store.open() as c:
                assignment_eid, handoff = latest_assignment(c, cid)
            if (
                handoff['target'] != t
                or handoff['policy_sha256'] != ph
                or handoff['reviewer_id'] != uid
                or handoff['service_execution_kind'] != api.execution_kind
            ):
                raise PermissionError('GITLAB_APPROVAL_HANDOFF_MISMATCH')
            if a.get('last_commit', {}).get('id') != t['commit_sha']:
                raise ValueError('GITLAB_APPROVED_COMMIT_MISMATCH')
            membership = member(api, uid)
            record, state = approval(api, uid, t['mr_iid'])
            # A delayed, previously received approval must not revive a withdrawn or revised review.
            with store.open() as c:
                for _, later in _events(c, cid, 'GITLAB_APPROVAL_RECEIVED'):
                    if later['submission_id'] != sid or later['receipt_id'] == rid:
                        continue
                    other = parse(base64.b64decode(later['body_base64'], validate=True))
                    if event_invalidates(other, saved, uid) and _time(
                        record['approved_at']
                    ) <= _time(later['received_at']):
                        raise PermissionError('GITLAB_APPROVAL_PREDATES_WITHDRAWAL_OR_REVISION')
            if _time(record['approved_at']) < _time(handoff['armed_at']):
                raise PermissionError('GITLAB_OLD_APPROVAL_NOT_REUSABLE')
            if (
                _time(record['approved_at']).timestamp()
                > int(r['headers']['webhook-timestamp']) + 5
            ):
                raise PermissionError('GITLAB_APPROVAL_EVENT_PRECEDES_ACTION')
            if uid not in reviewers(api.mr(t['mr_iid'])):
                raise PermissionError('GITLAB_ASSIGNED_REVIEWER_REMOVED')
            if context(db, cfg, api, host, sid) != (pol, ph, t):
                raise ValueError('GITLAB_TARGET_OR_POLICY_CHANGED_DURING_CHECK')
            # Recheck the exact approval action after content reads; revoked/replaced actions are not accepted.
            again, _ = approval(api, uid, t['mr_iid'])
            if again != record:
                raise ValueError('GITLAB_APPROVAL_CHANGED_DURING_CHECK')
            until = min(_time(pol['expires_at']), _time(g['valid_until']))
            if t.get('account_test'):
                until = min(until, _time(t['account_test']['expires_at']))
            details = {
                'approval_source': SOURCE,
                'target': t,
                'target_sha256': data_digest(t),
                'assignment_event_id': assignment_eid,
                'receipt_id': rid,
                'approver_id': uid,
                'gitlab_approved_at': record['approved_at'],
                'policy_sha256': ph,
                'valid_until': until.isoformat(),
                'service_execution_kind': api.execution_kind,
                'provider_evidence': {'member': membership, 'approvals': state},
                'execution_allowed': False,
                'baseline_updated': False,
            }
            if t.get('account_test'):
                details.update(
                    account_test=t['account_test'],
                    authority='ACCOUNT_TEST_ONLY',
                    person_independence_verified=False,
                )
            with store.open() as c, c:
                c.execute('BEGIN IMMEDIATE')
                row = _local_unchanged(c, db, t)
                current = [
                    d
                    for _, d in _events(c, cid, 'GITLAB_APPROVAL_DECIDED')
                    if d['receipt_id'] == rid
                ]
                if current and (not reconsider or current != done):
                    raise ValueError('GITLAB_RECEIPT_CONCURRENTLY_PROCESSED')
                if latest_assignment(c, cid)[0] != assignment_eid:
                    raise ValueError('GITLAB_HANDOFF_CHANGED_DURING_CHECK')
                if row['status'] != 'AWAITING_REVIEW':
                    raise ValueError('GITLAB_CHANGE_NOT_AWAITING_REVIEW')
                actor = t['gitlab_origin'] + '|' + str(uid)
                c.execute(
                    "UPDATE lifecycle_change_v1 SET status=?,review_actor=?,updated_at_utc=? WHERE change_id=?",
                    (_account_native_state(t), actor, lc._now(), cid),
                )
                lc._event(c, cid, _account_event_kind(t), actor, details)
                result.update(
                    approval_granted=not bool(t.get('account_test')),
                    reason='GITLAB_HUMAN_APPROVAL_BOUND_TO_EXACT_DESIGN',
                    target=t,
                    service_execution_kind=api.execution_kind,
                )
                if t.get('account_test'):
                    result.update(
                        test_only=True,
                        test_approval_granted=True,
                        person_independence_verified=False,
                        reason='GITLAB_ACCOUNT_TEST_APPROVAL_BOUND_TO_EXACT_DESIGN',
                    )
                lc._event(c, cid, 'GITLAB_APPROVAL_DECIDED', SOURCE, result)
            return result
        except Exception as exc:
            invalidate_submission(db, sid, _reason(exc))
            store.evidence(
                case,
                'gitlab_approval_failure_v1',
                {'receipt_id': rid, 'reason': _reason(exc), 'automatic_retry': False},
            )
            raise
    with store.open() as c, c:
        c.execute('BEGIN IMMEDIATE')
        current = [
            d for _, d in _events(c, cid, 'GITLAB_APPROVAL_DECIDED') if d['receipt_id'] == rid
        ]
        if not current or reconsider and current == done:
            lc._event(c, cid, 'GITLAB_APPROVAL_DECIDED', SOURCE, result)
    return result


def status(db, cfg, api, host, case, sid):
    pol, ph, t = context(db, cfg, api, host, sid)
    if t['case_id'] != case:
        raise PermissionError('SUBMISSION_CASE_MISMATCH')
    with Store(db).open() as c:
        row = _local_unchanged(c, db, t)
        prior = _approval(c, t['change_id'], _account_event_kind(t))
    result = {
        'approval_granted': False,
        'formal_approval_granted': False,
        'reason': 'NO_CURRENT_GITLAB_APPROVAL',
        'target': t,
        'execution_allowed': False,
        'baseline_updated': False,
        'fresh_remote_verification_required_before_use': True,
    }
    if t.get('account_test'):
        result.update(
            test_only=True, test_approval_granted=False, person_independence_verified=False
        )
    if row['status'] == _account_native_state(t) and not prior:
        with Store(db).open() as c, c:
            c.execute('BEGIN IMMEDIATE')
            _invalidate(c, t['change_id'], 'GITLAB_APPROVAL_RECORD_MISSING')
        result['reason'] = 'GITLAB_APPROVAL_RECORD_MISSING'
    if row['status'] != _account_native_state(t) or not prior:
        return result
    try:
        d = prior[1]
        if (
            d.get('approval_source') != SOURCE
            or d['target'] != t
            or d['policy_sha256'] != ph
            or d['service_execution_kind'] != api.execution_kind
            or _time(d['valid_until']) <= now()
        ):
            raise ValueError('GITLAB_APPROVAL_BINDING_OR_AUTHORITY_CHANGED')
        grant(pol, d['approver_id'], t)
        member(api, d['approver_id'])
        with Store(db).open() as c:
            if latest_assignment(c, t['change_id'])[0] != d['assignment_event_id']:
                raise ValueError('GITLAB_HANDOFF_CHANGED')
        if d['approver_id'] not in reviewers(api.mr(t['mr_iid'])):
            raise ValueError('GITLAB_ASSIGNED_REVIEWER_REMOVED')
        a, _ = approval(api, d['approver_id'], t['mr_iid'])
        if a['approved_at'] != d['gitlab_approved_at']:
            raise ValueError('GITLAB_APPROVAL_ACTION_CHANGED')
        if context(db, cfg, api, host, sid) != (pol, ph, t):
            raise ValueError('GITLAB_TARGET_OR_POLICY_CHANGED_DURING_CHECK')
        final, _ = approval(api, d['approver_id'], t['mr_iid'])
        if final['approved_at'] != d['gitlab_approved_at']:
            raise ValueError('GITLAB_APPROVAL_ACTION_CHANGED')
        with Store(db).open() as c:
            current = _local_unchanged(c, db, t)
            if (
                current['status'] != _account_native_state(t)
                or _approval(c, t['change_id'], _account_event_kind(t))[0] != prior[0]
            ):
                raise ValueError('GITLAB_APPROVAL_CHANGED_DURING_CHECK')
        result.update(
            approval_granted=True,
            formal_approval_granted=True,
            reason='CURRENT_GITLAB_DESIGN_APPROVAL_VERIFIED',
            approval_event_id=prior[0],
            service_execution_kind=api.execution_kind,
        )
        if t.get('account_test'):
            result.update(
                approval_granted=False,
                formal_approval_granted=False,
                test_approval_granted=True,
                reason='CURRENT_GITLAB_ACCOUNT_TEST_APPROVAL_VERIFIED',
            )
    except Exception as exc:
        invalidate_submission(db, sid, _reason(exc))
        result['reason'] = _reason(exc)
    return result


def execute(db, cfg, api, request, host):
    op = request['operation']
    p = request['payload']
    case = request['case_id']
    if op not in OPS:
        raise PermissionError('GITLAB_HUMAN_APPROVAL_REQUIRED_WINDOWS_ENTRY_DISABLED')
    authorize(cfg, op, case)
    # Check scope before any remote access or invalidation of another case.
    if Store(db).submission(p['submission_id'])['case_id'] != case:
        raise PermissionError('SUBMISSION_CASE_MISMATCH')
    try:
        _account_guard(db, cfg, api, host, p['submission_id'])
    except Exception as exc:
        invalidate_submission(db, p['submission_id'], _reason(exc))
        raise
    if op in {'formal_prepare', 'formal_reconcile'}:
        return assign(db, cfg, api, host, case, p, op == 'formal_reconcile')
    if op == 'formal_status':
        if set(p) != {'submission_id'}:
            raise ValueError('GITLAB_STATUS_PAYLOAD_INVALID')
        return status(db, cfg, api, host, case, p['submission_id'])
    if op == 'formal_resume':
        if set(p) != {'submission_id', 'receipt_id'}:
            raise ValueError('GITLAB_RESUME_PAYLOAD_INVALID')
        return reflect(
            db, cfg, api, host, case, p['submission_id'], p['receipt_id'], reconsider_ignored=True
        )
    if set(p) != {'submission_id', 'body_base64', 'headers'}:
        raise ValueError('GITLAB_RECEIVE_PAYLOAD_INVALID')
    return receive(
        db,
        cfg,
        api,
        host,
        case,
        p['submission_id'],
        base64.b64decode(p['body_base64'], validate=True),
        p['headers'],
    )


def make_server(db, cfg, api, host, case, sid, port=0):
    """Adapter ingress in the existing entry. TLS ingress must be operator supplied.
    Never exposes the PC, installs a relay, or trusts unsigned forwarding headers.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import queue
    import threading

    authorize(cfg, 'formal_receive', case)
    saved = Store(db).submission(sid)
    if saved['case_id'] != case:
        raise PermissionError('SUBMISSION_CASE_MISMATCH')
    bound_submission(cfg, api, saved)
    _account_guard(db, cfg, api, host, sid)
    policy(host)
    # Refuse a listener with no usable key before opening a socket.
    key = host.signing_key()
    try:
        if not key.startswith('whsec_') or len(base64.b64decode(key[6:], validate=True)) < 32:
            raise ValueError()
    except Exception:
        raise PermissionError('GITLAB_SIGNING_KEY_UNAVAILABLE') from None

    pending=queue.SimpleQueue()

    def evaluate_receipts():
        while True:
            rid=pending.get()
            if rid is None:
                return
            try:
                reflect(db,cfg,api,host,case,sid,rid)
            except Exception as exc:
                saved=Store(db).submission(sid)
                change_id=saved['prepared']['envelope']['manifest']['change_binding']['change_id']
                with Store(db).open() as con,con:
                    lc._event(con,change_id,'GITLAB_APPROVAL_REFLECTION_FAILED',SOURCE,
                        {'receipt_id':rid,'submission_id':sid,'reason':_reason(exc),
                         'exception_type':type(exc).__name__,'automatic_retry':False})

    class Receiver(HTTPServer):
        def server_close(self):
            pending.put(None)
            super().server_close()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def do_POST(self):
            if self.path != '/gitlab-approvals':
                self.send_error(404)
                return
            try:
                if self.headers.get('Transfer-Encoding'):
                    raise ValueError('TRANSFER_ENCODING_DENIED')
                n = int(self.headers['Content-Length'])
                if not 0 < n <= 1048576:
                    raise ValueError('BODY_LIMIT')
                raw = self.rfile.read(n)
                if len(raw) != n:
                    raise ValueError('BODY_INCOMPLETE')
                heads = {
                    k: self.headers.get(k, '')
                    for k in ('webhook-id', 'webhook-timestamp', 'webhook-signature')
                }
                # Persist authenticated bytes and invalidate withdrawn reviews
                # before ACK. Slow read-only GitLab checks run after the ACK.
                result = receive(db, cfg, api, host, case, sid, raw, heads, defer_reflection=True)
                # No raw payload, signature, token or provider exception is returned/logged.
                body = canonical_json(
                    {
                        'received': True,
                        'receipt_id': result['receipt_id'],
                        'requires_fresh_formal_status': True,
                    }
                ).encode()
            except Exception:
                self.send_error(400, 'GitLab event not applied; inspect local receipt')
                return
            try:
                self.send_response(202)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                if result.get('reflection_pending'):
                    pending.put(result['receipt_id'])

    server=Receiver(('127.0.0.1', port), Handler)
    threading.Thread(target=evaluate_receipts,daemon=True).start()
    return server


from hashlib import sha256
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration import gitlab as gl


def _time(x):
    if not isinstance(x, str):
        raise PermissionError('APPROVAL_TIME_INVALID')
    value = datetime.fromisoformat(x.replace('Z', '+00:00'))
    if value.tzinfo is None:
        raise PermissionError('APPROVAL_TIME_INVALID')
    return value.astimezone(timezone.utc)


def _target(db, cfg, api, sid):
    if not cfg['gitlab'].get('review_only', False):
        raise PermissionError('FORMAL_APPROVAL_REQUIRES_GITLAB_REVIEW_ONLY')
    saved = Store(db).submission(sid)
    if saved['state'] != 'SUBMITTED':
        raise ValueError('FORMAL_APPROVAL_SUBMISSION_NOT_COMPLETE')
    m = saved['prepared']['envelope']['manifest']
    binding = m['change_binding']
    if not binding:
        raise ValueError('FORMAL_APPROVAL_EXISTING_CHANGE_REQUIRED')
    files = gl._unchanged(db, cfg, api, saved)
    observed = {}
    ok, reasons, _ = gl._review_only_check(api, saved, db, files, observed)
    if not ok:
        raise ValueError(reasons[0])
    mr = api.mr(saved['mr_iid'])
    gl._mr_matches(api, saved, mr)
    if mr.get('state') != 'opened' or mr.get('updated_at') != observed['mr']['updated_at']:
        raise ValueError('MR_CHANGED_DURING_APPROVAL_CHECK')
    author_id = mr.get('author', {}).get('id')
    if type(author_id) is not int:
        raise ValueError('GITLAB_AUTHOR_IDENTITY_UNAVAILABLE')
    change = lc.get_change(db, binding['change_id'])
    if change['status'] not in {'AWAITING_REVIEW', 'APPROVED', 'APPROVED_TEST_ONLY'}:
        raise ValueError('FORMAL_APPROVAL_CHANGE_STATE_INVALID')
    with closing(connect(db)) as con:
        con.row_factory = sqlite3.Row
        row = lc._one(
            con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (binding['change_id'],)
        )
        change_binding = lc._binding(con, row)
    if (
        lc.proposal_kind(change) == 'DOCKER_LAB'
        and lc.current_baseline(db)['version'] != change['base_version']
    ):
        raise ValueError('FORMAL_APPROVAL_BASELINE_CHANGED')
    return {
        'case_id': saved['case_id'],
        'submission_id': sid,
        'change_id': binding['change_id'],
        'design_id': m['design_id'],
        'revision': m['revision'],
        'document_scope': m['scope'],
        'artifact_sha256': m['artifact_sha256'],
        'design_sha256': binding['design_sha256'],
        'change_binding_sha256': change_binding,
        'base_version': change['base_version'],
        'design_author': binding['author'],
        'project_id': api.project,
        'gitlab_origin': api.origin,
        'mr_iid': saved['mr_iid'],
        'commit_sha': saved['commit_sha'],
        'gitlab_author_id': author_id,
        'files': saved['prepared']['envelope']['files'],
    }


def _events(con, change_id, kind):
    return [
        (r[0], json.loads(r[1]))
        for r in con.execute(
            'SELECT event_id,details_json FROM lifecycle_event_v1 WHERE change_id=? AND event_type=? ORDER BY rowid',
            (change_id, kind),
        )
    ]


def _approval(con, change_id, kind='FORMAL_APPROVED'):
    rows = _events(con, change_id, kind)
    return rows[-1] if rows else None


def _invalidate(con, change_id, reason, actor='APPROVAL_INTEGRITY_CHECK'):
    row = lc._one(con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
    if row['status'] not in {'APPROVED', 'APPROVED_TEST_ONLY'}:
        return False
    test = row['status'] == 'APPROVED_TEST_ONLY'
    prior = _approval(con, change_id, 'TEST_APPROVED' if test else 'FORMAL_APPROVED')
    con.execute(
        "UPDATE lifecycle_change_v1 SET status='AWAITING_REVIEW',review_actor=NULL,updated_at_utc=? WHERE change_id=?",
        (lc._now(), change_id),
    )
    lc._event(
        con,
        change_id,
        'TEST_APPROVAL_INVALIDATED' if test else 'FORMAL_APPROVAL_INVALIDATED',
        actor,
        {
            'approval_event_id': prior[0] if prior else None,
            'reason': reason,
            'approval_granted': False,
            'execution_allowed': False,
            'baseline_updated': False,
        },
    )
    return True


def invalidate_document(con, scope, design_id, revision):
    if not con.execute("SELECT 1 FROM sqlite_master WHERE name='lifecycle_change_v1'").fetchone():
        return
    # Use the existing lifecycle/event transaction; no approval ledger is added.
    for change_id, state in con.execute(
        "SELECT change_id,status FROM lifecycle_change_v1 WHERE status IN ('APPROVED','APPROVED_TEST_ONLY')"
    ).fetchall():
        prior = _approval(
            con, change_id, 'TEST_APPROVED' if state == 'APPROVED_TEST_ONLY' else 'FORMAL_APPROVED'
        )
        if prior:
            target = prior[1]['target']
            if (
                target['document_scope'] == scope
                and target['design_id'] == design_id
                and target['revision'] != revision
            ):
                con.row_factory = sqlite3.Row
                _invalidate(con, change_id, 'DESIGN_REVISED')


def invalidate_submission(db, sid, reason):
    store = Store(db)
    with store.open() as con, con:
        con.execute('BEGIN IMMEDIATE')
        for change_id, state in con.execute(
            "SELECT change_id,status FROM lifecycle_change_v1 WHERE status IN ('APPROVED','APPROVED_TEST_ONLY')"
        ).fetchall():
            prior = _approval(
                con,
                change_id,
                'TEST_APPROVED' if state == 'APPROVED_TEST_ONLY' else 'FORMAL_APPROVED',
            )
            if prior and prior[1]['target']['submission_id'] == sid:
                _invalidate(con, change_id, reason)


def _local_unchanged(con, db, target):
    row = lc._one(
        con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (target['change_id'],)
    )
    lc._assert_integrity(con, row, db)
    if lc._binding(con, row) != target['change_binding_sha256']:
        raise ValueError('FORMAL_APPROVAL_CHANGE_BINDING_CHANGED')
    latest = con.execute(
        'SELECT MAX(revision) FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=?',
        (target['document_scope'], target['design_id']),
    ).fetchone()[0]
    if latest != target['revision']:
        raise ValueError('FORMAL_APPROVAL_DESIGN_REVISED')
    return row


def _reason(exc):
    raw = getattr(exc, 'code', str(exc))
    return raw if re.fullmatch('[A-Z][A-Z0-9_]*', raw) else type(exc).__name__


_account_STATE = 'APPROVED_TEST_ONLY'

_account_EVENT = 'GITLAB_ACCOUNT_TEST_BOUND'

_account_FIELDS = {
    'schema',
    'run_id',
    'issued_at',
    'expires_at',
    'db_path',
    'source_db_path',
    'case_id',
    'change_id',
    'gitlab_origin',
    'project_id',
    'submitter_user_id',
    'approver_user_id',
    'operator_person_id',
}


def _account_time(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise PermissionError('ACCOUNT_TEST_TIME_INVALID')
    return result.astimezone(timezone.utc)


def _account_validate(a):
    now = datetime.now(timezone.utc)
    if (
        type(a) is not dict
        or set(a) != _account_FIELDS
        or a.get('schema') != 'ila.eca.gitlab-account-test.v1'
        or (not isinstance(a.get('run_id'), str))
        or (not re.fullmatch('[A-Za-z0-9_-]{8,80}', a['run_id']))
        or (_account_time(a['issued_at']).timestamp() > now.timestamp() + 300)
        or (_account_time(a['expires_at']) <= now)
        or (
            not 0
            < (_account_time(a['expires_at']) - _account_time(a['issued_at'])).total_seconds()
            <= 7200
        )
    ):
        raise PermissionError('ACCOUNT_TEST_AUTHORIZATION_INVALID_OR_EXPIRED')
    for key in ('submitter_user_id', 'approver_user_id'):
        if type(a[key]) is not int or a[key] <= 0:
            raise PermissionError('ACCOUNT_TEST_DISTINCT_USER_IDS_REQUIRED')
    if a['submitter_user_id'] == a['approver_user_id']:
        raise PermissionError('ACCOUNT_TEST_DISTINCT_USER_IDS_REQUIRED')
    for key in ('case_id', 'change_id', 'operator_person_id', 'project_id'):
        if type(a[key]) is not str or not a[key] or '*' in a[key]:
            raise PermissionError('ACCOUNT_TEST_EXACT_SCOPE_REQUIRED')
    from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.adapters import origin

    if origin(a['gitlab_origin']) != a['gitlab_origin'] or not a['project_id'].isdigit():
        raise PermissionError('ACCOUNT_TEST_EXACT_SCOPE_REQUIRED')
    for key in ('db_path', 'source_db_path'):
        if type(a[key]) is not str or not Path(a[key]).is_absolute():
            raise PermissionError('ACCOUNT_TEST_ABSOLUTE_DATABASE_REQUIRED')
    if Path(a['db_path']).resolve() == Path(a['source_db_path']).resolve():
        raise PermissionError('ACCOUNT_TEST_ISOLATED_COPY_REQUIRED')
    return a


def _account_guard(db, cfg, api, host, sid, target=None):
    store = Store(db)
    saved = store.submission(sid)
    with store.open() as c:
        markers = c.execute(
            'SELECT details_json FROM lifecycle_event_v1 WHERE event_type=?', (_account_EVENT,)
        ).fetchall()
    path = getattr(host, 'account_test_authorization_path', None)
    if path is None:
        if markers:
            raise PermissionError('TEST_DATABASE_REQUIRES_EXPLICIT_ACCOUNT_TEST_RUNTIME')
        return None
    from ILA_ECA_REAL_DISCOVERY_LAB.llm.cloud import parse

    a = _account_validate(parse(Path(path).read_bytes()))
    if Path(db).resolve(strict=True) != Path(a['db_path']).resolve(strict=True) or os.path.samefile(
        db, a['source_db_path']
    ):
        raise PermissionError('ACCOUNT_TEST_DATABASE_BINDING_MISMATCH')
    expected = {
        'run_id': a['run_id'],
        'authorization_sha256': data_digest(a),
        'case_id': a['case_id'],
        'change_id': a['change_id'],
    }
    if len(markers) != 1 or json.loads(markers[0][0]) != expected:
        raise PermissionError('ACCOUNT_TEST_PREPARED_DATABASE_REQUIRED')
    m = saved['prepared']['envelope']['manifest']
    binding = m['change_binding']
    if (
        cfg.get('classification') != 'SYNTHETIC_ONLINE'
        or api.origin != a['gitlab_origin']
        or api.project != a['project_id']
        or (saved['case_id'] != a['case_id'])
        or (not binding)
        or (binding['change_id'] != a['change_id'])
        or (m['scope'] not in {'lab', 'ila-discovery-lab'})
    ):
        raise PermissionError('ACCOUNT_TEST_SCOPE_MISMATCH')
    if target is not None and target['gitlab_author_id'] != a['submitter_user_id']:
        raise PermissionError('ACCOUNT_TEST_SUBMITTER_ID_MISMATCH')
    return {
        k: a[k]
        for k in (
            'run_id',
            'submitter_user_id',
            'approver_user_id',
            'operator_person_id',
            'expires_at',
        )
    } | {
        'authorization_sha256': data_digest(a),
        'person_independence_verified': False,
        'test_only': True,
    }


def _account_identity_exception(p, uid, target, context, author, submitter, reviewer):
    if (
        context != target.get('account_test')
        or uid != context['approver_user_id']
        or target['gitlab_author_id'] != context['submitter_user_id']
        or (not author == submitter == reviewer == context['operator_person_id'])
    ):
        raise PermissionError('ACCOUNT_TEST_EXACT_SAME_OPERATOR_PAIR_REQUIRED')


def _account_event_kind(target):
    return 'TEST_APPROVED' if target.get('account_test') else 'FORMAL_APPROVED'


def _account_native_state(target):
    return _account_STATE if target.get('account_test') else 'APPROVED'
