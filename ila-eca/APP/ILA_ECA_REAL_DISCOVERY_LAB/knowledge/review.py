"""Read-only verification of stored source-review artifacts; shared helpers live in core.artifacts."""

import json

from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import validate_record, document_paths
from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.intake import _read_source, verify_search_evidence


def _data(
    con, design_id, revision, scope, title, source_ids, evidence_ids, unknowns, change_request_ref
):
    sources = []
    for sid in source_ids:
        row, meta = _read_source(con, sid, scope)
        sources.append(
            {'source_id': sid, 'manifest_sha256': row['manifest_sha256'], 'metadata': meta}
        )
    queries = []
    fields = {
        'source_id',
        'section_id',
        'chunk_id',
        'source_ref',
        'title',
        'source_kind',
        'document_state',
        'product',
        'version',
        'heading_path',
        'start',
        'end',
        'chunk_sha256',
        'source_sha256',
        'manifest_sha256',
        'vector_sha256',
        'cosine',
        'lexical_score',
        'rank',
    }
    for eid in evidence_ids:
        result = verify_search_evidence(con, eid, scope)
        if set(result['source_ids']) - set(source_ids):
            raise ValueError('REVIEW_SOURCE_SET_INCOMPLETE')
        queries.append(
            {
                'evidence_id': eid,
                'query': result['query'],
                'filters': result['filters'],
                'embedding_model': result['embedding_model'],
                'model_fingerprint': result['model_fingerprint'],
                'status': result['status'],
                'hits': [
                    {
                        **{k: v for k, v in hit.items() if k in fields},
                        'context_coverage': hit.get('context_coverage'),
                        'supporting_parts': [
                            {k: v for k, v in p.items() if k != 'text'}
                            for p in hit.get('supporting_parts', [])
                        ],
                        'unshown_section_ranges': hit.get('unshown_section_ranges', []),
                    }
                    for hit in result['hits']
                ],
            }
        )
    if change_request_ref is not None:
        row = con.execute(
            'SELECT scope FROM lifecycle_change_v1 WHERE change_id=?', (change_request_ref,)
        ).fetchone()
        if row is None or row['scope'] != scope:
            raise ValueError('REVIEW_CHANGE_SCOPE_MISMATCH')
    return {
        'schema': 'ila.eca.received-document-review.v1',
        'design_id': design_id,
        'revision': revision,
        'scope': scope,
        'title': title,
        'source_ids': source_ids,
        'sources': sources,
        'query_evidence_ids': evidence_ids,
        'queries': queries,
        'unknowns': unknowns,
        'change_request_ref': change_request_ref,
        'review_state': 'AWAITING_REVIEW',
        'approval_granted': False,
        'baseline_updated': False,
        'design_judgment_generated': False,
    }


def verify_review_from_connection(con, db, design_id, revision, scope):
    con.row_factory = __import__('sqlite3').Row
    row = con.execute(
        'SELECT * FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
        (scope, design_id, revision),
    ).fetchone()
    if not row:
        raise ValueError('REVIEW_ARTIFACT_NOT_FOUND')
    md, path = document_paths(db, row['relative_path'])
    if md.is_symlink() or path.is_symlink():
        raise ValueError('REVIEW_ARTIFACT_PATH_INVALID')
    content = md.read_bytes()
    data = json.loads(path.read_bytes())
    record = json.loads(row['record_json'])
    validate_record(record, content=content, structured_data=data)
    expected = _data(
        con,
        design_id,
        revision,
        scope,
        data['title'],
        data['source_ids'],
        data['query_evidence_ids'],
        data['unknowns'],
        data['change_request_ref'],
    )
    if data != expected or record['document_kind'] != 'RECEIVED_DOCUMENT_REVIEW':
        raise ValueError('REVIEW_SOURCE_BINDING_CHANGED')
    return {'record': record, 'data': data, 'path': str(md), 'structured_path': str(path)}


