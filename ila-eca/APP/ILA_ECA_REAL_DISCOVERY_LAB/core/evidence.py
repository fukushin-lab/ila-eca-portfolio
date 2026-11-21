"""Read selected fields from existing domain-local audit evidence; never infer cause."""

from contextlib import closing
from datetime import datetime
from pathlib import Path
from time import perf_counter
import copy
import json
import sqlite3

from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.design.change import resolve


def collect_evidence(
    db_path: Path,
    *,
    scope: str,
    selections: list[dict],
    hypotheses=None,
    operations=None,
    verification=None,
):
    """Keep provenance and unobserved selections without resending every raw payload.

    Paths are exact JSON pointers, not a product-specific meaning dictionary.
    Original payloads stay in the existing evidence table; no interpretation cache
    or external embedding/model call is introduced. Missing data is not normality.
    """
    started = perf_counter()
    if not isinstance(scope, str) or not scope or not isinstance(selections, list):
        raise ValueError('EVIDENCE_SELECTION_INVALID')
    output = []
    with closing(connect(db_path)) as con:
        con.row_factory = sqlite3.Row
        for selection in selections:
            if (
                not isinstance(selection, dict)
                or set(selection) - {'evidence_id', 'paths', 'subject_ref', 'conditions'}
                or not {'evidence_id', 'paths'} <= selection.keys()
            ):
                raise ValueError('EVIDENCE_SELECTION_INVALID')
            if not isinstance(selection['evidence_id'], str) or not isinstance(
                selection['paths'], list
            ):
                raise ValueError('EVIDENCE_SELECTION_INVALID')
            record = con.execute(
                'SELECT * FROM evidence WHERE evidence_id=?', (selection['evidence_id'],)
            ).fetchone()
            if record is None:
                output.append(
                    {
                        'selection': copy.deepcopy(selection),
                        'state': 'NOT_COLLECTED',
                        'reason': 'EVIDENCE_NOT_FOUND',
                    }
                )
                continue
            if record['scope'] != scope:
                raise PermissionError('CROSS_DOMAIN_EVIDENCE_DENIED')
            when = datetime.fromisoformat(record['observed_at'])
            if when.tzinfo is None:
                raise ValueError('EVIDENCE_TIMESTAMP_MISSING_TIMEZONE')
            payload = json.loads(record['payload_json'])
            fields = []
            for pointer in selection['paths']:
                try:
                    value = resolve(payload, pointer)
                    fields.append(
                        {'path': pointer, 'state': 'OBSERVED', 'value': copy.deepcopy(value)}
                    )
                except (KeyError, IndexError, TypeError):
                    fields.append({'path': pointer, 'state': 'UNOBSERVED'})
            output.append(
                {
                    'selection': copy.deepcopy(selection),
                    'state': 'COLLECTED_AT_RECORDED_TIME',
                    'evidence_id': record['evidence_id'],
                    'scope': scope,
                    'adapter': record['adapter'],
                    'source': record['source'],
                    'observed_at': record['observed_at'],
                    'record_sha256': data_digest(dict(record)),
                    'payload_sha256': data_digest(payload),
                    'fields': fields,
                    'current_validity': 'NOT_ASSESSED',
                }
            )
    return {
        'schema': 'ila.eca.selected-evidence.v1',
        'scope': scope,
        'evidence': output,
        'hypotheses': copy.deepcopy(hypotheses or []),
        'operations': copy.deepcopy(operations or []),
        'verification': copy.deepcopy(verification or []),
        'causal_conclusion': 'NOT_ASSESSED',
        'elapsed_ms': round((perf_counter() - started) * 1000, 3),
        'llm_calls': 0,
        'external_calls': 0,
        'baseline_updated': False,
    }
