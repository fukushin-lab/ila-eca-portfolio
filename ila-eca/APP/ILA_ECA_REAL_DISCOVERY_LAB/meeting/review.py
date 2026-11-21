"""Local ASR, existing text extraction and verification of source/time-bound review artifacts.

No audio-derived authority, identity inference, calendar action or Baseline seed.
The caller prepares public/model downloads separately; inference permits loopback only.
"""

from contextlib import closing
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from urllib import request as http
import inspect
import json
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, save_evidence
from ILA_ECA_REAL_DISCOVERY_LAB.meeting import audio as audio, analysis as eca
from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import deny_external_egress
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest, validate_record
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import document_paths
from ILA_ECA_REAL_DISCOVERY_LAB.design.non_aws import _model_digest

TEMPLATE = Path(__file__).resolve().parent.parent / 'templates/meeting_audio_review_v1.md.tpl'


def file_digest(path):
    h = sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def model_identity(path, *, runtime=None):
    path = Path(path).resolve(strict=True)
    from importlib.metadata import version

    files = {
        str(p.relative_to(path)): file_digest(p)
        for p in sorted(path.rglob('*'))
        if p.is_file() and '.cache' not in p.parts
    }
    if not {'config.json', 'model.bin', 'tokenizer.json'} <= files.keys():
        raise ValueError('LOCAL_ASR_MODEL_FILES_MISSING')
    return {
        'directory': str(path),
        'files_sha256': files,
        'runtime': (
            runtime
            if runtime is not None
            else {
                'python': __import__('platform').python_version(),
                **{k: version(k) for k in ('faster-whisper', 'ctranslate2', 'av', 'onnxruntime')},
            }
        ),
        'device': 'cpu',
        'compute_type': 'int8',
        'beam_size': 3,
        'vad_filter': True,
        'language': 'ja',
        'adapter_sha256': sha256(inspect.getsource(audio.transcribe_segments).encode()).hexdigest(),
    }


def _row(con, eid, scope, adapter):
    con.row_factory = sqlite3.Row
    row = con.execute('SELECT * FROM evidence WHERE evidence_id=?', (eid,)).fetchone()
    if not row or row['scope'] != scope or row['adapter'] != adapter:
        raise PermissionError('MEETING_EVIDENCE_SCOPE_OR_ADAPTER_MISMATCH')
    return dict(row), json.loads(row['payload_json'])


def _save(db, scope, adapter, payload):
    return save_evidence(
        adapter=adapter,
        source='LOCAL_MEETING_AUDIO_PIPELINE',
        scope=scope,
        payload=payload,
        db_path=db,
    )['evidence_id']


def transcribe(db, *, scope, path, model_path, source):
    path = Path(path).resolve(strict=True)
    digest = file_digest(path)
    identity = model_identity(model_path)
    if source.get('raw_sha256', digest) != digest:
        raise ValueError('RECEIVED_AUDIO_RECEIPT_MISMATCH')
    condition = {'audio_path': str(path), 'audio_sha256': digest, 'asr': identity, 'source': source}
    key = data_digest(condition)
    with closing(connect(db)) as con:
        # init only the existing audit schema; no Baseline is created.
        from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import init_db

        init_db(db)
        cached = con.execute(
            "SELECT evidence_id,payload_json FROM evidence WHERE adapter='meeting_asr_result_v1' AND scope=? AND json_extract(payload_json,'$.cache_key')=? AND json_extract(payload_json,'$.status')='GENERATED'",
            (scope, key),
        ).fetchone()
    if cached:
        payload = json.loads(cached[1])
        if (
            data_digest(payload['result']) != payload['result_sha256']
            or payload['condition'] != condition
        ):
            raise ValueError('MEETING_ASR_CACHE_CHANGED')
        return {
            'evidence_id': cached[0],
            'payload': payload,
            'actual_asr_calls': 0,
            'cache_hit': True,
        }
    started = perf_counter()
    try:
        with deny_external_egress():
            result = audio.transcribe_segments(path, model_path=str(model_path), device='cpu')
        if file_digest(path) != digest:
            raise ValueError('AUDIO_CHANGED_DURING_TRANSCRIPTION')
        payload = {
            'status': 'GENERATED',
            'cache_key': key,
            'condition': condition,
            'result': result,
            'result_sha256': data_digest(result),
            'elapsed_seconds': round(perf_counter() - started, 3),
            'actual_asr_calls': 1,
            'external_inference_calls': 0,
        }
    except Exception as exc:
        _save(
            db,
            scope,
            'meeting_asr_failure_v1',
            {
                'status': 'FAILED',
                'condition': condition,
                'error_type': type(exc).__name__,
                'error_code': (
                    str(exc)
                    if str(exc).startswith(('ASR_', 'AUDIO_', 'LOCAL_'))
                    else type(exc).__name__
                ),
                'partial_trace': getattr(exc, 'asr_trace', None),
                'elapsed_seconds': round(perf_counter() - started, 3),
            },
        )
        raise
    eid = _save(db, scope, 'meeting_asr_result_v1', payload)
    return {'evidence_id': eid, 'payload': payload, 'actual_asr_calls': 1, 'cache_hit': False}


def extract(db, *, scope, asr_evidence_id, model='qwen3:8b', profile=None):
    from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import IncidentModelProfile

    chosen = profile or IncidentModelProfile(model=model)
    chosen = IncidentModelProfile.from_dict(chosen.as_dict())
    if chosen.model != model:
        raise ValueError('MEETING_MODEL_PROFILE_MISMATCH')
    with closing(connect(db)) as con:
        row, asr = _row(con, asr_evidence_id, scope, 'meeting_asr_result_v1')
    _validate_asr(asr)
    note = audio.transcript_for_eca(asr['result'])['meeting_text']
    eca.validate_note(note)
    condition = {
        'asr_evidence_id': asr_evidence_id,
        'asr_record_sha256': data_digest(row),
        'text_sha256': sha256(note.encode()).hexdigest(),
        'model': model,
        'model_digest': _model_digest(model),
        'num_ctx': chosen.options['num_ctx'],
        'num_predict': chosen.options['num_predict'],
        'runtime_profile': chosen.as_dict(),
        'extractor_sha256': sha256(
            (
                inspect.getsource(eca.extract_with_ollama)
                + inspect.getsource(eca.validate_extraction)
                + inspect.getsource(eca.extraction_schema)
            ).encode()
        ).hexdigest(),
    }
    key = data_digest(condition)
    with closing(connect(db)) as con:
        old = con.execute(
            "SELECT evidence_id,payload_json FROM evidence WHERE adapter='meeting_llm_result_v1' AND scope=? AND json_extract(payload_json,'$.cache_key')=? AND json_extract(payload_json,'$.status')='GENERATED'",
            (scope, key),
        ).fetchone()
    if old:
        payload = json.loads(old[1])
        _validate_model(payload, note)
        return {'evidence_id': old[0], 'payload': payload, 'actual_llm_calls': 0, 'cache_hit': True}
    exchange = {}
    started = perf_counter()

    def capture(req, timeout):
        if req.full_url != 'http://127.0.0.1:11434/api/generate':
            raise PermissionError('LOCAL_MEETING_MODEL_ONLY')
        exchange['request'] = json.loads(req.data)
        response = http.urlopen(req, timeout=timeout)

        class Response:
            def __enter__(self):
                return self

            def read(self, limit):
                raw = response.read(limit)
                try:
                    exchange['response'] = json.loads(raw)
                except (ValueError, UnicodeError):
                    exchange['invalid_response_sha256'] = sha256(raw).hexdigest()
                return raw

            def __exit__(self, *_):
                response.close()

        return Response()

    try:
        with deny_external_egress():
            parsed = eca.extract_with_ollama(
                note,
                model=model,
                timeout=chosen.timeout,
                opener=capture,
                num_ctx=chosen.options['num_ctx'],
                num_predict=chosen.options['num_predict'],
                max_http_bytes=chosen.max_http_bytes,
                options=chosen.options,
            )
        payload = {
            'status': 'GENERATED',
            'condition': condition,
            'cache_key': key,
            'extraction': parsed,
            'extraction_sha256': data_digest(parsed),
            'exchange': exchange,
            'elapsed_seconds': round(perf_counter() - started, 3),
            'actual_llm_calls': 1,
            'inference_origin': 'REAL_LOCAL_OLLAMA_HTTP',
            'external_inference_calls': 0,
        }
        _validate_model(payload, note)
        if _model_digest(model) != condition['model_digest']:
            raise ValueError('MEETING_MODEL_CHANGED_DURING_EXTRACTION')
    except Exception as exc:
        _save(
            db,
            scope,
            'meeting_llm_failure_v1',
            {
                'status': 'FAILED',
                'condition': condition,
                'exchange': exchange,
                'error_type': type(exc).__name__,
                'error_code': (
                    str(exc) if str(exc).startswith(('V8_', 'MEETING_')) else type(exc).__name__
                ),
                'elapsed_seconds': round(perf_counter() - started, 3),
                'actual_llm_calls': int('request' in exchange),
            },
        )
        raise
    eid = _save(db, scope, 'meeting_llm_result_v1', payload)
    return {'evidence_id': eid, 'payload': payload, 'actual_llm_calls': 1, 'cache_hit': False}


def _validate_model(payload, note):
    envelope = payload['exchange']['response']
    if envelope.get('done') is not True or envelope.get('done_reason') not in (None, 'stop'):
        raise ValueError('MEETING_MODEL_INCOMPLETE')
    parsed = eca.validate_extraction(note, json.loads(envelope['response']))
    if parsed != payload['extraction'] or data_digest(parsed) != payload['extraction_sha256']:
        raise ValueError('MEETING_MODEL_OUTPUT_CHANGED')


def _validate_asr(asr):
    c = asr['condition']
    result = asr['result']
    if (
        file_digest(c['audio_path']) != c['audio_sha256']
        or c['audio_sha256'] != result['audio_sha256']
    ):
        raise ValueError('MEETING_ORIGINAL_AUDIO_CHANGED')
    # A document reader does not need an ASR runtime installed. The historical
    # runtime is pinned in its evidence; current source/model bytes are checked.
    if model_identity(c['asr']['directory'], runtime=c['asr']['runtime']) != c['asr']:
        raise ValueError('MEETING_ASR_MODEL_OR_ADAPTER_CHANGED')
    if asr['status'] != 'GENERATED' or data_digest(result) != asr['result_sha256']:
        raise ValueError('MEETING_ASR_OUTPUT_CHANGED')


def _items(result, extraction):
    note = audio.transcript_for_eca(result)['meeting_text']
    items = eca.anchor_meeting_items(note, extraction)
    for item in items:
        item['audio_anchor'] = audio.anchor_claims_to_segments(result, [{'quote': item['quote']}])[
            0
        ]
        for name in ('assignee', 'due'):
            quote = item.get(name + '_quote')
            item[name + '_audio_anchor'] = (
                audio.anchor_claims_to_segments(result, [{'quote': quote}])[0] if quote else None
            )
    return items


def _material(con, scope, did, revision, asr_eid, llm_eid):
    ar, asr = _row(con, asr_eid, scope, 'meeting_asr_result_v1')
    lr, llm = _row(con, llm_eid, scope, 'meeting_llm_result_v1')
    c = asr['condition']
    result = asr['result']
    note = audio.transcript_for_eca(result)['meeting_text']
    _validate_asr(asr)
    if llm['condition']['asr_evidence_id'] != asr_eid or llm['condition'][
        'asr_record_sha256'
    ] != data_digest(ar):
        raise ValueError('MEETING_ASR_LLM_BINDING_CHANGED')
    _validate_model(llm, note)
    return {
        'schema': 'ila.eca.audio-review.v1',
        'design_id': did,
        'revision': revision,
        'scope': scope,
        'asr_evidence_id': asr_eid,
        'asr_record_sha256': data_digest(ar),
        'llm_evidence_id': llm_eid,
        'llm_record_sha256': data_digest(lr),
        'source': c['source'],
        'audio_path': c['audio_path'],
        'audio_sha256': result['audio_sha256'],
        'asr_result': result,
        'transcript': note,
        'transcript_sha256': sha256(note.encode()).hexdigest(),
        'model': llm['condition']['model'],
        'model_digest': llm['condition']['model_digest'],
        'model_extraction': llm['extraction'],
        'items': _items(result, llm['extraction']),
        'time_alignment': 'ASR_SEGMENT_BOUNDS_NOT_WORD_LEVEL_FORCED_ALIGNMENT',
        'render_template_sha256': file_digest(TEMPLATE),
        'renderer_sha256': sha256(inspect.getsource(_body).encode()).hexdigest(),
        'unprocessed_audio': 'NONE_IN_RECEIVED_SAMPLE',
        'coverage': 'RECEIVED_SAMPLE_ONLY_NOT_FULL_MEETING_OR_CORPUS',
        'speech_recognition_accuracy': 'REQUIRES_SEPARATE_AUDIO_REFERENCE_COMPARISON',
        'semantic_extraction_accuracy': 'REQUIRES_SEPARATE_REFERENCE_COMPARISON',
        'speaker_identity': 'UNKNOWN_NOT_DIARIZED',
        'authority': 'UNTRUSTED_MEETING_STATEMENTS_NOT_APPROVAL',
        'calendar_actions': 0,
        'automatic_tasks_created': 0,
        'baseline_comparison': 'NOT_ASSESSED_NO_TARGET_BASELINE_PROVIDED',
        'baseline_updated': False,
    }


def _body(data):
    def block(value):
        raw = json.dumps(value, ensure_ascii=False, indent=2)
        import re

        fence = '`' * max(3, max((len(m) for m in re.findall(r'`+', raw)), default=0) + 1)
        return fence + 'json\n' + raw + '\n' + fence

    return '\n\n'.join(
        [
            '## 出典と確認範囲',
            block(data['source']),
            '受領サンプル内の確認です。話者の本人・権限、正式な決定、会議全体の品質を確認した記録ではありません。',
            '## 時刻付き文字起こし（音声認識結果）',
            block(data['asr_result']['segments']),
            '## 既存テキスト判断の出力（未確認の候補）',
            block(data['model_extraction']),
            '## 元発言・文字位置・音声時刻との対応',
            block(data['items']),
            '時刻は引用を含むASR区間の範囲であり、単語単位の正確な開始・終了を示すものではありません。',
            '## 生成経路・同一性',
            block(
                {
                    k: data[k]
                    for k in (
                        'asr_evidence_id',
                        'asr_record_sha256',
                        'llm_evidence_id',
                        'llm_record_sha256',
                        'audio_sha256',
                        'transcript_sha256',
                        'model',
                        'model_digest',
                        'speaker_identity',
                        'baseline_comparison',
                        'baseline_updated',
                        'calendar_actions',
                        'automatic_tasks_created',
                    )
                }
            ),
        ]
    )



def verify_audio_review(con, db, did, revision, scope):
    row = con.execute(
        'SELECT relative_path,record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
        (scope, did, revision),
    ).fetchone()
    if not row:
        raise ValueError('MEETING_AUDIO_DOCUMENT_NOT_FOUND')
    md, path = document_paths(db, row[0])
    data = json.loads(path.read_bytes())
    record = json.loads(row[1])
    validate_record(record, content=md.read_bytes(), structured_data=data)
    expected = _material(
        con, scope, did, revision, data['asr_evidence_id'], data['llm_evidence_id']
    )
    if data != expected or record['document_kind'] != 'MEETING_AUDIO_REVIEW':
        raise ValueError('MEETING_AUDIO_DOCUMENT_BINDING_CHANGED')
    return {'record': record, 'data': data, 'path': str(md), 'structured_path': str(path)}


