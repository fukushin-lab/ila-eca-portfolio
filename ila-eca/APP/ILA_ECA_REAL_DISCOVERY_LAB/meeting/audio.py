"""Optional local meeting audio ASR -> timestamped events -> existing ECA V8.

ASR runtime is an optional dependency, not silently claimed working without a
real audio file and a local faster-whisper model.  Speaker IDs remain UNKNOWN
unless independent verified diarization is supplied. No auto approval.
"""

from __future__ import annotations
from hashlib import sha256
from pathlib import Path
from datetime import datetime, timezone
import json
import math
import wave

SUPPORTED = {'.wav', '.mp3', '.m4a', '.mp4', '.ogg', '.flac'}
MAX_AUDIO_BYTES = 90 * 1024 * 1024


def transcribe_segments(audio: Path, *, model_path: str, model_factory=None, device='auto') -> dict:
    """Runs real ASR when faster-whisper is installed and audio is explicitly supplied."""
    original = Path(audio)
    if original.is_symlink():
        raise ValueError('INVALID_LOCAL_AUDIO_FILE')
    path = original.resolve(strict=True)
    if not path.is_file() or path.suffix.lower() not in SUPPORTED:
        raise ValueError('INVALID_LOCAL_AUDIO_FILE')
    size = path.stat().st_size
    if not 44 <= size <= MAX_AUDIO_BYTES:
        raise ValueError('AUDIO_FILE_SIZE_OUT_OF_RANGE')
    injected = model_factory is not None
    if not injected:
        local_model = Path(model_path)
        if (
            not local_model.is_dir()
            or local_model.is_symlink()
            or any(
                not (local_model / name).is_file()
                for name in ('model.bin', 'config.json', 'tokenizer.json')
            )
        ):
            raise ValueError('LOCAL_ASR_MODEL_DIRECTORY_REQUIRED_NO_AUTO_DOWNLOAD')
        try:
            from faster_whisper import WhisperModel
        except ImportError as exc:
            raise RuntimeError('FASTER_WHISPER_OPTIONAL_DEPENDENCY_NOT_INSTALLED') from exc
        model_factory = WhisperModel
    if not isinstance(model_path, str) or not model_path or len(model_path) > 500:
        raise ValueError('INVALID_ASR_MODEL_REFERENCE')
    if device not in {'auto', 'cpu', 'cuda'}:
        raise ValueError('INVALID_ASR_DEVICE')
    content_sha = sha256(path.read_bytes()).hexdigest()
    asr = model_factory(model_path, device=device, compute_type='int8', local_files_only=True)
    segments, info = asr.transcribe(str(path), beam_size=3, vad_filter=True, language='ja')
    duration = getattr(info, 'duration', None)
    if path.suffix.lower() == '.wav':
        with wave.open(str(path)) as wav:
            duration = wav.getnframes() / wav.getframerate()
    events = []
    last_end = 0.0
    for i, s in enumerate(segments):
        start = float(s.start)
        end = float(s.end)
        txt = str(s.text).strip()
        if (
            not math.isfinite(start)
            or not math.isfinite(end)
            or start < 0
            or end < start
            or end > 7200
            or start + 0.01 < last_end
        ):
            raise ValueError('ASR_INVALID_SEGMENT_TIMESTAMPS')
        if duration is not None and (
            not math.isfinite(float(duration)) or end > float(duration) + 0.04
        ):
            exc = ValueError('ASR_SEGMENT_EXCEEDS_AUDIO_DURATION')
            exc.asr_trace = {
                'audio_duration_seconds': duration,
                'invalid_segment': {'start_sec': start, 'end_sec': end, 'transcript': txt},
                'prior_segments': events,
                'coverage': 'PARTIAL_ASR_NOT_ACCEPTED_NOT_SENT_TO_LLM',
            }
            raise exc
        last_end = end
        if not txt:
            continue
        events.append(
            {
                'segment_id': f'ASR-{i:05d}',
                'start_sec': round(start, 3),
                'end_sec': round(end, 3),
                'speaker_id': 'UNKNOWN',
                'speaker_verified': False,
                'transcript': txt,
                'text_sha256': sha256(txt.encode()).hexdigest(),
                'confidence': 'UNASSESSED',
            }
        )
    if sha256(path.read_bytes()).hexdigest() != content_sha:
        raise ValueError('AUDIO_CHANGED_DURING_TRANSCRIPTION')
    return {
        'schema': 'ila.eca.audio.v13',
        'source_kind': 'LOCAL_AUDIO_ASR',
        'transcribed_at': datetime.now(timezone.utc).isoformat(),
        'audio_filename': path.name,
        'audio_sha256': content_sha,
        'model': model_path,
        'language': 'ja',
        'segments': events,
        'speaker_identity': 'UNKNOWN_NOT_DIARIZED',
        'inference_origin': (
            'INJECTED_ASR_TEST_PROVIDER' if injected else 'REAL_LOCAL_FASTER_WHISPER'
        ),
        'device': device,
        'compute_type': 'int8',
        'automatic_download': False,
        'audio_duration_seconds': float(duration) if duration is not None else None,
        'formal_approval': False,
        'authority': 'UNTRUSTED_TRANSCRIPT',
    }


def transcript_for_eca(audio_result: dict) -> dict:
    if audio_result.get('schema') != 'ila.eca.audio.v13':
        raise ValueError('INVALID_ASR_RESULT_SCHEMA')
    events = audio_result['segments']
    for e in events:
        if e['speaker_id'] != 'UNKNOWN' or e['speaker_verified'] is not False:
            raise PermissionError('UNVERIFIED_SPEAKER_CANNOT_BE_TRUSTED')
    return {
        'meeting_text': ' '.join(e['transcript'] for e in events),
        'source_audio_sha256': audio_result['audio_sha256'],
        'segments': events,
        'authority': 'UNTRUSTED_MEETING_STATEMENT',
        'approval_created': False,
    }


def anchor_claims_to_segments(audio_result: dict, claims: list[dict]) -> list[dict]:
    """Anchor extracted meeting claims to audio time ranges without asserting authority.

    Only verbatim quotation matches are linked; ambiguous repeated quotations
    remain explicitly ambiguous. No speaker identity inference or task approval.
    """
    transcript_for_eca(audio_result)  # reject speaker identity spoofing
    if not isinstance(claims, list) or len(claims) > 100:
        raise ValueError('INVALID_AUDIO_CLAIM_LIST')
    segments = audio_result['segments']
    texts = [str(x['transcript']) for x in segments]
    text = ' '.join(texts)
    spans = []
    cursor = 0
    for i, value in enumerate(texts):
        spans.append((cursor, cursor + len(value), i))
        cursor += len(value) + 1
    result = []
    for claim in claims:
        quote = claim.get('quote') if isinstance(claim, dict) else None
        if not isinstance(quote, str) or not quote or len(quote) > 1500:
            raise ValueError('CLAIM_QUOTE_REQUIRED')
        occurrences = []
        pos = text.find(quote)
        while pos >= 0 and len(occurrences) < 3:
            occurrences.append(pos)
            pos = text.find(quote, pos + 1)
        item = {
            'quote_sha256': sha256(quote.encode('utf-8')).hexdigest(),
            'match_status': 'UNMATCHED',
            'speaker_identity': 'UNKNOWN',
            'approval_from_audio': False,
            'segments': [],
        }
        if len(occurrences) == 1:
            begin, end = occurrences[0], occurrences[0] + len(quote)
            found = [i for a, b, i in spans if a < end and b > begin]
            if found:
                covered = [segments[i] for i in found]
                item.update(
                    match_status='EXACT_SPAN_UNVERIFIED_ASR',
                    start_sec=covered[0]['start_sec'],
                    end_sec=covered[-1]['end_sec'],
                    segments=[e['segment_id'] for e in covered],
                )
        elif len(occurrences) > 1:
            item['match_status'] = 'AMBIGUOUS_REPEATED_QUOTE'
        result.append(item)
    return result
