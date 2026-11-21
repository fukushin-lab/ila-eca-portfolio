"""Domain-local received documents -> existing RAG -> exact source-bound evidence.

No public fetch, text generation, infrastructure operations, or approval here.
The existing evidence and RAG tables remain the stores for audit and vectors.
"""

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
from time import perf_counter
import inspect
import copy
import json
import math
import re
import sqlite3

from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, init_db, save_evidence
from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.index import (
    init_rag,
    index_documents,
    search_documents,
    split_text,
)
import ILA_ECA_REAL_DISCOVERY_LAB.knowledge.index as rag_v03
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import DEFAULT_RESPONSE_BYTES, positive_int

VERSION = 'received-documents-v1'
ADAPTER = 'received_document_search_v1'


class _HTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tokens = []
        self.skip = []
        self.stack = []
        self.main = None
        self.depth = 0
        self.cell_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.stack.append(tag)
        if tag in {'script', 'style', 'nav', 'footer', 'form', 'head'} or (
            tag == 'a' and 'headerlink' in attrs.get('class', '').split()
        ):
            self.skip.append(tag)
        if self.skip:
            return
        if tag == 'main' or attrs.get('role') == 'main':
            self.depth = 1
            self.main = []
        elif self.depth:
            self.depth += 1
        target = self.main if self.depth else self.tokens
        if tag in {'td', 'th'}:
            self.cell_depth += 1
        if re.fullmatch('h[1-6]', tag):
            target.append('\n\n' + '#' * int(tag[1]) + ' ')
        elif tag == 'pre':
            target.append('\n' + '`' * 16 + '\n')
        elif tag in {'p', 'tr', 'ul', 'ol', 'div', 'section', 'article'}:
            target.append(' ' if self.cell_depth else '\n')
        elif tag == 'li':
            target.append('\n- ')
        elif tag in {'td', 'th'}:
            target.append(' | ')
        elif tag == 'br':
            target.append('\n')
        # HTML void elements have no corresponding closing tag.
        if self.depth and tag in {'img', 'br', 'hr', 'input', 'meta', 'link', 'source', 'wbr'}:
            self.depth -= 1

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in {'img', 'br', 'hr', 'input', 'meta', 'link', 'source', 'wbr'}:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.skip:
            if tag == self.skip[-1]:
                self.skip.pop()
            return
        target = self.main if self.depth else self.tokens
        if tag in {'td', 'th'}:
            self.cell_depth -= 1
        if tag == 'pre':
            target.append('\n' + '`' * 16 + '\n')
        elif tag == 'tr':
            target.append(' |\n')
        elif re.fullmatch('h[1-6]', tag) or tag in {'p', 'li'}:
            target.append(' ' if self.cell_depth else '\n')
        if self.depth:
            self.depth -= 1

    def handle_data(self, data):
        if not self.skip:
            (self.main if self.depth else self.tokens).append(data)


def extract(raw, format):
    text = raw.decode('utf-8-sig')
    if format == 'html':
        parser = _HTML()
        parser.feed(text)
        parser.close()
        text = ''.join(parser.main if parser.main is not None else parser.tokens)
        lines = []
        in_code = False
        for line in text.split('\n'):
            if line.strip() == '`' * 16:
                in_code = not in_code
                lines.append('`' * 16)
            elif in_code:
                lines.append(line.rstrip('\r'))
            else:
                lines.append(re.sub(r'[ \t\r\f\v]+', ' ', line).strip())
        text = '\n'.join(lines)
        text = text.strip()
    elif format not in {'markdown', 'text'}:
        raise ValueError('DOCUMENT_FORMAT_UNSUPPORTED')
    if not text.strip():
        raise ValueError('DOCUMENT_TEXT_EMPTY')
    return text


def sections(text, format):
    """Contiguous complete ranges, retaining Markdown hierarchy and table/code text."""
    starts = [(0, [])]
    headings = []
    offset = 0
    fence = None
    for line in text.splitlines(keepends=True):
        marker = re.match(r'^\s*(`{3,}|~{3,})', line)
        if marker:
            kind = marker[1][0]
            if fence is None:
                fence = (kind, len(marker[1]))
            elif kind == fence[0] and len(marker[1]) >= fence[1]:
                fence = None
        match = (
            None
            if fence or format == 'text'
            else re.match(r'^(#{1,6})\s+(.+?)\s*#*\s*$', line.rstrip('\r\n'))
        )
        if match:
            level = len(match[1])
            headings = [x for x in headings if x[0] < level] + [(level, match[2])]
            current = [x[1] for x in headings]
            if offset == 0:
                starts[0] = (0, current)
            else:
                starts.append((offset, current))
        offset += len(line)
    return [
        {
            'ordinal': i,
            'start': start,
            'end': starts[i + 1][0] if i + 1 < len(starts) else len(text),
            'heading_path': path,
        }
        for i, (start, path) in enumerate(starts)
    ]


def init_documents(db):
    init_db(db)
    init_rag(db)
    with closing(connect(db)) as con, con:
        con.execute(
            '''CREATE TABLE IF NOT EXISTS received_document_v1 (
          source_id TEXT PRIMARY KEY,scope TEXT NOT NULL,source_ref TEXT NOT NULL,version TEXT,
          index_scope TEXT NOT NULL,state TEXT NOT NULL,raw_bytes BLOB NOT NULL,
          text_data TEXT NOT NULL,manifest_json TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,evidence_id TEXT)'''
        )
        con.execute(
            '''CREATE TABLE IF NOT EXISTS received_section_v1 (
          section_id TEXT PRIMARY KEY,source_id TEXT NOT NULL,ordinal INTEGER NOT NULL,
          start_offset INTEGER NOT NULL,end_offset INTEGER NOT NULL,heading_json TEXT NOT NULL,
          chunks_json TEXT NOT NULL)'''
        )


def _read_source(con, source_id, scope, *, require_current=True):
    con.row_factory = sqlite3.Row
    row = con.execute(
        'SELECT * FROM received_document_v1 WHERE source_id=?', (source_id,)
    ).fetchone()
    if row is None or row['scope'] != scope:
        raise PermissionError('DOCUMENT_SCOPE_OR_SOURCE_MISMATCH')
    if require_current and row['state'] != 'ACTIVE':
        raise ValueError('DOCUMENT_INPUT_VERSION_CHANGED')
    meta = json.loads(row['manifest_json'])
    if meta['scope'] != scope:
        raise PermissionError('DOCUMENT_SCOPE_OR_SOURCE_MISMATCH')
    if (
        row['source_id'] != 'DOC_' + data_digest(meta)[:32]
        or row['source_ref'] != meta['source_ref']
        or row['version'] != meta['version']
    ):
        raise ValueError('DOCUMENT_SOURCE_METADATA_CHANGED')
    expected_scope = (
        'DOCS_'
        + data_digest(
            [scope, meta['source_kind'], meta['product'], meta['version'], meta['configuration']]
        )[:32]
    )
    if row['index_scope'] != expected_scope:
        raise ValueError('DOCUMENT_INDEX_SCOPE_CHANGED')
    if (
        data_digest(meta) != row['manifest_sha256']
        or sha256(row['raw_bytes']).hexdigest() != meta['raw_sha256']
        or sha256(row['text_data'].encode()).hexdigest() != meta['text_sha256']
    ):
        raise ValueError('DOCUMENT_SOURCE_CHANGED')
    path = Path(meta['local_path'])
    if not path.is_file() or sha256(path.read_bytes()).hexdigest() != meta['raw_sha256']:
        raise ValueError('DOCUMENT_ORIGINAL_FILE_CHANGED_OR_MISSING')
    return row, meta


def ingest_file(
    db,
    path,
    *,
    scope,
    source_ref,
    title,
    format,
    source_kind,
    version,
    document_state,
    embeddings,
    embedding_model,
    model_fingerprint,
    product=None,
    receipt=None,
    max_source_bytes=DEFAULT_RESPONSE_BYTES,
):
    started = perf_counter()
    path = Path(path)
    if path.is_symlink():
        raise ValueError('DOCUMENT_FILE_INVALID_OR_TOO_LARGE')
    path = path.resolve(strict=True)
    positive_int(max_source_bytes, 'DOCUMENT_SOURCE_CAPACITY_INVALID')
    if not path.is_file() or path.stat().st_size > max_source_bytes:
        raise ValueError('DOCUMENT_FILE_INVALID_OR_TOO_LARGE')
    if not scope or not source_ref or not title or not model_fingerprint:
        raise ValueError('DOCUMENT_METADATA_REQUIRED')
    raw = path.read_bytes()
    raw_sha = sha256(raw).hexdigest()
    if receipt and receipt.get('raw_sha256') != raw_sha:
        raise ValueError('PUBLIC_RECEIPT_BYTES_MISMATCH')
    if receipt and any(
        receipt.get(k) != v
        for k, v in [('source_ref', source_ref), ('product', product), ('version', version)]
    ):
        raise ValueError('PUBLIC_RECEIPT_METADATA_MISMATCH')
    text = extract(raw, format)
    spans = sections(text, format)
    configuration = {
        'extractor': VERSION,
        'rag_splitter': 'rag_v03:500:80',
        'embedding_model': embedding_model,
        'model_fingerprint': model_fingerprint,
        'extractor_code_sha256': sha256(
            (''.join(inspect.getsource(x) for x in (_HTML, extract, sections))).encode()
        ).hexdigest(),
        'rag_core_sha256': sha256(Path(rag_v03.__file__).read_bytes()).hexdigest(),
    }
    metadata = {
        'scope': scope,
        'source_ref': source_ref,
        'title': title,
        'format': format,
        'source_kind': source_kind,
        'version': version,
        'document_state': document_state,
        'product': product,
        'raw_sha256': raw_sha,
        'text_sha256': sha256(text.encode()).hexdigest(),
        'local_path': str(path),
        'raw_bytes': len(raw),
        'text_chars': len(text),
        'configuration': configuration,
        'receipt': receipt,
        'sections': spans,
        'processed_chars': sum(s['end'] - s['start'] for s in spans),
        'unprocessed_chars': 0,
        'coverage': 'ALL_RECEIVED_TEXT_PROCESSED_NOT_ALL_EXTERNAL_LINKED_PAGES',
    }
    source_id = 'DOC_' + data_digest(metadata)[:32]
    index_scope = 'DOCS_' + data_digest([scope, source_kind, product, version, configuration])[:32]
    init_documents(db)
    with closing(connect(db)) as con:
        con.row_factory = sqlite3.Row
        old = con.execute(
            'SELECT * FROM received_document_v1 WHERE source_id=?', (source_id,)
        ).fetchone()
        if old and old['state'] == 'ACTIVE':
            _read_source(con, source_id, scope)
            verify_source_index(con, source_id, scope)
            return {
                'source_id': source_id,
                'evidence_id': old['evidence_id'],
                'cache_hit': True,
                'embedded_sections': 0,
                'elapsed_ms': round((perf_counter() - started) * 1000, 3),
            }
    with closing(connect(db)) as con, con:
        con.execute(
            'INSERT OR IGNORE INTO received_document_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?)',
            (
                source_id,
                scope,
                source_ref,
                version,
                index_scope,
                'PENDING',
                raw,
                text,
                canonical_json(metadata),
                data_digest(metadata),
                None,
            ),
        )
    prepared = []
    for span in spans:
        content = text[span['start'] : span['end']]
        if not content.strip():
            continue
        sid = 'SEC_' + data_digest([source_id, span])[:32]
        index_documents(
            [
                {
                    'doc_id': sid,
                    'title': title + ' / ' + ' / '.join(span['heading_path']),
                    'source_ref': source_ref,
                    'scope': index_scope,
                    'status': 'DRAFT',
                    'source_type': 'RECEIVED_SOURCE_SECTION',
                    'updated_at': raw_sha,
                    'text': content,
                }
            ],
            embeddings=embeddings,
            embedding_model=embedding_model,
            db_path=db,
        )
        with closing(connect(db)) as con:
            chunks = con.execute(
                'SELECT chunk_id,chunk_text,embedding_json FROM rag_chunks WHERE doc_id=? ORDER BY chunk_id',
                (sid,),
            ).fetchall()
        sealed = []
        for cid, chunk, vector in chunks:
            numbers = json.loads(vector)
            if not numbers or not all(
                type(x) in (int, float) and math.isfinite(x) for x in numbers
            ):
                raise ValueError('DOCUMENT_VECTOR_INVALID')
            sealed.append(
                {
                    'chunk_id': cid,
                    'text_sha256': sha256(chunk.encode()).hexdigest(),
                    'vector_sha256': sha256(vector.encode()).hexdigest(),
                }
            )
        prepared.append(
            (
                sid,
                source_id,
                span['ordinal'],
                span['start'],
                span['end'],
                canonical_json(span['heading_path']),
                canonical_json(sealed),
            )
        )
    evidence = save_evidence(
        adapter='received_document_v1',
        source=source_ref,
        scope=scope,
        payload={
            'source_id': source_id,
            'manifest_sha256': data_digest(metadata),
            'raw_sha256': raw_sha,
            'text_sha256': metadata['text_sha256'],
            'document_state': document_state,
            'version': version,
            'source_kind': source_kind,
            'sections': len(prepared),
            'processed_chars': len(text),
            'unprocessed_chars': 0,
        },
        db_path=db,
    )
    with closing(connect(db)) as con, con:
        con.execute('BEGIN IMMEDIATE')
        _read_source(con, source_id, scope, require_current=False)
        # Superseding one declared edition does not merge product versions or domains.
        stale = con.execute(
            'SELECT source_id FROM received_document_v1 WHERE scope=? AND source_ref=? AND version IS ? AND source_id!=? AND state=\'ACTIVE\'',
            (scope, source_ref, version, source_id),
        ).fetchall()
        for (previous,) in stale:
            con.execute(
                "UPDATE received_document_v1 SET state='SUPERSEDED' WHERE source_id=?", (previous,)
            )
            con.execute(
                "UPDATE rag_docs SET status='SUPERSEDED' WHERE doc_id IN (SELECT section_id FROM received_section_v1 WHERE source_id=?)",
                (previous,),
            )
        for row in prepared:
            con.execute('INSERT OR REPLACE INTO received_section_v1 VALUES (?,?,?,?,?,?,?)', row)
            con.execute("UPDATE rag_docs SET status='ACTIVE' WHERE doc_id=?", (row[0],))
        con.execute(
            "UPDATE received_document_v1 SET state='ACTIVE',evidence_id=? WHERE source_id=?",
            (evidence['evidence_id'], source_id),
        )
    return {
        'source_id': source_id,
        'evidence_id': evidence['evidence_id'],
        'cache_hit': False,
        'embedded_sections': len(prepared),
        'elapsed_ms': round((perf_counter() - started) * 1000, 3),
    }


def _sources(con, scope, filters):
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM received_document_v1 WHERE scope=? AND state='ACTIVE' ORDER BY source_id",
        (scope,),
    ).fetchall()
    selected = []
    for row in rows:
        meta = json.loads(row['manifest_json'])
        if all(meta.get(key) == value for key, value in filters.items()):
            selected.append(row)
    return selected


def _supporting_parts(text, section, chunk_start, chunk_end):
    start, end = section['start_offset'], section['end_offset']
    if end - start <= 3000:
        ranges = [(start, end)]
    else:
        ranges = [
            (start, min(start + 600, end)),
            (max(start, chunk_start - 300), min(end, chunk_end + 300)),
        ]
    merged = []
    for a, b in sorted(ranges):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(b, merged[-1][1]))
        else:
            merged.append((a, b))
    shown = [
        {'start': a, 'end': b, 'text': text[a:b], 'sha256': sha256(text[a:b].encode()).hexdigest()}
        for a, b in merged
    ]
    missing = []
    position = start
    for a, b in merged:
        if position < a:
            missing.append({'start': position, 'end': a})
        position = b
    if position < end:
        missing.append({'start': position, 'end': end})
    return shown, missing


def verify_hit_binding(con, hit, scope):
    source, meta = _read_source(con, hit['source_id'], scope)
    if any(
        key in hit and hit[key] != meta[key]
        for key in ('source_ref', 'title', 'source_kind', 'document_state', 'product', 'version')
    ):
        raise ValueError('DOCUMENT_CITATION_METADATA_CHANGED')
    section = con.execute(
        'SELECT * FROM received_section_v1 WHERE section_id=? AND source_id=?',
        (hit['section_id'], hit['source_id']),
    ).fetchone()
    if not section:
        raise ValueError('DOCUMENT_SECTION_MISSING')
    expected_span = meta['sections'][section['ordinal']]
    if (
        section['start_offset'] != expected_span['start']
        or section['end_offset'] != expected_span['end']
        or json.loads(section['heading_json']) != expected_span['heading_path']
        or section['section_id'] != 'SEC_' + data_digest([source['source_id'], expected_span])[:32]
    ):
        raise ValueError('DOCUMENT_SECTION_CHANGED')
    parent = con.execute('SELECT * FROM rag_docs WHERE doc_id=?', (hit['section_id'],)).fetchone()
    if (
        not parent
        or parent['scope'] != source['index_scope']
        or parent['status'] != 'ACTIVE'
        or parent['title'] != meta['title'] + ' / ' + ' / '.join(expected_span['heading_path'])
        or parent['source_ref'] != meta['source_ref']
        or parent['embedding_model'] != meta['configuration']['embedding_model']
    ):
        raise ValueError('DOCUMENT_INDEX_METADATA_CHANGED')
    chunk = con.execute(
        'SELECT * FROM rag_chunks WHERE chunk_id=? AND doc_id=?',
        (hit['chunk_id'], hit['section_id']),
    ).fetchone()
    if not chunk:
        raise ValueError('DOCUMENT_CHUNK_MISSING')
    sealed = next(
        (x for x in json.loads(section['chunks_json']) if x['chunk_id'] == hit['chunk_id']), None
    )
    if (
        not sealed
        or sha256(chunk['chunk_text'].encode()).hexdigest() != sealed['text_sha256']
        or sha256(chunk['embedding_json'].encode()).hexdigest() != sealed['vector_sha256']
        or hit['vector_sha256'] != sealed['vector_sha256']
    ):
        raise ValueError('DOCUMENT_INDEX_CHANGED')
    if (
        hit['source_sha256'] != meta['raw_sha256']
        or hit['manifest_sha256'] != source['manifest_sha256']
    ):
        raise ValueError('DOCUMENT_SOURCE_BINDING_CHANGED')
    text = source['text_data']
    content = text[section['start_offset'] : section['end_offset']]
    number = int(hit['chunk_id'].rsplit(':', 1)[1])
    expected = split_text(content)[number]
    start = section['start_offset'] + len(content) - len(content.lstrip()) + number * 420
    if (
        hit['start'] != start
        or hit['end'] != start + len(expected)
        or text[hit['start'] : hit['end']] != expected
        or hit['excerpt'] != expected
        or hit['chunk_sha256'] != sha256(expected.encode()).hexdigest()
        or hit['heading_path'] != json.loads(section['heading_json'])
    ):
        raise ValueError('DOCUMENT_EXCERPT_BINDING_CHANGED')
    if 'supporting_parts' in hit:
        parts, missing = _supporting_parts(text, section, hit['start'], hit['end'])
        if hit['supporting_parts'] != parts or hit['unshown_section_ranges'] != missing:
            raise ValueError('DOCUMENT_CONTEXT_BINDING_CHANGED')
    return meta


def verify_source_index(con, source_id, scope):
    source, meta = _read_source(con, source_id, scope)
    stored = con.execute(
        'SELECT * FROM received_section_v1 WHERE source_id=? ORDER BY ordinal', (source_id,)
    ).fetchall()
    expected = [s for s in meta['sections'] if source['text_data'][s['start'] : s['end']].strip()]
    if len(stored) != len(expected):
        raise ValueError('DOCUMENT_INDEX_COVERAGE_CHANGED')
    for section in stored:
        content = source['text_data'][section['start_offset'] : section['end_offset']]
        chunks = split_text(content)
        seals = json.loads(section['chunks_json'])
        actual = con.execute(
            'SELECT COUNT(*) FROM rag_chunks WHERE doc_id=?', (section['section_id'],)
        ).fetchone()[0]
        if len(seals) != len(chunks) or actual != len(chunks):
            raise ValueError('DOCUMENT_INDEX_COVERAGE_CHANGED')
        for seal in seals:
            number = int(seal['chunk_id'].rsplit(':', 1)[1])
            text = chunks[number]
            start = section['start_offset'] + len(content) - len(content.lstrip()) + number * 420
            verify_hit_binding(
                con,
                {
                    'source_id': source_id,
                    'section_id': section['section_id'],
                    'chunk_id': seal['chunk_id'],
                    'source_sha256': meta['raw_sha256'],
                    'manifest_sha256': source['manifest_sha256'],
                    'start': start,
                    'end': start + len(text),
                    'excerpt': text,
                    'heading_path': json.loads(section['heading_json']),
                    'chunk_sha256': sha256(text.encode()).hexdigest(),
                    'vector_sha256': seal['vector_sha256'],
                },
                scope,
            )


def search_received(
    db,
    query,
    *,
    scope,
    embeddings,
    embedding_model,
    model_fingerprint,
    top_k=5,
    filters=None,
    source_ids=None,
):
    started = perf_counter()
    filters = filters or {}
    if not isinstance(query, str) or not query.strip() or type(top_k) is not int or top_k < 1:
        raise ValueError('DOCUMENT_QUERY_INVALID')
    if set(filters) - {'product', 'version', 'source_kind', 'document_state'}:
        raise ValueError('DOCUMENT_FILTER_INVALID')
    init_documents(db)
    with closing(connect(db)) as con:
        source_rows = _sources(con, scope, filters)
    if source_ids is not None:
        if not isinstance(source_ids, (list, tuple)) or any(
            not isinstance(s, str) for s in source_ids
        ):
            raise ValueError('DOCUMENT_SOURCE_SELECTION_INVALID')
        selected = set(source_ids)
        if selected - {r['source_id'] for r in source_rows}:
            raise PermissionError('DOCUMENT_SOURCE_SELECTION_SCOPE_OR_STATE_MISMATCH')
        source_rows = [r for r in source_rows if r['source_id'] in selected]
    for row in source_rows:
        configuration = json.loads(row['manifest_json'])['configuration']
        if (
            configuration['embedding_model'] != embedding_model
            or configuration['model_fingerprint'] != model_fingerprint
        ):
            raise ValueError('DOCUMENT_MODEL_INDEX_VERSION_MISMATCH')

    # Reuse the existing RAG ranker per metadata partition; compute the query vector once.
    class QueryVector:
        def __init__(self):
            self.value = None

        def embed_query(self, text):
            if self.value is None:
                self.value = embeddings.embed_query(text)
            return self.value

    provider = QueryVector()
    found = {}
    for partition in sorted({r['index_scope'] for r in source_rows}):
        for item in search_documents(
            query,
            embeddings=provider,
            embedding_model=embedding_model,
            scope=partition,
            top_k=None,
            db_path=db,
        ):
            found[item['chunk_id']] = item
    candidates = list(found.values())
    vector_rank = {
        x['chunk_id']: i
        for i, x in enumerate(sorted(candidates, key=lambda x: (-x['cosine'], x['chunk_id'])), 1)
    }
    lexical_rank = {
        x['chunk_id']: i
        for i, x in enumerate(
            sorted(
                (x for x in candidates if x['lexical_score'] > 0),
                key=lambda x: (-x['lexical_score'], x['chunk_id']),
            ),
            1,
        )
    }
    candidates.sort(
        key=lambda x: (
            -(
                1 / (60 + vector_rank[x['chunk_id']])
                + (1 / (60 + lexical_rank[x['chunk_id']]) if x['chunk_id'] in lexical_rank else 0)
            ),
            x['chunk_id'],
        )
    )
    hits = []
    allowed = {r['source_id'] for r in source_rows}
    seen_sections = set()
    with closing(connect(db)) as con:
        con.row_factory = sqlite3.Row
        for item in candidates:
            if item['doc_id'] in seen_sections:
                continue
            section = con.execute(
                'SELECT * FROM received_section_v1 WHERE section_id=?', (item['doc_id'],)
            ).fetchone()
            if not section or section['source_id'] not in allowed:
                continue
            source, meta = _read_source(con, section['source_id'], scope)
            text = source['text_data']
            content = text[section['start_offset'] : section['end_offset']]
            start = (
                section['start_offset']
                + len(content)
                - len(content.lstrip())
                + int(item['chunk_id'].rsplit(':', 1)[1]) * 420
            )
            hit = {
                'source_id': source['source_id'],
                'section_id': item['doc_id'],
                'chunk_id': item['chunk_id'],
                'source_ref': meta['source_ref'],
                'title': meta['title'],
                'source_kind': meta['source_kind'],
                'document_state': meta['document_state'],
                'product': meta['product'],
                'version': meta['version'],
                'heading_path': json.loads(section['heading_json']),
                'start': start,
                'end': start + len(item['text']),
                'excerpt': item['text'],
                'chunk_sha256': sha256(item['text'].encode()).hexdigest(),
                'source_sha256': meta['raw_sha256'],
                'manifest_sha256': source['manifest_sha256'],
                'vector_sha256': next(
                    x['vector_sha256']
                    for x in json.loads(section['chunks_json'])
                    if x['chunk_id'] == item['chunk_id']
                ),
                'cosine': item['cosine'],
                'lexical_score': item['lexical_score'],
                'rank': len(hits) + 1,
            }
            parts, missing = _supporting_parts(text, section, hit['start'], hit['end'])
            hit.update(
                supporting_parts=parts,
                unshown_section_ranges=missing,
                context_coverage=(
                    'WHOLE_SECTION' if not missing else 'SECTION_LEAD_AND_MATCH_WINDOW'
                ),
            )
            verify_hit_binding(con, hit, scope)
            hits.append(hit)
            seen_sections.add(item['doc_id'])
            if len(hits) == top_k:
                break
    payload = {
        'query': query,
        'filters': filters,
        'embedding_model': embedding_model,
        'model_fingerprint': model_fingerprint,
        'source_ids': sorted(allowed),
        'retrieval_code_sha256': sha256(
            (inspect.getsource(search_received) + inspect.getsource(_supporting_parts)).encode()
        ).hexdigest(),
        'hits': hits,
        'elapsed_ms': round((perf_counter() - started) * 1000, 3),
        'query_embedding_calls': int(provider.value is not None),
        'status': 'RETRIEVAL_ONLY' if hits else 'NO_COMPATIBLE_RECEIVED_MATERIAL',
        'answer_generated': False,
        'approval_granted': False,
    }
    if source_ids is not None:
        payload['source_selection'] = sorted(set(source_ids))
    evidence = save_evidence(
        adapter=ADAPTER,
        source='domain-local-received-documents',
        scope=scope,
        payload=payload,
        db_path=db,
    )
    return {**payload, 'evidence_id': evidence['evidence_id']}


def verify_search_evidence(con, evidence_id, scope):
    con.row_factory = sqlite3.Row
    row = con.execute('SELECT * FROM evidence WHERE evidence_id=?', (evidence_id,)).fetchone()
    if not row or row['scope'] != scope or row['adapter'] != ADAPTER:
        raise PermissionError('DOCUMENT_SEARCH_EVIDENCE_SCOPE_MISMATCH')
    payload = json.loads(row['payload_json'])
    current_sources = _sources(con, scope, payload['filters'])
    if 'source_selection' in payload:
        if sorted(set(payload['source_selection'])) != payload['source_ids']:
            raise ValueError('DOCUMENT_SOURCE_SELECTION_CHANGED')
        current_sources = [
            r for r in current_sources if r['source_id'] in payload['source_selection']
        ]
    if sorted(r['source_id'] for r in current_sources) != payload['source_ids']:
        raise ValueError('DOCUMENT_CORPUS_VERSION_CHANGED')
    for source in current_sources:
        configuration = json.loads(source['manifest_json'])['configuration']
        if (configuration['embedding_model'], configuration['model_fingerprint']) != (
            payload['embedding_model'],
            payload['model_fingerprint'],
        ):
            raise ValueError('DOCUMENT_MODEL_INDEX_VERSION_MISMATCH')
    for hit in payload['hits']:
        if hit['source_id'] not in payload['source_ids']:
            raise ValueError('DOCUMENT_SOURCE_SELECTION_CHANGED')
        verify_hit_binding(con, hit, scope)
    return payload


def source_context(hit, number):
    """Preserve a verified RAG hit's fields; selection and provenance stay upstream."""
    return {
        "id": "P" + str(number),
        "source_id": hit["source_id"],
        "section_id": hit["section_id"],
        "source_ref": hit["source_ref"],
        "source_kind": hit["source_kind"],
        "version": hit["version"],
        "document_state": hit["document_state"],
        "heading_path": copy.deepcopy(hit["heading_path"]),
        "context_parts": copy.deepcopy(hit["supporting_parts"]),
        "unshown_section_ranges": copy.deepcopy(hit["unshown_section_ranges"]),
    }
