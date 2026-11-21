"""Bind existing readers to the single-read loop. No diagnostic routing table."""

from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import ReadOperation


def existing_evidence(operation_id, *, target_ref, selections):
    """Exact original paths, source and receipt times are resolved by evidence_context."""
    return ReadOperation(
        operation_id,
        target_ref,
        'audit://existing-evidence',
        'Read selected original evidence fields',
        lambda _: {'selections': selections},
        basis_type='EXISTING_RECEIPT',
        conditions={'selections': selections},
    )


def discovery_node(operation_id, *, adapter, profile, target_ref):
    """Reuse collect_evidence(subject, profile); no fixed traversal or signal matching."""

    def read(_):
        result = adapter.collect_evidence(target_ref, profile)
        if result is None:
            from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import utc_now

            return {
                'state': 'NOT_OBSERVED',
                'target_ref': target_ref,
                'observed_at': utc_now(),
                'coverage': 'Adapter returned no observation',
                'values': {},
            }
        if result.node != target_ref:
            raise ValueError('READ_ADAPTER_SUBJECT_MISMATCH')
        return {
            'state': 'OBSERVED',
            'target_ref': result.node,
            'observed_at': result.observed_at,
            'coverage': 'Only the fields returned by the existing adapter',
            'values': {
                'fields': result.evidence,
                'observed_kind': result.observed_kind,
                'signal': result.signal,
                'source_ref': result.source_ref,
                'source_sha256': result.sha256,
            },
        }

    return ReadOperation(
        operation_id,
        target_ref,
        'adapter://' + adapter.adapter_id,
        'Collect one configured Discovery target',
        read,
        basis_type='UNVERIFIED_DISCOVERY',
        origin='EXISTING_READ_ONLY_ADAPTER',
    )


def received_search(
    operation_id,
    *,
    db,
    scope,
    target_ref,
    embeddings,
    embedding_model,
    model_fingerprint,
    query=None,
    filters=None,
    top_k=10,
):
    """Reuse the domain-filtered received-document RAG; query is trusted local config."""
    from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.intake import search_received

    def read(context):
        local_query = query or context['investigation'].get('query')
        if not local_query:
            raise ValueError('READ_LOCAL_QUERY_REQUIRED')
        result = search_received(
            db,
            local_query,
            scope=scope,
            embeddings=embeddings,
            embedding_model=embedding_model,
            model_fingerprint=model_fingerprint,
            filters=filters,
            top_k=top_k,
        )
        return {
            'selections': [
                {
                    'evidence_id': result['evidence_id'],
                    'paths': ['/hits'],
                    'subject_ref': target_ref,
                }
            ]
        }

    return ReadOperation(
        operation_id,
        target_ref,
        'rag://received-documents',
        'Search received local documents; not an environment observation',
        read,
        basis_type='REFERENCE',
        origin='DOMAIN_LOCAL_RECEIVED_RAG',
        kind='LOCAL_RAG',
        conditions={
            'scope': scope,
            'query': query,
            'filters': filters,
            'model': embedding_model,
            'fingerprint': model_fingerprint,
            'top_k': top_k,
        },
    )


def readonly_http(operation_id, *, target_ref, url, product, allowed_hosts, allow_remote=False):
    """Use the existing opt-in GET/host/path/redirection guard for one endpoint."""
    from urllib.error import HTTPError
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.product_api import capture

    def read(_):
        try:
            result = capture(url, product, allowed_hosts=allowed_hosts, allow_remote=allow_remote)
        except RuntimeError as exc:
            cause = exc.__context__
            if isinstance(cause, HTTPError) and cause.code in {401, 403}:
                raise PermissionError('READ_ACCESS_DENIED') from None
            raise
        return {
            'state': 'OBSERVED',
            'target_ref': target_ref,
            'observed_at': result['observed_at'],
            'coverage': 'Existing adapter normalized fields only; unverified HTTP receipt',
            'values': {
                'fields': result['fields'],
                'signal': result['signal'],
                'product': result['product'],
                'response_sha256': result['response_sha256'],
                'transport': result['transport'],
            },
        }

    return ReadOperation(
        operation_id,
        target_ref,
        url,
        'Existing guarded HTTP GET only',
        read,
        basis_type='UNVERIFIED_OBSERVATION',
        origin='EXISTING_V19_HTTP_ADAPTER',
        conditions={
            'product': product,
            'allowed_hosts': allowed_hosts,
            'allow_remote': allow_remote,
        },
    )
