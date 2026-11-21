"""No network/model calls. Check fail-closed transport, replay and document bindings."""

from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
import base64, copy, json, sqlite3, unittest
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import init_db
from ILA_ECA_REAL_DISCOVERY_LAB.llm import cloud as cloud
from ILA_ECA_REAL_DISCOVERY_LAB.design import route_documents as docs
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import load_evidence


class CloudGenerationTests(unittest.TestCase):
    def test_http_transport_preserves_original_safe_error_body(self):
        from io import BytesIO
        from urllib.error import HTTPError

        raw = b'{"error":{"code":"invalid_api_key"}}'
        opener = Mock()
        opener.open.side_effect = HTTPError(cloud.ENDPOINT, 401, 'Unauthorized', {}, BytesIO(raw))
        with patch('urllib.request.build_opener', return_value=opener):
            status, body = cloud.OpenAITransport(lambda: 'synthetic-credential-never-sent')(b'{}')
        self.assertEqual(status, 401)
        self.assertEqual(body, raw)
        opener.open.assert_called_once()

    def test_http_transport_rejects_echoed_credential_without_logging_it(self):
        from io import BytesIO
        from urllib.error import HTTPError

        credential = 'synthetic-credential-never-sent'
        opener = Mock()
        opener.open.side_effect = HTTPError(
            cloud.ENDPOINT, 401, 'Unauthorized', {}, BytesIO(credential.encode())
        )
        with patch('urllib.request.build_opener', return_value=opener):
            with self.assertRaisesRegex(
                ValueError, 'CLOUD_HTTP_BODY_CONTAINS_CREDENTIAL_NOT_SAVED'
            ):
                cloud.OpenAITransport(lambda: credential)(b'{}')

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / 'audit.sqlite3'
        init_db(self.db)
        self.request = cloud.request_for(
            {'text': '元の項目12台\r\n全文'}, [{'text': '技術仕様全文'}]
        )
        self.auth = {
            'schema': 'ila.eca.cloud-export-authorization.v1',
            'scope': 'lab',
            'request_id': 'G-X',
            'endpoint': cloud.ENDPOINT,
            'model': cloud.MODEL,
            'request_sha256': data_digest(self.request),
            'approved_by': 'TEST_OPERATOR_NOT_ENTERPRISE_APPROVAL',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            'classification': 'SYNTHETIC_ONLINE',
            'external_send_permitted': True,
        }
        self.env = {
            'status': 'completed',
            'error': None,
            'incomplete_details': None,
            'model': cloud.MODEL,
            'service_tier': 'default',
            'output': [
                {
                    'type': 'message',
                    'role': 'assistant',
                    'status': 'completed',
                    'content': [{'type': 'output_text', 'text': '\r\n# 未承認\r\n'}],
                }
            ],
            'usage': {
                'input_tokens': 100,
                'output_tokens': 50,
                'input_tokens_details': {'cached_tokens': 0},
            },
        }
        self.transport = Mock(side_effect=lambda _: (200, json.dumps(self.env).encode()))

    def runtime(self):
        return cloud.CloudRuntime(self.auth, self.transport, 'MOCK')

    def call(self):
        return cloud.infer_cloud(
            self.db, scope='lab', request_id='G-X', request=self.request, runtime=self.runtime()
        )

    def test_full_text_and_common_registry(self):
        r = self.call()
        self.assertEqual(r['status'], 'GENERATED')
        self.assertEqual(r['value'], '\r\n# 未承認\r\n')
        doc = docs.create_route_document(
            self.db, scope='lab', route='G', request_id='G-X', result=r
        )
        self.assertFalse(doc['data']['approval_granted'])
        self.assertIn(r['value'].encode(), Path(doc['path']).read_bytes())
        self.assertEqual(json.loads(self.transport.call_args.args[0]), self.request)
        self.assertEqual(r['actual_llm_calls'], 0)
        self.assertFalse(r['external_llm_used'])

    def test_replay_never_resends_or_reserves(self):
        a = self.call()
        b = self.call()
        self.transport.assert_called_once()
        self.assertEqual(a['evidence_id'], b['evidence_id'])

    def test_scope_denied(self):
        with self.assertRaises(PermissionError):
            cloud.infer_cloud(
                self.db,
                scope='closed',
                request_id='G-X',
                request=self.request,
                runtime=self.runtime(),
            )
        self.transport.assert_not_called()

    def test_changed_payload_denied(self):
        self.request['input'][1]['content'] += 'changed'
        with self.assertRaises(PermissionError):
            self.call()
        self.transport.assert_not_called()

    def test_changed_request_id_reuse_denied(self):
        self.call()
        self.request['input'][1]['content'] += 'changed'
        self.auth['request_sha256'] = data_digest(self.request)
        with self.assertRaises(ValueError):
            self.call()
        self.transport.assert_called_once()

    def test_closed_classification_denied(self):
        self.auth['classification'] = 'CLOSED_PRIVATE'
        with self.assertRaises(PermissionError):
            self.call()
        self.transport.assert_not_called()

    def test_no_authorization(self):
        self.auth.clear()
        with self.assertRaises(PermissionError):
            self.call()
        self.transport.assert_not_called()

    def test_expired_authorization(self):
        self.auth['expires_at'] = '2000-01-01T00:00:00+00:00'
        with self.assertRaises(PermissionError):
            self.call()
        self.transport.assert_not_called()

    def test_model_tools_truncation_cannot_change(self):
        for k, v in [
            ('model', 'gpt-6.2-astra'),
            ('truncation', 'auto'),
            ('tools', [{'type': 'web_search'}]),
            ('stream', True),
        ]:
            old = self.request[k]
            self.request[k] = v
            with self.assertRaises(ValueError):
                self.call()
            self.request[k] = old
        self.transport.assert_not_called()

    def test_runtime_does_not_require_or_create_a_budget_database(self):
        self.assertEqual(self.call()['status'], 'GENERATED')
        self.assertFalse((self.root / 'budget.sqlite3').exists())

    def test_timeout_saves_unknown_execution_and_no_resend(self):
        self.transport.side_effect = TimeoutError('secret must not appear')
        r = self.call()
        self.assertEqual(r['dispatch_state'], 'RESULT_UNKNOWN')
        self.assertEqual(r['error_code'], 'TimeoutError')
        self.assertNotIn('secret', json.dumps(r))
        self.call()
        self.transport.assert_called_once()

    def test_http_failure_saves_response_without_resend(self):
        self.transport.side_effect = lambda _: (429, b'')
        r = self.call()
        self.assertEqual(r['status'], 'HOLD')
        self.assertEqual(r['dispatch_state'], 'RESPONSE_RECEIVED')

    def test_incomplete_response_keeps_usage_but_no_draft(self):
        self.env['status'] = 'incomplete'
        self.env['incomplete_details'] = {'reason': 'max_output_tokens'}
        r = self.call()
        self.assertEqual(r['status'], 'HOLD')
        self.assertIsNone(r['value'])
        self.assertEqual(r['dispatch_state'], 'RESPONSE_RECEIVED')

    def test_usage_is_recorded_but_is_not_a_generation_acceptance_condition(self):
        del self.env['usage']
        r = self.call()
        self.assertEqual(r['status'], 'GENERATED')
        self.assertIsNone(r['usage'])
        self.assertNotIn('billing_state', r)

    def test_wrong_model_no_draft(self):
        self.env['model'] = 'other'
        self.assertEqual(self.call()['status'], 'HOLD')

    def test_refusal_no_draft(self):
        self.env['output'][0]['content'] = [{'type': 'refusal', 'refusal': 'no'}]
        self.assertEqual(self.call()['status'], 'HOLD')

    def test_tampered_raw_response_rejected(self):
        r = self.call()
        _, saved = load_evidence(self.db, r['evidence_id'], 'lab')
        row, record = load_evidence(self.db, r['input_evidence_id'], 'lab')
        saved['response_base64'] = base64.b64encode(b'{}').decode()
        with self.assertRaises(ValueError):
            cloud.verify_exchange(saved, record, row)

    def test_rewritten_body_rejected(self):
        r = self.call()
        r['value'] = 'rewritten'
        with self.assertRaises(ValueError):
            docs.create_route_document(self.db, scope='lab', route='G', request_id='G-X', result=r)

    def test_usage_is_preserved_without_price_calculation(self):
        r = self.call()
        self.assertEqual(r['usage'], self.env['usage'])
        self.assertNotIn('budget_request_id', r)
        self.assertNotIn('billing_state', r)

    def test_runtime_configuration_needs_only_export_authorization(self):
        auth = self.root / 'auth.json'
        auth.write_text(json.dumps(self.auth))
        config = self.root / 'runtime.json'
        config.write_text(
            json.dumps({'schema': 'ila.eca.cloud-runtime.v1', 'authorization_path': auth.name})
        )
        runtime = cloud.runtime_from_config(config, key_provider=lambda: 'not-used')
        self.assertEqual(runtime.authorization, self.auth)
        self.assertFalse(hasattr(runtime, 'ledger'))

    def spec(self, provider='OPENAI_SOL'):
        from ILA_ECA_REAL_DISCOVERY_LAB.design.cloud_draft import make_upstream_binding

        self.adoption = self.root / 'adoption.json'
        self.adoption.write_text(
            json.dumps({'recommended_model': 'gpt-6.2-sol', 'status': 'CANDIDATE'})
        )
        return {
            'schema': 'ila.eca.full-route-request.v1',
            'request_id': 'G-X',
            'route': 'G',
            'scope': 'lab',
            'profile': None,
            'payload': {
                'provider': provider,
                'input': {'text': '元の項目12台\r\n全文'},
                'materials': [{'text': '技術仕様全文'}],
                'upstream_binding': make_upstream_binding(self.adoption),
            },
        }

    def test_entry_to_document_and_resume(self):
        from ILA_ECA_REAL_DISCOVERY_LAB.run_structured_design_v2 import dispatch

        spec = self.spec()
        a = dispatch(self.db, spec, cloud_runtime=self.runtime())
        b = dispatch(self.db, spec, cloud_runtime=self.runtime())
        self.assertEqual(a['status'], 'GENERATED')
        self.assertEqual(a['document']['record'], b['document']['record'])
        self.assertFalse(a['result']['human_approved'])
        self.transport.assert_called_once()

    def test_no_runtime_no_implicit_local_fallback(self):
        from ILA_ECA_REAL_DISCOVERY_LAB.run_structured_design_v2 import dispatch

        result = dispatch(self.db, self.spec())
        self.assertEqual(result['status'], 'HOLD')
        self.assertIn('CLOUD_TRUSTED_RUNTIME_REQUIRED', result['result']['error_code'])

    def test_runtime_requires_explicit_provider(self):
        from ILA_ECA_REAL_DISCOVERY_LAB.run_structured_design_v2 import dispatch

        result = dispatch(self.db, self.spec('LOCAL8B'), cloud_runtime=self.runtime())
        self.assertEqual(result['status'], 'HOLD')
        self.transport.assert_not_called()

    def test_cloud_runtime_not_used_for_other_routes(self):
        from ILA_ECA_REAL_DISCOVERY_LAB.run_structured_design_v2 import dispatch

        spec = self.spec()
        spec['route'] = 'F'
        spec['payload'] = {}
        self.assertEqual(dispatch(self.db, spec, cloud_runtime=self.runtime())['status'], 'HOLD')
        self.transport.assert_not_called()

    def test_copying_existing_audit_records_does_not_resend(self):
        self.call()
        new = self.root / 'copy.sqlite3'
        from contextlib import closing

        with closing(sqlite3.connect(self.db)) as source, closing(sqlite3.connect(new)) as target:
            source.backup(target)
        self.db = new
        self.call()
        self.transport.assert_called_once()

    def test_unrelated_request_does_not_share_a_verification_budget_gate(self):
        self.call()
        self.request['input'][1]['content'] += 'another'
        self.auth['request_sha256'] = data_digest(self.request)
        self.auth['request_id'] = 'G-Y'
        result = cloud.infer_cloud(
            self.db, scope='lab', request_id='G-Y', request=self.request, runtime=self.runtime()
        )
        self.assertEqual(result['status'], 'GENERATED')
        self.assertEqual(self.transport.call_count, 2)

    def test_interrupt_saved_and_propagated(self):
        self.transport.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.call()
        self.assertEqual(caught.exception.route_call['dispatch_state'], 'RESULT_UNKNOWN')
        self.call()
        self.transport.assert_called_once()
