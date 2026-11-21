"""Shared artifact guards work without loading the retired review writers."""

from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import json, os, subprocess, sys, unittest

from ILA_ECA_REAL_DISCOVERY_LAB.core import artifacts
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import init_db, connect
from ILA_ECA_REAL_DISCOVERY_LAB.knowledge import intake
from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.index import OfflineHashEmbedding


class SharedArtifactBoundaryTests(unittest.TestCase):
    def test_current_entries_load_with_source_review_module_unavailable(self):
        app = Path(os.environ["ILA_ECA_TEST_APP_ROOT"])
        code = """import sys,importlib.abc
sys.path[:0]=sys.argv[1:]
class BlockHistoricalReview(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname == 'ILA_ECA_REAL_DISCOVERY_LAB.knowledge.review':
   raise AssertionError('Unrelated source-review module loaded')
sys.meta_path.insert(0,BlockHistoricalReview())
from ILA_ECA_REAL_DISCOVERY_LAB import run_structured_design_v2,run_web_ui
from ILA_ECA_REAL_DISCOVERY_LAB.design import aws,non_aws,route_documents
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration import gitlab
from ILA_ECA_REAL_DISCOVERY_LAB.incident import artifacts
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import document_paths,valid_document_id
assert valid_document_id('DESIGN-ONE')
assert 'ILA_ECA_REAL_DISCOVERY_LAB.knowledge.review' not in sys.modules
print('SHARED_ARTIFACTS_WITHOUT_REVIEW_WRITERS')
"""
        result = subprocess.run(
            [sys.executable, "-I", "-c", code, str(app), str(app.parent / "runtime_deps")],
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SHARED_ARTIFACTS_WITHOUT_REVIEW_WRITERS", result.stdout)

    def test_shared_paths_and_identifiers_keep_original_boundaries(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "audit.sqlite3"
            md, structured = artifacts.document_paths(db, "documents/revision1.md")
            self.assertEqual(md, root.resolve() / "documents/revision1.md")
            self.assertEqual(structured, md.with_suffix(".json"))
            for path in ("../outside.md", str(root.parent / "outside.md")):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "PATH_INVALID"):
                    artifacts.document_paths(db, path)
            for name in (".", "..", "../design", "a/b", "", None):
                with self.subTest(name=name):
                    self.assertFalse(artifacts.valid_document_id(name))
            self.assertTrue(artifacts.valid_document_id("DESIGN-01:r2"))

    def test_historical_review_still_checks_source_scope_content_and_hash(self):
        # Recreate a stored historical artifact, without bringing its removed
        # writer back into runtime or routing current generation through it.
        from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.review import _data

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "audit.sqlite3"
            init_db(db)
            source = root / "synthetic.md"
            source.write_text(
                "# Synthetic reference\nKeep original configuration for rollback.\n", "utf8"
            )
            embedding = OfflineHashEmbedding()
            received = intake.ingest_file(
                db,
                source,
                scope="lab",
                source_ref="fixture://synthetic",
                title="Synthetic reference",
                format="markdown",
                source_kind="TECHNICAL_REFERENCE",
                version="1",
                document_state="REFERENCE_NOT_LIVE",
                embeddings=embedding,
                embedding_model="fixture",
                model_fingerprint="fixture",
            )
            found = intake.search_received(
                db,
                "rollback configuration",
                scope="lab",
                embeddings=embedding,
                embedding_model="fixture",
                model_fingerprint="fixture",
            )
            relative = "document_reviews/historical.md"
            md, data_path = artifacts.document_paths(db, relative)
            md.parent.mkdir(parents=True)
            with closing(connect(db)) as con, con:
                con.execute("BEGIN IMMEDIATE")
                artifacts.init_registry(con)
                data = _data(
                    con,
                    "OLD-REVIEW",
                    1,
                    "lab",
                    "Historical synthetic review",
                    [received["source_id"]],
                    [found["evidence_id"]],
                    ["Not approved"],
                    None,
                )
                content, metadata = artifacts.render_template(
                    b"$body", {"body": "Historical synthetic draft"}, template_version="fixture"
                )
                md.write_bytes(content)
                data_path.write_text(artifacts.canonical_json(data), "utf8")
                record = artifacts.register_document(
                    con,
                    domain_id="lab",
                    design_id="OLD-REVIEW",
                    document_kind="RECEIVED_DOCUMENT_REVIEW",
                    content=content,
                    structured_data=data,
                    render_metadata=metadata,
                    relative_path=relative,
                )
                result = artifacts.verify_attached_document_from_connection(
                    con, db, "OLD-REVIEW", 1, "lab"
                )
                self.assertEqual(result["record"], record)
                with self.assertRaises(ValueError):
                    artifacts.verify_attached_document_from_connection(
                        con, db, "OLD-REVIEW", 1, "other-scope"
                    )
                md.write_bytes(content + b" altered")
                with self.assertRaises(ValueError):
                    artifacts.verify_attached_document_from_connection(
                        con, db, "OLD-REVIEW", 1, "lab"
                    )


class SharedPolicyTests(unittest.TestCase):
    def test_json_policies_reject_nested_duplicates_and_nonfinite_constants_with_original_reasons(
        self,
    ):
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.cloud import parse

        for raw in ('{"x":1,"x":2}', '{"a":{"x":1,"x":2}}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(
                ValueError, "CLOUD_DUPLICATE_JSON_KEY"
            ):
                parse(raw)
        for raw in ('{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "CLOUD_NONFINITE_JSON"):
                parse(raw)
        for boundary in ("HTTP", "CLI"):
            with self.assertRaisesRegex(ValueError, boundary + "_DUPLICATE"):
                artifacts.parse_json(
                    '{"x":1,"x":2}',
                    duplicate_error=boundary + "_DUPLICATE",
                    nonfinite_error=boundary + "_NONFINITE",
                )
        self.assertEqual(
            parse('{"zero":0,"no":false,"large":9007199254740993}'),
            {"zero": 0, "no": False, "large": 9007199254740993},
        )

    def test_shared_model_structure_rejects_invalid_fields_types_lengths_and_enum_without_editing(
        self,
    ):
        import copy

        rule = {
            "type": "object",
            "required": ["name", "enabled", "items"],
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 4, "enum": ["ab"]},
                "enabled": {"type": "boolean"},
                "items": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 2,
                    "items": [{"type": "string"}, {"type": "boolean"}],
                },
            },
        }
        valid = {"name": "ab", "enabled": False, "items": ["zero", False]}
        before = copy.deepcopy(valid)
        artifacts.validate_model_shape(valid, rule, error_prefix="ROUTE_MODEL")
        self.assertEqual(valid, before)
        cases = [
            ({"name": "ab"}, "FIELDS"),
            ({**valid, "enabled": 1}, "BOOLEAN"),
            ({**valid, "name": ""}, "TEXT"),
            ({**valid, "name": "cd"}, "ENUM"),
            ({**valid, "items": []}, "ARRAY"),
            ({**valid, "items": ["x", 0]}, "BOOLEAN"),
        ]
        for value, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(
                ValueError, "ROUTE_MODEL_" + reason + "_INVALID"
            ):
                artifacts.validate_model_shape(value, rule, error_prefix="ROUTE_MODEL")
        with self.assertRaisesRegex(ValueError, "DESIGN_FIELDS_INVALID"):
            artifacts.validate_model_shape(
                [], {"type": "object", "required": [], "properties": {}}, error_prefix="DESIGN"
            )

    def test_shared_inputs_and_generation_contracts_match_saved_pre_refactor_values(self):
        import copy, inspect
        from hashlib import sha256
        from unittest.mock import patch
        from ILA_ECA_REAL_DISCOVERY_LAB.design import non_aws as a, context_routes as c
        from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.intake import source_context

        golden = json.loads(
            (Path(__file__).parents[1] / "fixtures/shared_policy_contracts.json").read_text("utf8")
        )

        def hit(letter):
            return {
                "source_id": letter,
                "section_id": letter + "-section",
                "source_ref": "fixture://" + letter,
                "source_kind": "TECHNICAL_REFERENCE",
                "version": "1",
                "document_state": "REFERENCE_NOT_LIVE",
                "heading_path": ["Context"],
                "supporting_parts": [{"start": 0, "end": 4, "text": "zero", "flags": [0, False]}],
                "unshown_section_ranges": [],
            }

        searches = {"q1": {"hits": [hit("A"), hit("B")]}, "q2": {"hits": [hit("C"), hit("A")]}}
        task = {
            "id": "TASK-ONE",
            "kind": "CHANGE",
            "goal": "synthetic contract",
            "constraints": [],
            "input_unknowns": [],
        }
        with patch.object(
            a,
            "verify_search_evidence",
            side_effect=lambda con, eid, scope: copy.deepcopy(searches[eid]),
        ):
            packet = a.source_packet(None, "lab", task, ["q1", "q2"])
        self.assertEqual(artifacts.data_digest(packet), golden["A_packet_sha256"])
        self.assertEqual([x["source_id"] for x in packet["sources"]], ["A", "C", "B"])

        class Row:
            def __init__(self, eid):
                self.eid = eid

            def fetchone(self):
                return {"evidence_id": self.eid, "scope": "lab", "value": self.eid}

        class Connection:
            def execute(self, sql, args):
                return Row(args[0])

            def close(self):
                pass

        with patch.object(c, "connect", return_value=Connection()), patch.object(
            c,
            "verify_search_evidence",
            side_effect=lambda con, eid, scope: copy.deepcopy(searches[eid]),
        ):
            sources = c._received_sources("unused", "lab", ["q1", "q2"])
        self.assertEqual(artifacts.data_digest(sources), golden["D_sources_sha256"])
        self.assertEqual([x["source_id"] for x in sources["sources"]], ["A", "B", "C"])
        captured = {}

        def record(**kwargs):
            captured[kwargs["route"]] = {
                "instruction": kwargs["instruction"],
                "schema": kwargs["schema"],
                "input": kwargs["input_data"],
            }
            return {"status": "HOLD", "value": None, "actual_llm_calls": 0}

        with patch.object(c, "infer", side_effect=record), patch.object(
            c, "_received_sources", return_value=sources
        ), patch.object(c, "_security_sources", return_value=[]):
            c.question(
                "unused",
                scope="lab",
                request_id="D-ONE",
                query="synthetic question",
                evidence_ids=["q1", "q2"],
            )
            c.security(
                "unused",
                scope="lab",
                request_id="H-ONE",
                symptom="synthetic report",
                evidence_ids=[],
                unknowns=[],
            )
        for route in ("D", "H"):
            self.assertEqual(
                artifacts.data_digest(captured[route]), golden[route + "_contract_sha256"]
            )
        self.assertEqual(artifacts.data_digest(a.schema()), golden["A_schema_sha256"])
        self.assertEqual(
            sha256(inspect.getsource(a.generate_design).encode()).hexdigest(),
            golden["A_generate_source_sha256"],
        )
        original = hit("A")
        context = source_context(original, 1)
        context["context_parts"][0]["flags"].append("changed")
        self.assertEqual(original["supporting_parts"][0]["flags"], [0, False])

    def test_job_projection_uses_recorded_hold_and_failure_with_no_invented_completion(self):
        from ILA_ECA_REAL_DISCOVERY_LAB.webapp.portal import job_result_category

        self.assertEqual(
            job_result_category({"state": "FINISHED", "result_summary": {"status": "HOLD"}}),
            "WAITING_INFORMATION",
        )
        self.assertEqual(
            job_result_category({"state": "FINISHED", "outcome": "HOLD", "result_summary": {}}),
            "WAITING_INFORMATION",
        )
        self.assertEqual(
            job_result_category(
                {
                    "state": "FINISHED",
                    "outcome": "HOLD",
                    "result_summary": {"call": {"error_code": "BROKEN"}},
                }
            ),
            "FAILED",
        )
        for state in ("RUNNING", "RESULT_UNKNOWN", "CANCELED"):
            self.assertEqual(job_result_category({"state": state}), state)

    def test_nested_secret_checks_retain_policy_without_repeated_whole_subtree_scans(self):
        from unittest.mock import patch
        from ILA_ECA_REAL_DISCOVERY_LAB.webapp import portal
        from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import safe

        value = {
            "items": [{"text": "synthetic", "zero": 0, "no": False} for _ in range(100)],
            "parameters": {"password": "${var.password}"},
        }
        with patch.object(portal, "safe", wraps=safe) as scan:
            self.assertIs(portal.checked(value), value)
            scan.assert_called_once_with(value)
        invalid = [
            ({"nested": [{"api_key": "synthetic"}]}, "SECRET_VALUE_NOT_ALLOWED"),
            (
                {"nested": ["https://user:pass@synthetic.invalid/path"]},
                "URL_CREDENTIAL_NOT_ALLOWED",
            ),
            ({"nested": ["token=synthetic"]}, "SERVICE_SECRET_MATERIAL_DENIED"),
        ]
        for value, reason in invalid:
            with self.subTest(reason=reason), self.assertRaisesRegex(PermissionError, reason):
                portal.checked(value)


if __name__ == "__main__":
    unittest.main()
