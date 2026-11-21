"""Local LangGraph execution; business receipts remain the authority.

Checkpoints contain cursors and opaque references only. Credentials, callbacks,
model inputs and generated documents stay out of graph state. No automatic retry,
cloud tracing, deployment server, or approval decision is introduced here.
"""

from contextlib import closing
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import TypedDict
import json
import sqlite3

from langgraph.graph import StateGraph, START, END
from langgraph.types import Command, interrupt
from langgraph.errors import GraphBubbleUp
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langsmith import tracing_context


class Cursor(TypedDict, total=False):
    reference: str
    stage: str
    failed: bool
    error_type: str


@dataclass
class Execution:
    """Invocation-local values. This object is never passed to the serializer."""

    values: dict = field(default_factory=dict)
    output: object = None
    error: BaseException | None = None

    def node(self, graph, name, function):
        def step(_state):
            if self.error is not None:
                return {"failed": True}
            try:
                function()
                return {"stage": name, "failed": False}
            except GraphBubbleUp:
                raise
            except BaseException as exc:
                # Preserve the original exception for the existing caller's
                # audit, without persisting arbitrary exception text in a graph.
                self.error = exc
                return {"stage": name, "failed": True, "error_type": type(exc).__name__}

        graph.add_node(name, step, retry_policy=None)

    def choose(self, destination):
        if self.error is not None:
            return END
        return destination() if callable(destination) else destination


def reference(family, identity):
    raw = json.dumps(
        ["ila-eca-langgraph-v1", family, identity],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return sha256(raw).hexdigest()


def invoke(graph, db, family, identity, execution, *, limit=128, resume_wait=False):
    """Only an explicitly requested, side-effect-free wait can resume a cursor.

    An interrupted product/model write is reconciled by its original business
    reservation, never by replaying a failed graph node with invoke(None).
    """
    path = Path(db).resolve()
    if not path.is_file():
        raise ValueError("WORKFLOW_EXISTING_DATABASE_REQUIRED")
    ref = reference(family, identity)
    config = {
        "configurable": {"thread_id": ref},
        "recursion_limit": limit,
        "callbacks": [],
        "tags": ["ila-eca-local-workflow"],
    }
    checkpoint = path.with_name(path.stem + ".langgraph.sqlite3")
    if checkpoint.is_symlink() or checkpoint.resolve().parent != path.parent:
        raise PermissionError("WORKFLOW_CHECKPOINT_PATH_DENIED")
    with closing(sqlite3.connect(checkpoint, check_same_thread=False, timeout=30)) as connection:
        saver = SqliteSaver(connection, serde=JsonPlusSerializer(pickle_fallback=False))
        compiled = graph.compile(checkpointer=saver)
        with tracing_context(enabled=False):
            old = compiled.get_state(config) if resume_wait else None
            waiting = bool(
                old and old.next == ("wait",) and any(task.interrupts for task in old.tasks)
            )
            request = (
                Command(resume={"explicit_request": ref})
                if waiting
                else {"reference": ref, "stage": "start", "failed": False, "error_type": ""}
            )
            compiled.invoke(request, config=config, durability="sync")
    if execution.error is not None:
        raise execution.error
    return execution.output


def wait_for_request():
    """A wait is not approval. Its next node rechecks the real business state."""
    interrupt({"state": "WAITING_FOR_EXPLICIT_REQUEST", "approval_granted": False})
