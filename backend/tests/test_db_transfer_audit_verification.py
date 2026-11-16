"""Canonical response audit-chain validation during synthetic transfer."""
from __future__ import annotations

import json

import pytest
from sqlalchemy import Column, Integer, MetaData, Table, Text, create_engine, insert, select

from app.response.audit_chain import GENESIS_HASH, calculate_event_hash
from app.db_transfer_rehearsal import transfer_synthetic_tables


def _tables():
    metadata = MetaData()
    audit = Table(
        "response_audit_log",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("response_id", Integer, nullable=False),
        Column("alert_id", Integer, nullable=False),
        Column("event", Text, nullable=False),
        Column("actor", Text, nullable=False),
        Column("details", Text, nullable=False),
        Column("created_at", Text, nullable=False),
        Column("previous_hash", Text, nullable=False),
        Column("event_hash", Text, nullable=False),
    )
    heads = Table(
        "response_audit_chain_heads",
        metadata,
        Column("response_id", Integer, primary_key=True),
        Column("event_count", Integer, nullable=False),
        Column("final_hash", Text, nullable=False),
        Column("updated_at", Text, nullable=False),
    )
    return metadata, audit, heads


def _valid_rows():
    events = [
        {
            "id": 1,
            "response_id": 7,
            "alert_id": 11,
            "event": "response_request_created",
            "actor": "synthetic-analyst",
            "details": {"action": "block_ip", "target": "198.51.100.7"},
            "created_at": "2026-11-17T10:00:00+00:00",
            "previous_hash": GENESIS_HASH,
        },
        {
            "id": 2,
            "response_id": 7,
            "alert_id": 11,
            "event": "response_approved",
            "actor": "synthetic-approver",
            "details": {"decision": "approved", "executed": False},
            "created_at": "2026-11-17T10:01:00+00:00",
            "previous_hash": None,
        },
    ]
    events[0]["event_hash"] = calculate_event_hash(events[0], GENESIS_HASH)
    events[1]["previous_hash"] = events[0]["event_hash"]
    events[1]["event_hash"] = calculate_event_hash(
        events[1], events[1]["previous_hash"]
    )
    stored = [
        {
            **event,
            "details": json.dumps(
                event["details"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ),
        }
        for event in events
    ]
    head = {
        "response_id": 7,
        "event_count": 2,
        "final_hash": events[-1]["event_hash"],
        "updated_at": "2026-11-17T10:01:00+00:00",
    }
    return stored, head


def _connections():
    metadata, audit, heads = _tables()
    source_engine = create_engine("sqlite:///:memory:")
    destination_engine = create_engine("sqlite:///:memory:")
    metadata.create_all(source_engine)
    metadata.create_all(destination_engine)
    return metadata, audit, heads, source_engine, destination_engine


def test_transfer_accepts_valid_canonical_audit_chain():
    metadata, audit, heads, source_engine, destination_engine = _connections()
    events, head = _valid_rows()
    try:
        with source_engine.begin() as source:
            source.execute(insert(audit), events)
            source.execute(insert(heads), head)
        with source_engine.connect() as source, destination_engine.connect() as destination:
            manifest = transfer_synthetic_tables(source, destination, [audit, heads])
        assert manifest["response_audit_log"]["row_count"] == 2
        assert manifest["response_audit_chain_heads"]["row_count"] == 1
    finally:
        source_engine.dispose()
        destination_engine.dispose()


@pytest.mark.parametrize("tamper", ["event", "head", "missing_head"])
def test_transfer_rejects_invalid_audit_evidence_before_copy(tamper):
    metadata, audit, heads, source_engine, destination_engine = _connections()
    events, head = _valid_rows()
    if tamper == "event":
        events[1]["actor"] = "tampered-actor"
    elif tamper == "head":
        head["final_hash"] = "f" * 64
    else:
        head = None

    try:
        with source_engine.begin() as source:
            source.execute(insert(audit), events)
            if head is not None:
                source.execute(insert(heads), head)
        with source_engine.connect() as source, destination_engine.connect() as destination:
            with pytest.raises(ValueError, match="response audit"):
                transfer_synthetic_tables(source, destination, [audit, heads])
            assert destination.execute(select(audit)).mappings().all() == []
            assert destination.execute(select(heads)).mappings().all() == []
    finally:
        source_engine.dispose()
        destination_engine.dispose()
