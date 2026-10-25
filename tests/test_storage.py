
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from src.action import AgentAction
from src.storage import EventStorage


@pytest.fixture
def storage(tmp_path):
    """Use an isolated database for every test."""
    database_file = tmp_path / "test_agentshield.db"
    return EventStorage(database_file=str(database_file))


def make_action(
    agent_name="Test-Agent",
    action_type="FILE_READ",
    resource="/tmp/test.txt",
    result="ALLOWED",
):
    return AgentAction(
        agent_name=agent_name,
        action_type=action_type,
        resource=resource,
        timestamp=datetime(2026, 10, 25, 12, 0, 0),
        result=result,
    )


def test_save_event_with_incident_id(storage):
    action = make_action()

    storage.save_event(
        "run-test-001",
        action,
        incident_id="INC-0001",
    )

    records = storage.get_event_records("run-test-001")

    assert len(records) == 1
    assert records[0]["agent_name"] == "Test-Agent"
    assert records[0]["incident_id"] == "INC-0001"


def test_save_event_without_incident_id(storage):
    """Older calls without incident_id should remain supported."""
    action = make_action()

    storage.save_event("run-test-002", action)

    records = storage.get_event_records("run-test-002")

    assert len(records) == 1
    assert records[0]["incident_id"] is None


def test_events_are_separated_by_run_id(storage):
    storage.save_event(
        "run-A",
        make_action(agent_name="Agent-A"),
        incident_id="INC-0001",
    )
    storage.save_event(
        "run-B",
        make_action(agent_name="Agent-B"),
        incident_id="INC-0002",
    )

    run_a = storage.get_event_records("run-A")
    run_b = storage.get_event_records("run-B")

    assert len(run_a) == 1
    assert len(run_b) == 1
    assert run_a[0]["agent_name"] == "Agent-A"
    assert run_b[0]["agent_name"] == "Agent-B"


def test_get_events_still_returns_agent_actions(storage):
    action = make_action()
    storage.save_event("run-test-003", action, incident_id="INC-0003")

    events = storage.get_events(run_id="run-test-003")

    assert len(events) == 1
    assert isinstance(events[0], AgentAction)
    assert events[0].agent_name == "Test-Agent"


def test_existing_database_gets_incident_id_column(tmp_path):
    """Adding the column must preserve existing event records."""
    database_file = tmp_path / "legacy_agentshield.db"

    # Simulate a database created before incident_id was added.
    with sqlite3.connect(database_file) as connection:
        connection.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                resource TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                result TEXT NOT NULL
            )
        """)
        connection.execute("""
            INSERT INTO events (
                run_id, agent_name, action_type,
                resource, timestamp, result
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "legacy-run",
            "Legacy-Agent",
            "FILE_READ",
            "/tmp/legacy.txt",
            "2026-10-24T10:00:00",
            "ALLOWED",
        ))

    # Initialization should migrate the existing database.
    storage = EventStorage(database_file=str(database_file))
    records = storage.get_event_records("legacy-run")

    assert len(records) == 1
    assert records[0]["agent_name"] == "Legacy-Agent"
    assert records[0]["incident_id"] is None


def test_get_incident_summaries_groups_by_run_and_incident(storage):
    """The same incident ID in separate runs must remain separate."""
    storage.save_event(
        "run-A",
        make_action(agent_name="Agent-A", result="DENIED"),
        incident_id="INC-0001",
    )
    storage.save_event(
        "run-A",
        make_action(agent_name="Agent-A", result="ALLOWED"),
        incident_id="INC-0001",
    )
    storage.save_event(
        "run-B",
        make_action(agent_name="Agent-B", result="DENIED"),
        incident_id="INC-0001",
    )

    summaries = storage.get_incident_summaries()

    assert len(summaries) == 2

    by_run = {item["run_id"]: item for item in summaries}

    assert by_run["run-A"]["incident_id"] == "INC-0001"
    assert by_run["run-A"]["agent_name"] == "Agent-A"
    assert by_run["run-A"]["event_count"] == 2
    assert by_run["run-A"]["denied_count"] == 1

    assert by_run["run-B"]["incident_id"] == "INC-0001"
    assert by_run["run-B"]["agent_name"] == "Agent-B"
    assert by_run["run-B"]["event_count"] == 1
    assert by_run["run-B"]["denied_count"] == 1


def test_get_incident_records_returns_only_matching_incident(storage):
    storage.save_event(
        "run-A",
        make_action(action_type="READ_DATABASE"),
        incident_id="INC-0001",
    )
    storage.save_event(
        "run-A",
        make_action(action_type="READ_FILE", result="DENIED"),
        incident_id="INC-0001",
    )
    storage.save_event(
        "run-A",
        make_action(action_type="NETWORK_CONNECT"),
        incident_id="INC-0002",
    )
    storage.save_event(
        "run-B",
        make_action(action_type="READ_FILE"),
        incident_id="INC-0001",
    )

    records = storage.get_incident_records("INC-0001", "run-A")

    assert len(records) == 2
    assert [r["action_type"] for r in records] == [
        "READ_DATABASE",
        "READ_FILE",
    ]
    assert all(r["incident_id"] == "INC-0001" for r in records)
    assert all(r["run_id"] == "run-A" for r in records)


def test_get_incident_records_returns_empty_for_unknown_incident(storage):
    records = storage.get_incident_records("INC-9999", "run-missing")

    assert records == []


@pytest.mark.parametrize(
    ("incident_id", "run_id"),
    [
        ("", "run-A"),
        ("INC-0001", ""),
        (None, "run-A"),
        ("INC-0001", None),
    ],
)
def test_get_incident_records_requires_both_ids(
    storage, incident_id, run_id
):
    with pytest.raises(ValueError):
        storage.get_incident_records(incident_id, run_id)
