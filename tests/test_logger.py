
from datetime import datetime

from src.action import AgentAction
from src.logger import EventLogger, SecurityEvent


def make_action():
    return AgentAction(
        agent_name="Test-Agent",
        action_type="READ",
        resource="test-file.txt",
        timestamp=datetime(2026, 10, 25, 12, 0, 0),
        result="ALLOWED"
    )


def test_logger_creates_structured_event():
    logger = EventLogger()

    event = logger.log(make_action())

    assert isinstance(event, SecurityEvent)
    assert event.event_id == 1
    assert event.agent_name == "Test-Agent"
    assert event.action_type == "READ"
    assert event.result == "ALLOWED"


def test_logger_preserves_incident_id():
    logger = EventLogger()

    event = logger.log(
        make_action(),
        incident_id="INC-0001"
    )

    assert event.to_dict()["incident_id"] == "INC-0001"


def test_logger_assigns_sequential_event_ids():
    logger = EventLogger()

    first = logger.log(make_action())
    second = logger.log(make_action())

    assert first.event_id == 1
    assert second.event_id == 2


def test_logger_serializes_timestamp():
    logger = EventLogger()

    event = logger.log(make_action())

    assert event.to_dict()["timestamp"] == "2026-10-25T12:00:00"


def test_logger_returns_structured_records():
    logger = EventLogger()
    logger.log(make_action())

    records = logger.get_events()

    assert len(records) == 1
    assert records[0]["agent_name"] == "Test-Agent"
    assert records[0]["incident_id"] is None
