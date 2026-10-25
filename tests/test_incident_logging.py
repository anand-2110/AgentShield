
from datetime import datetime, timedelta

from src.action import AgentAction
from src.incident import IncidentManager
from src.logger import EventLogger


def make_action(agent_name, seconds=0):
    return AgentAction(
        agent_name=agent_name,
        action_type="READ_FILE",
        resource="test.txt",
        timestamp=datetime(2026, 10, 25, 12, 0, 0)
        + timedelta(seconds=seconds),
        result="ALLOWED"
    )


def test_logged_event_has_assigned_incident_id():
    manager = IncidentManager()
    logger = EventLogger()

    action = make_action("Test-Agent")
    incident = manager.add_event(action)
    event = logger.log(action, incident_id=incident.incident_id)

    assert event.incident_id == incident.incident_id
    assert event.incident_id == "INC-0001"


def test_events_in_same_incident_share_incident_id():
    manager = IncidentManager()
    logger = EventLogger()

    first = make_action("Test-Agent", 0)
    second = make_action("Test-Agent", 5)

    first_incident = manager.add_event(first)
    second_incident = manager.add_event(second)

    first_event = logger.log(
        first,
        incident_id=first_incident.incident_id
    )
    second_event = logger.log(
        second,
        incident_id=second_incident.incident_id
    )

    assert first_event.incident_id == second_event.incident_id
    assert len(manager.get_incidents()) == 1


def test_different_agents_get_separate_incidents():
    manager = IncidentManager()

    first = manager.add_event(make_action("Agent-A"))
    second = manager.add_event(make_action("Agent-B"))

    assert first.incident_id != second.incident_id
    assert len(manager.get_incidents()) == 2
