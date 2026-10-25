
from datetime import datetime

from src.action import AgentAction
from src.investigate import build_action, list_incidents


class FakeStorage:
    def get_incident_summaries(self):
        return [
            {
                "run_id": "run-A",
                "incident_id": "INC-0001",
                "agent_name": "Test-Agent",
                "start_time": "2026-10-25T12:00:00",
                "end_time": "2026-10-25T12:00:02",
                "event_count": 2,
                "denied_count": 1,
            }
        ]


def test_build_action_converts_stored_record():
    record = {
        "timestamp": "2026-10-25T12:00:00",
        "agent_name": "Test-Agent",
        "action_type": "READ_FILE",
        "resource": "credentials.txt",
        "result": "DENIED",
    }

    action = build_action(record)

    assert isinstance(action, AgentAction)
    assert action.agent_name == "Test-Agent"
    assert action.action_type == "READ_FILE"
    assert action.result == "DENIED"
    assert action.timestamp == datetime(2026, 10, 25, 12, 0, 0)


def test_list_incidents_displays_summary(capsys):
    summaries = list_incidents(FakeStorage())

    output = capsys.readouterr().out

    assert len(summaries) == 1
    assert "INC-0001" in output
    assert "Test-Agent" in output
    assert "Total incident records: 1" in output


def test_list_incidents_handles_empty_history(capsys):
    class EmptyStorage:
        def get_incident_summaries(self):
            return []

    summaries = list_incidents(EmptyStorage())

    output = capsys.readouterr().out

    assert summaries == []
    assert "No historical incidents found." in output
