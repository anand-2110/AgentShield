
import csv

from src.export import (
    export_incident_summaries,
    export_incident_timeline,
)


def read_csv(path):
    with path.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        return list(csv.DictReader(file))


def test_export_incident_summaries(tmp_path):
    destination = tmp_path / "incidents.csv"

    export_incident_summaries(
        [
            {
                "run_id": "run-A",
                "incident_id": "INC-0001",
                "agent_name": "Database-Agent",
                "start_time": "2026-10-25T12:00:00",
                "end_time": "2026-10-25T12:01:00",
                "event_count": 2,
                "denied_count": 1,
            }
        ],
        destination,
    )

    rows = read_csv(destination)

    assert len(rows) == 1
    assert rows[0]["run_id"] == "run-A"
    assert rows[0]["incident_id"] == "INC-0001"
    assert rows[0]["event_count"] == "2"
    assert rows[0]["denied_count"] == "1"


def test_export_empty_summaries_writes_headers(tmp_path):
    destination = tmp_path / "empty.csv"

    export_incident_summaries([], destination)

    assert read_csv(destination) == []


def test_export_summaries_escapes_formula_like_text(tmp_path):
    destination = tmp_path / "safe.csv"

    export_incident_summaries(
        [
            {
                "run_id": "run-A",
                "incident_id": "INC-0001",
                "agent_name": "=1+1",
                "start_time": "",
                "end_time": "",
                "event_count": 1,
                "denied_count": 0,
            }
        ],
        destination,
    )

    rows = read_csv(destination)

    assert rows[0]["agent_name"] == "'=1+1"


def test_export_incident_timeline(tmp_path):
    from datetime import datetime

    from src.risk import RiskEngine
    from src.export import TIMELINE_FIELDS

    destination = tmp_path / "timeline.csv"
    risk_engine = RiskEngine("configs/risk_rules.json")

    records = [
        {
            "run_id": "run-A",
            "incident_id": "INC-0001",
            "agent_name": "Test-Agent",
            "timestamp": datetime(2026, 10, 25, 12, 0, 0).isoformat(),
            "action_type": "FILE_READ",
            "resource": "/tmp/test.txt",
            "result": "ALLOWED",
        }
    ]

    export_incident_timeline(records, destination, risk_engine)

    rows = read_csv(destination)

    assert len(rows) == 1
    assert rows[0]["action_type"] == "FILE_READ"
    assert rows[0]["result"] == "ALLOWED"
    assert rows[0]["run_id"] == "run-A"
    assert set(rows[0]) == set(TIMELINE_FIELDS)
    assert rows[0]["action_risk"].isdigit()
    assert rows[0]["severity"]
