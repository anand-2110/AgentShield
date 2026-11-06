
"""CSV export helpers for historical AgentShield investigations."""

import csv
from datetime import datetime
from pathlib import Path

from src.action import AgentAction


SUMMARY_FIELDS = [
    "run_id",
    "incident_id",
    "agent_name",
    "start_time",
    "end_time",
    "event_count",
    "denied_count",
]

TIMELINE_FIELDS = [
    "run_id",
    "incident_id",
    "agent_name",
    "timestamp",
    "action_type",
    "resource",
    "result",
    "action_risk",
    "severity",
    "risk_factors",
]


def _safe_cell(value):
    """Reduce spreadsheet formula-injection risk for text cells."""
    if isinstance(value, str):
        stripped = value.lstrip()
        if stripped.startswith(("=", "+", "-", "@")):
            return "'" + value
    return value


def _write_csv(rows, fields, destination):
    """Write CSV using UTF-8 BOM for convenient spreadsheet compatibility."""
    path = Path(destination)

    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for row in rows:
            writer.writerow({
                field: _safe_cell(row.get(field, ""))
                for field in fields
            })

    return path


def export_incident_summaries(summaries, destination):
    """Export incident summaries, including any applied filters."""
    rows = [
        {field: item.get(field, "") for field in SUMMARY_FIELDS}
        for item in summaries
    ]

    return _write_csv(rows, SUMMARY_FIELDS, destination)


def export_incident_timeline(records, destination, risk_engine):
    """Export an incident timeline with current action-level risk."""
    rows = []

    for record in records:
        action = AgentAction(
            agent_name=record["agent_name"],
            action_type=record["action_type"],
            resource=record["resource"],
            timestamp=datetime.fromisoformat(record["timestamp"]),
            result=record["result"],
        )

        action_risk = risk_engine.assess(action)
        factors = risk_engine.explain(action)

        rows.append({
            "run_id": record["run_id"],
            "incident_id": record["incident_id"],
            "agent_name": record["agent_name"],
            "timestamp": action.timestamp.isoformat(),
            "action_type": action.action_type,
            "resource": action.resource,
            "result": action.result,
            "action_risk": action_risk,
            "severity": risk_engine.severity(action_risk),
            "risk_factors": "; ".join(
                f"{factor['type']} (+{factor['risk']})"
                for factor in factors
            ),
        })

    return _write_csv(rows, TIMELINE_FIELDS, destination)
