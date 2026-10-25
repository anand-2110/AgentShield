
"""Read-only CLI for investigating historical AgentShield incidents."""

from pathlib import Path
from datetime import datetime

from src.action import AgentAction
from src.risk import RiskEngine
from src.storage import EventStorage


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_FILE = PROJECT_ROOT / "agentshield.db"
RISK_RULES_FILE = PROJECT_ROOT / "configs" / "risk_rules.json"


def build_action(record):
    """Convert a stored event record into an AgentAction."""
    return AgentAction(
        agent_name=record["agent_name"],
        action_type=record["action_type"],
        resource=record["resource"],
        timestamp=datetime.fromisoformat(record["timestamp"]),
        result=record["result"],
    )


def list_incidents(storage):
    """Display historical incidents and return their summaries."""
    summaries = storage.get_incident_summaries()

    print("\n=== AgentShield Historical Investigations ===")

    if not summaries:
        print("No historical incidents found.")
        return summaries

    print(
        f"\n{'No.':<5} {'Incident':<13} {'Agent':<18} "
        f"{'Events':<8} {'Denied':<8} {'Start time'}"
    )
    print("-" * 90)

    for index, item in enumerate(summaries, start=1):
        print(
            f"{index:<5} "
            f"{item['incident_id']:<13} "
            f"{item['agent_name']:<18} "
            f"{item['event_count']:<8} "
            f"{item['denied_count']:<8} "
            f"{item['start_time']}"
        )

    print(
        f"\nTotal incident records: {len(summaries)}"
    )
    return summaries


def investigate_incident(summary, storage, risk_engine):
    """Display the stored timeline and a current action-risk assessment."""
    records = storage.get_incident_records(
        incident_id=summary["incident_id"],
        run_id=summary["run_id"],
    )

    if not records:
        print("No matching event records found.")
        return

    actions = [build_action(record) for record in records]
    denied_count = sum(
        action.result == "DENIED" for action in actions
    )

    print("\n=== Incident Details ===")
    print(f"Incident ID: {summary['incident_id']}")
    print(f"Agent:      {summary['agent_name']}")
    print(f"Run ID:     {summary['run_id']}")
    print(f"Start:      {summary['start_time']}")
    print(f"End:        {summary['end_time']}")
    print(f"Events:     {len(actions)}")

    print("\n=== Event Timeline ===")

    for action in sorted(actions, key=lambda item: item.timestamp):
        action_risk = risk_engine.assess(action)
        risk_level = risk_engine.severity(action_risk)

        print(f"\nTime:     {action.timestamp.isoformat()}")
        print(f"Action:   {action.action_type}")
        print(f"Resource: {action.resource}")
        print(f"Result:   {action.result}")
        print(f"Risk:     {action_risk} ({risk_level})")

        factors = risk_engine.explain(action)

        if factors:
            print("Risk factors:")
            for factor in factors:
                print(
                    f"  - {factor['type']}: "
                    f"+{factor['risk']}"
                )

    highest_action_risk = max(
        (risk_engine.assess(action) for action in actions),
        default=0,
    )

    incident_factors = risk_engine.explain_incident(actions)

    print("\n=== Investigation Summary ===")
    print(f"Total events:       {len(actions)}")
    print(f"Allowed actions:    {len(actions) - denied_count}")
    print(f"Denied actions:     {denied_count}")
    print(
        f"Denied percentage:  "
        f"{denied_count / len(actions) * 100:.1f}%"
    )
    print(
        f"Highest action risk: {highest_action_risk} "
        f"({risk_engine.severity(highest_action_risk)})"
    )

    print("\nDistinct action risk factors:")
    if incident_factors:
        for factor in incident_factors:
            print(
                f"  - {factor['type']}: "
                f"+{factor['risk']}"
            )
    else:
        print("  None identified by the configured action rules.")

    print(
        "\nNote: This is an action-level risk assessment, "
        "not the original incident risk score. Historical "
        "behavioral findings were not persisted with these events."
    )


def main():
    """Run the read-only historical investigation menu."""
    storage = EventStorage(database_file=str(DATABASE_FILE))
    risk_engine = RiskEngine(str(RISK_RULES_FILE))

    while True:
        summaries = list_incidents(storage)

        if not summaries:
            print("\nNo incidents to investigate. Exiting.")
            return

        choice = input(
            "\nEnter an incident number, R to refresh, "
            "or Q to quit: "
        ).strip().lower()

        if choice == "q":
            print("Investigation session ended.")
            return

        if choice == "r":
            continue

        try:
            selection = int(choice)
        except ValueError:
            print("Invalid input. Enter a number, R, or Q.")
            continue

        if not 1 <= selection <= len(summaries):
            print("Incident number out of range.")
            continue

        investigate_incident(
            summaries[selection - 1],
            storage,
            risk_engine,
        )

        input("\nPress Enter to return to the incident list...")


if __name__ == "__main__":
    main()
