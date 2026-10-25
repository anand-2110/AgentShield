
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


def list_incidents(
    storage,
    agent_name=None,
    run_id=None,
    denied_only=False,
):
    """Display historical incidents using optional filters."""

    if agent_name is None and run_id is None and not denied_only:
        # Preserve compatibility with existing callers and tests.
        summaries = storage.get_incident_summaries()
    else:
        summaries = storage.get_incident_summaries(
            agent_name=agent_name,
            run_id=run_id,
            denied_only=denied_only,
        )

    print("\n=== AgentShield Historical Investigations ===")

    active_filters = []
    if agent_name:
        active_filters.append(f"Agent: {agent_name}")
    if run_id:
        active_filters.append(f"Run: {run_id}")
    if denied_only:
        active_filters.append("Denied actions only")

    if active_filters:
        print("Active filters: " + " | ".join(active_filters))

    if not summaries:
        print("No historical incidents found.")
        return summaries

    # Fixed-width columns keep the table aligned.
    columns = (
        f"{'No.':<5} "
        f"{'Incident':<13} "
        f"{'Agent':<22} "
        f"{'Events':>7} "
        f"{'Denied':>7} "
        f"{'Run ID':<22} "
        f"Start time"
    )

    print()
    print(columns)
    print("-" * len(columns))

    for index, item in enumerate(summaries, start=1):
        incident_id = str(item["incident_id"])[:13]
        agent_name = str(item["agent_name"])[:22]
        run_id_value = str(item["run_id"])[:22]
        start_time = str(item["start_time"])

        print(
            f"{index:<5} "
            f"{incident_id:<13} "
            f"{agent_name:<22} "
            f"{item['event_count']:>7} "
            f"{item['denied_count']:>7} "
            f"{run_id_value:<22} "
            f"{start_time}"
        )

    print()
    print(f"Total incident records: {len(summaries)}")
    return summaries



def investigate_incident(summary, storage, risk_engine):
    """Display the stored timeline and current action-risk assessment."""
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
    print(f"Agent:       {summary['agent_name']}")
    print(f"Run ID:      {summary['run_id']}")
    print(f"Start:       {summary['start_time']}")
    print(f"End:         {summary['end_time']}")
    print(f"Events:      {len(actions)}")

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
                print(f"  - {factor['type']}: +{factor['risk']}")

    highest_action_risk = max(
        (risk_engine.assess(action) for action in actions),
        default=0,
    )

    incident_factors = risk_engine.explain_incident(actions)

    print("\n=== Investigation Summary ===")
    print(f"Total events:        {len(actions)}")
    print(f"Allowed actions:     {len(actions) - denied_count}")
    print(f"Denied actions:      {denied_count}")
    print(
        f"Denied percentage:   "
        f"{denied_count / len(actions) * 100:.1f}%"
    )
    print(
        f"Highest action risk: {highest_action_risk} "
        f"({risk_engine.severity(highest_action_risk)})"
    )

    print("\nDistinct action risk factors:")
    if incident_factors:
        for factor in incident_factors:
            print(f"  - {factor['type']}: +{factor['risk']}")
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

    agent_filter = None
    run_filter = None
    denied_only = False

    while True:
        summaries = list_incidents(
            storage,
            agent_name=agent_filter,
            run_id=run_filter,
            denied_only=denied_only,
        )

        print("\n=== Investigation Menu ===")
        print("Enter an incident number to investigate")
        print("A - Filter by agent name")
        print("D - Toggle denied-action-only filter")
        print("I - Filter by run ID")
        print("C - Clear all filters")
        print("R - Refresh incident list")
        print("Q - Quit")

        choice = input("\nYour choice: ").strip()

        if choice.lower() == "q":
            print("Investigation session ended.")
            return

        if choice.lower() == "r":
            continue

        if choice.lower() == "a":
            value = input(
                "Enter exact agent name (blank to clear): "
            ).strip()
            agent_filter = value or None
            continue

        if choice.lower() == "d":
            denied_only = not denied_only
            state = "ON" if denied_only else "OFF"
            print(f"Denied-action-only filter: {state}")
            continue

        if choice.lower() == "i":
            value = input(
                "Enter exact run ID (blank to clear): "
            ).strip()
            run_filter = value or None
            continue

        if choice.lower() == "c":
            agent_filter = None
            run_filter = None
            denied_only = False
            print("All filters cleared.")
            continue

        try:
            selection = int(choice)
        except ValueError:
            print("Invalid input. Choose a menu option or incident number.")
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
