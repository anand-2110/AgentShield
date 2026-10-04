#This makes everything work together.

#modules required
import uuid
from risk import RiskEngine
from agent import SimulatedAgent
from policy import PolicyEngine
from logger import EventLogger
from storage import EventStorage
from behavior import BehaviorAnalyzer
from incident import IncidentManager
from agent_config import AgentConfigLoader
from incident_summary import IncidentSummary
from datetime import datetime, timedelta
 
#initializing modules.
run_id = str(uuid.uuid4())
config_loader = AgentConfigLoader(
    "configs/agents.json"
)

agents = [
    SimulatedAgent("HR-Agent"),
    SimulatedAgent("Finance-Agent"),
    SimulatedAgent("Support-Agent"),
    SimulatedAgent("DevOps-Agent"),
    SimulatedAgent("Research-Agent"),
    SimulatedAgent("Code-Agent"),
    SimulatedAgent("Database-Agent")
]
policy_engine = PolicyEngine("configs/policies.json")
logger = EventLogger()
risk_engine = RiskEngine("configs/risk_rules.json")
behavior_analyzer = BehaviorAnalyzer("configs/risk_rules.json")
storage = EventStorage()
incident_manager = IncidentManager()
summary_generator = IncidentSummary()

actions = []

for agent in agents:
    scenario = config_loader.get_scenario(
        agent.name
    )

    print(
        f"\nSimulating {agent.name} "
        f"[{scenario}]"
    )

    agent_actions = config_loader.get_actions(
        agent.name
    )

    for action_config in agent_actions:
        action = agent.perform(
            action_config["type"],
            action_config["resource"]
        )

        actions.append(action)

for action in actions:
    action.result = policy_engine.check(action)
    behavior_analyzer.record(action)
    storage.save_event(run_id, action)
    incident_manager.add_event(action)

    risk_score = risk_engine.assess(action)
    risk_level = risk_engine.severity(risk_score)
    risk_factors = risk_engine.explain(action)

    logger.log(action)

    print(f"Risk: {risk_score} ({risk_level})")

    if risk_factors:
        print("Risk factors:")
        for factor in risk_factors:
            print(f"- {factor['type']}: +{factor['risk']}")

print("\nIncidents:")

for incident in incident_manager.get_incidents():

    incident_findings = behavior_analyzer.analyze_events(
        incident.events,
        incident.agent_name
    )

    sequence_findings = behavior_analyzer.detect_sequences(
        incident.events,
        incident.agent_name
    )

    incident_findings.extend(sequence_findings)

    incident.findings = incident_findings
    incident.risk_factors = risk_engine.explain_incident(
        incident.events
    )

    behavior_risk = risk_engine.assess_behavior(
        incident_findings
    )

    incident_risk = risk_engine.assess_incident(
        incident.events,
        behavior_risk
    )

    incident.incident_risk = incident_risk
    incident.severity = risk_engine.severity(incident_risk)
    summary = summary_generator.generate(incident)

    print("\nIncident Summary:")
    print(f"ID: {summary['incident_id']}")
    print(f"Agent: {summary['agent']}")
    print(f"Severity: {summary['severity']}")
    print(f"Status: {summary['status']}")
    print(f"Risk: {summary['risk']}")
    print(f"Events: {summary['event_count']}")
    print(f"Summary: {summary['description']}")

    print(f"{incident.incident_id}: {incident.agent_name}")
    print(f"Status: {incident.status}")
    print(f"Events: {len(incident.events)}")
    print(f"Start: {incident.start_time}")
    print(f"End: {incident.end_time}")
    print("Timeline:")

    for event in incident.get_timeline():
        print(
            f"- {event.timestamp} | "
            f"{event.action_type} | "
            f"{event.resource} | "
            f"{event.result}"
        )

    if incident.findings:
        print("Findings:")

        for finding in incident.findings:
            print(f"- {finding['type']}")

            if "category" in finding:
                print(f"  Category: {finding['category']}")

            if "severity" in finding:
                print(f"  Severity: {finding['severity']}")

            if "confidence" in finding:
                print(f"  Confidence: {finding['confidence']}")

            if "count" in finding:
                print(f"  Count: {finding['count']}")

            if "source" in finding:
                print(f"  Source: {finding['source']}")

            if "destination" in finding:
                print(f"  Destination: {finding['destination']}")

    if incident.risk_factors:
        print("Risk factors:")
        for factor in incident.risk_factors:
            print(
                f"- {factor['type']}: "
                f"+{factor['risk']}"
            )

    print(
        f"Incident Risk: "
        f"{incident.incident_risk} "
        f"({incident.severity})"
    )

print("\nAgent behavior:")

for agent in agents:
    current_events = [
        event
        for event in behavior_analyzer.get_events()
        if event.agent_name == agent.name
    ]

    findings = behavior_analyzer.analyze_events(
        current_events,
        agent.name
    )

    sequence_findings = behavior_analyzer.detect_sequences(
        current_events,
        agent.name
    )

    findings.extend(sequence_findings)

    behavior_risk = risk_engine.assess_behavior(findings)

    print(f"\n{agent.name}")
    print("Behavior findings:")

    for finding in findings:
        print(finding)

    print(f"Behavior risk: {behavior_risk}")

    historical_window = (
        risk_engine.rules["behavior"]["historical_behavior"]["within_seconds"]
    )

    since = datetime.now() - timedelta(
        seconds=historical_window
    )

    historical_runs = storage.get_event_runs(
        agent_name=agent.name,
        exclude_run_id=run_id,
        since=since
    )

    historical_findings = []

    for historical_run in historical_runs:

        run_findings = behavior_analyzer.analyze_events(
            historical_run,
            agent.name
        )

        run_sequence_findings = (
            behavior_analyzer.detect_sequences(
                historical_run,
                agent.name
            )
        )

        run_findings.extend(
            run_sequence_findings
        )

        historical_findings.extend(
            run_findings
        )

    historical_findings = (
        behavior_analyzer.consolidate_findings(
            historical_findings
        )
    )

    historical_risk = risk_engine.assess_agent_risk(
        historical_findings
    )

    agent_risk = behavior_risk + historical_risk

    agent_risk_level = risk_engine.severity(agent_risk)

    print("Historical findings:")

    for finding in historical_findings:
        print(finding)

    print(f"Historical behavior risk: {historical_risk}")

    print(
        f"Agent Risk: "
        f"{agent_risk} "
        f"({agent_risk_level})"
    )
print("\nBehavior history:")
for event in behavior_analyzer.get_events():
    print(event)


logger.show_events()
