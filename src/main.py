#This makes everything work together.

#modules required
from agent import SimulatedAgent
from agent_config import AgentConfigLoader
from baseline import BaselineEngine
from baseline_detector import BaselineDetector
from behavior import BehaviorAnalyzer
from correlation import CorrelationEngine
from datetime import datetime, timedelta
from incident import IncidentManager
from incident_summary import IncidentSummary
from logger import EventLogger
from policy import PolicyEngine
from risk import RiskEngine
from storage import EventStorage
import uuid
 
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
baseline_config = risk_engine.rules["baseline"]
baseline_engine = BaselineEngine(
    minimum_events=baseline_config["minimum_events"]
)
baseline_detector = BaselineDetector(
    volume_multiplier=3.0,
    minimum_baseline_events=baseline_config["minimum_events"],
    window_seconds=60,
    minimum_activity_events=baseline_config["minimum_activity_events"],
)
correlation_engine = CorrelationEngine(
    risk_engine.rules
)
incident_manager = IncidentManager()
summary_generator = IncidentSummary()

actions = []


def get_baseline_findings(agent_name, current_events):
    if not current_events:
        return []

    baseline_lookback = (
    risk_engine.rules["baseline"]["lookback_seconds"]
    )

    baseline_since = datetime.now() - timedelta(
        seconds=baseline_lookback
    )

    historical_events = storage.get_events(
        agent_name=agent_name,
        exclude_run_id=run_id,
        since=baseline_since,
    )

    baseline = baseline_engine.build(
        historical_events
    ).get(agent_name)

    if not baseline or not baseline["baseline_mature"]:
        return []

    findings = []
    seen = set()

    # Detect unfamiliar actions and resources.
    for event in current_events:
        event_findings = baseline_detector.detect(
            event, baseline
        )

        for finding in event_findings:
            evidence = finding.get("evidence", {})

            key = (
                finding["type"],
                evidence.get("action_type"),
                evidence.get("resource"),
            )

            if key not in seen:
                seen.add(key)
                findings.append(finding)

    # Count events in the configured recent window.
    window_end = max(
        event.timestamp for event in current_events
    )
    window_start = window_end - timedelta(
        seconds=baseline_detector.window_seconds
    )

    recent_event_count = sum(
        window_start <= event.timestamp <= window_end
        for event in current_events
    )

    last_event = max(
        current_events,
        key=lambda event: event.timestamp,
    )

    volume_findings = baseline_detector.detect(
        last_event,
        baseline,
        recent_event_count,
    )

    findings.extend(
        finding
        for finding in volume_findings
        if finding["type"] == "EXCESSIVE_ACTIVITY"
    )

    return findings


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
#incidenents
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

    baseline_findings = get_baseline_findings(
        incident.agent_name,
        incident.events,
    )

    incident_findings.extend(baseline_findings)

    incident_findings = behavior_analyzer.apply_confidence(
        incident_findings
    )

    correlations = correlation_engine.correlate(
    incident_findings
    )

    incident.findings = incident_findings
    incident.risk_factors = risk_engine.explain_incident(
        incident.events
    )

    behavior_risk = risk_engine.assess_agent_risk(
        incident_findings,
        correlations
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

    if correlations:
        print("Correlations:")

        for correlation in correlations:
            print(
                f"- {correlation['type']} "
                f"(+{correlation['risk_bonus']} risk)"
            )

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

#findings
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

    baseline_findings = get_baseline_findings(
        agent.name,
        current_events,
    )

    findings.extend(baseline_findings)

    findings = behavior_analyzer.apply_confidence(
        findings
    )

    correlations = correlation_engine.correlate(
        findings
    )

    behavior_risk = risk_engine.assess_agent_risk(
        findings,
        correlations
    )

    print(f"\n{agent.name}")
    print("Behavior findings:")

    if correlations:
        print("Correlations:")

        for correlation in correlations:
            print(
                f"- {correlation['type']} "
                f"(+{correlation['risk_bonus']} risk)"
            )

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

        run_findings.extend(run_sequence_findings)

        historical_findings.extend(run_findings)


    historical_findings = behavior_analyzer.consolidate_findings(
        historical_findings
    )

    historical_findings = behavior_analyzer.apply_confidence(
        historical_findings
    )


    historical_correlations = correlation_engine.correlate(
        historical_findings
    )

    historical_risk = risk_engine.assess_agent_risk(
        historical_findings,
        historical_correlations
    )

    current_incident_risks = [
        incident.incident_risk
        for incident in incident_manager.get_incidents()
        if incident.agent_name == agent.name
    ]

    agent_risk = risk_engine.assess_overall_agent_risk(
        current_incident_risks,
        historical_risk
    )

    highest_incident_risk = max(
        current_incident_risks,
        default=0
    )

    agent_risk_level = risk_engine.severity(agent_risk)

    print("Historical findings:")

    for finding in historical_findings:
        print(finding)

    print(f"Highest current incident risk: {highest_incident_risk}")
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
