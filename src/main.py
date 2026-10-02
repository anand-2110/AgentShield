#This makes everything work together.

#modules required
from risk import RiskEngine
from agent import SimulatedAgent
from policy import PolicyEngine
from logger import EventLogger
from storage import EventStorage
from behavior import BehaviorAnalyzer
from incident import IncidentManager
 
#initializing modules.
agent = SimulatedAgent("HR-Agent")
policy_engine = PolicyEngine("configs/policies.json")
logger = EventLogger()
risk_engine = RiskEngine("configs/risk_rules.json")
behavior_analyzer = BehaviorAnalyzer()
storage = EventStorage()
incident_manager = IncidentManager()


actions = [
    agent.perform("READ_FILE", "candidate.pdf"),
    agent.perform("READ_DATABASE", "candidates"),
    agent.perform("READ_FILE", "payroll.csv"),
]

for action in actions:
    action.result = policy_engine.check(action)
    behavior_analyzer.record(action)
    storage.save_event(action)
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

    incident.findings = incident_findings

    behavior_risk = risk_engine.assess_behavior(
        incident_findings
    )

    incident_risk = risk_engine.assess_incident(
        incident.events,
        behavior_risk
    )

    incident.incident_risk = incident_risk
    incident.severity = risk_engine.severity(incident_risk)

    print(f"{incident.incident_id}: {incident.agent_name}")
    print(f"Events: {len(incident.events)}")
    print(f"Start: {incident.start_time}")
    print(f"End: {incident.end_time}")

    if incident.findings:
        print("Findings:")

        for finding in incident.findings:
            print(
                f"- {finding['type']}: "
                f"{finding['count']}"
            )

    print(
        f"Incident Risk: "
        f"{incident.incident_risk} "
        f"({incident.severity})"
    )

findings = behavior_analyzer.get_findings("HR-Agent")

behavior_risk = risk_engine.assess_behavior(findings)

print("\nBehavior findings:")
for finding in findings:
    print(finding)

print(f"Behavior risk: {behavior_risk}")

incident_risk = risk_engine.assess_incident(
    actions,
    behavior_risk
)

incident_level = risk_engine.severity(incident_risk)

print(f"Incident risk: {incident_risk} ({incident_level})")

historical_events = storage.get_events(agent.name)

historical_findings = behavior_analyzer.get_historical_findings(
    agent.name,
    historical_events
)

agent_risk = risk_engine.assess_agent_risk(historical_findings)
agent_risk_level = risk_engine.severity(agent_risk)

print("\nHistorical findings:")
for finding in historical_findings:
    print(finding)

print(f"Agent Risk: {agent_risk} ({agent_risk_level})")

print("\nBehavior history:")
for event in behavior_analyzer.get_events():
    print(event)


logger.show_events()
