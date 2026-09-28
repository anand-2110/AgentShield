from risk import RiskEngine
from agent import SimulatedAgent
from policy import PolicyEngine
from logger import EventLogger
from behavior import BehaviorAnalyzer
 

agent = SimulatedAgent("HR-Agent")
policy_engine = PolicyEngine("configs/policies.json")
logger = EventLogger()
risk_engine = RiskEngine("configs/risk_rules.json")
behavior_analyzer = BehaviorAnalyzer()

actions = [
    agent.perform("READ_FILE", "candidate.pdf"),
    agent.perform("READ_DATABASE", "candidates"),
    agent.perform("READ_FILE", "payroll.csv"),
]

for action in actions:
    action.result = policy_engine.check(action)
    behavior_analyzer.record(action)

    risk_score = risk_engine.assess(action)
    risk_level = risk_engine.severity(risk_score)

    logger.log(action)

    print(f"Risk: {risk_score} ({risk_level})")


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

print("\nBehavior history:")
for event in behavior_analyzer.get_events():
    print(event)


logger.show_events()
