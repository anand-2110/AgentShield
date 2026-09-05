from risk import RiskEngine
from agent import SimulatedAgent
from policy import PolicyEngine
from logger import EventLogger


agent = SimulatedAgent("HR-Agent")
policy_engine = PolicyEngine("configs/policies.json")
logger = EventLogger()
risk_engine = RiskEngine("configs/risk_rules.json")

actions = [
    agent.perform("READ_FILE", "candidate.pdf"),
    agent.perform("READ_DATABASE", "candidates"),
    agent.perform("READ_FILE", "payroll.csv"),
]


for action in actions:
    action.result = policy_engine.check(action)

    risk_score = risk_engine.assess(action)
    risk_level = risk_engine.severity(risk_score)

    logger.log(action)

    print(f"Risk: {risk_score} ({risk_level})")


logger.show_events()
