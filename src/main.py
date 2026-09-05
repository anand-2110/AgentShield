from agent import SimulatedAgent
from policy import PolicyEngine
from logger import EventLogger


agent = SimulatedAgent("HR-Agent")
policy_engine = PolicyEngine("configs/policies.json")
logger = EventLogger()


actions = [
    agent.perform("READ_FILE", "candidate.pdf"),
    agent.perform("READ_DATABASE", "candidates"),
    agent.perform("READ_FILE", "payroll.csv"),
]


for action in actions:
    action.result = policy_engine.check(action)
    logger.log(action)


logger.show_events()
