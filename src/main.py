from datetime import datetime

from action import AgentAction
from policy import PolicyEngine


action = AgentAction(
    agent_name="HR-Agent",
    action_type="READ_FILE",
    resource="PATROLL.csv",
    timestamp=datetime.now(),
    result="PENDING"
)

policy_engine = PolicyEngine()

action.result = policy_engine.check(action)

print(action)
