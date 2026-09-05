from datetime import datetime

from action import AgentAction


class SimulatedAgent:

    def __init__(self, name):
        self.name = name

    def perform(self, action_type, resource):
        return AgentAction(
            agent_name=self.name,
            action_type=action_type,
            resource=resource,
            timestamp=datetime.now(),
            result="PENDING"
        )
