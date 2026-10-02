from dataclasses import dataclass
from datetime import datetime

@dataclass
class AgentAction:
    agent_name: str
    action_type: str
    resource: str
    timestamp: datetime
    result: str
