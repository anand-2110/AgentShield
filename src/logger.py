
# Structured security event logging.

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

try:
    from .action import AgentAction
except ImportError:
    from action import AgentAction


@dataclass
class SecurityEvent:
    event_id: int
    timestamp: datetime
    agent_name: str
    action_type: str
    resource: str
    result: str
    incident_id: Optional[str] = None

    @classmethod
    def from_action(
        cls,
        event_id: int,
        action: AgentAction,
        incident_id: Optional[str] = None
    ):
        return cls(
            event_id=event_id,
            timestamp=action.timestamp,
            agent_name=action.agent_name,
            action_type=action.action_type,
            resource=action.resource,
            result=action.result,
            incident_id=incident_id
        )

    def to_dict(self):
        record = asdict(self)
        record["timestamp"] = self.timestamp.isoformat()
        return record

class EventLogger:
    def __init__(self):
        self.events = []

    def log(self, action, incident_id=None):
        event = SecurityEvent.from_action(
            event_id=len(self.events) + 1,
            action=action,
            incident_id=incident_id
        )

        self.events.append(event)
        return event

    def get_events(self):
        return [
            event.to_dict()
            for event in self.events
        ]

    def show_events(self):
        for event in self.events:
            print(event.to_dict())
