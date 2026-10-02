#Records and displayes logs.

from datetime import datetime


class EventLogger:

    def __init__(self):
        self.events = []

    def log(self, action):
        self.events.append({
            "timestamp": action.timestamp,
            "agent": action.agent_name,
            "action": action.action_type,
            "resource": action.resource,
            "result": action.result
        })

    def show_events(self):
        for event in self.events:
            print(event)
