#Basically checks and evalucates if the incidents belong or join dots.

from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class Incident:
    incident_id: str
    agent_name: str
    start_time: datetime
    end_time: datetime
    events: list = field(default_factory=list)
    risk_factors: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    incident_risk: int = 0
    severity: str = "LOW"
    status: str = "NEW"

    def add_event(self, action):
        self.events.append(action)
        self.end_time = action.timestamp

    def get_timeline(self):
        return sorted(
            self.events,
            key=lambda event: event.timestamp
        )
    
    def update_status(self, new_status):
        valid_statuses = {
            "NEW",
            "INVESTIGATING",
            "RESOLVED",
            "FALSE_POSITIVE"
        }

        if new_status not in valid_statuses:
            raise ValueError(
                f"Invalid incident status: {new_status}"
            )

        self.status = new_status

class IncidentManager:

    def __init__(self, correlation_window_seconds=60):
        self.correlation_window = timedelta(
            seconds=correlation_window_seconds
        )
        self.incidents = []
        self.next_incident_id = 1

    def _create_incident(self, action):
        incident = Incident(
            incident_id=f"INC-{self.next_incident_id:04d}",
            agent_name=action.agent_name,
            start_time=action.timestamp,
            end_time=action.timestamp,
            events=[action]
        )

        self.next_incident_id += 1
        self.incidents.append(incident)

        return incident

    def add_event(self, action):
        for incident in reversed(self.incidents):

            if incident.agent_name != action.agent_name:
                continue

            within_window = (
                action.timestamp - incident.end_time
                <= self.correlation_window
            )

            if within_window:
                incident.add_event(action)
                return incident

            break

        return self._create_incident(action)

    def get_incidents(self):
        return self.incidents