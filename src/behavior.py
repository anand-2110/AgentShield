#this is to look for patterns that could lead to suspicious activity

class BehaviorAnalyzer:

    def __init__(self):
        self.events = []

    def record(self, action):
        self.events.append(action)

    def get_events(self):
        return self.events

    def analyze_events(self, events, agent_name):
        denied_count = sum(
            1
            for event in events
            if event.agent_name == agent_name
            and event.result == "DENIED"
        )

        findings = []

        if denied_count == 1:
            findings.append({
                "type": "DENIED_ACTION",
                "count": denied_count
            })

        elif denied_count >= 2:
            findings.append({
                "type": "REPEATED_DENIALS",
                "count": denied_count
            })

        return findings
    
    def detect_sequences(self, events, agent_name):
        agent_events = [
            event
            for event in events
            if event.agent_name == agent_name
        ]

        findings = []

        sensitive_resources = {
            "payroll.csv",
            "employee_salary.csv",
            "passwords.db",
            "credentials.txt"
        }

        sensitive_access = None

        for event in agent_events:
            if event.resource in sensitive_resources:
                sensitive_access = event
                continue

            if (
                sensitive_access
                and event.action_type == "NETWORK_CONNECT"
            ):
                findings.append({
                    "type": "SUSPICIOUS_DATA_FLOW",
                    "source": sensitive_access.resource,
                    "destination": event.resource
                })

                break

        return findings
    
    def get_findings(self, agent_name):
        return self.analyze_events(
            self.events,
            agent_name
        )


