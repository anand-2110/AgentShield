class BehaviorAnalyzer:

    def __init__(self):
        self.events = []

    def record(self, action):
        self.events.append(action)

    def get_events(self):
        return self.events

    def count_denied(self, agent_name):
        return sum(
            1
            for event in self.events
            if event.agent_name == agent_name
            and event.result == "DENIED"
        )

    def get_findings(self, agent_name):
        denied_count = self.count_denied(agent_name)

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