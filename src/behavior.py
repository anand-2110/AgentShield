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

    def get_findings(self, agent_name):
        return self.analyze_events(
            self.events,
            agent_name
        )

    def get_historical_findings(self, agent_name, events):
        denied_count = sum(
            1
            for event in events
            if event[0] == agent_name
            and event[4] == "DENIED"
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