#this is to look for patterns that could lead to suspicious activity

import json

class BehaviorAnalyzer:

    def __init__(self, rules_file):
        with open(rules_file, "r") as file:
            self.rules = json.load(file)

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

        sequence_rules = self.rules["behavior_sequences"]

        sensitive_resources = set(
            self.rules["sensitive_resources"]
        )

        for sequence_rule in sequence_rules.values():

            source = sequence_rule["source"]
            destination = sequence_rule["destination"]
            finding_type = sequence_rule["finding"]

            source_event = None

            for event in agent_events:

                source_matches = False

                if source["type"] == "RESOURCE":
                    if (
                        source["value"] == "SENSITIVE_RESOURCE"
                        and event.resource in sensitive_resources
                    ):
                        source_matches = True

                elif source["type"] == "ACTION":
                    if event.action_type == source["value"]:
                        source_matches = True

                if source_matches:
                    source_event = event
                    continue

                if source_event is None:
                    continue

                destination_matches = False

                if destination["type"] == "RESOURCE":
                    if (
                        destination["value"] == "SENSITIVE_RESOURCE"
                        and event.resource in sensitive_resources
                    ):
                        destination_matches = True

                elif destination["type"] == "ACTION":
                    if event.action_type == destination["value"]:
                        destination_matches = True

                if destination_matches:
                    findings.append({
                        "type": finding_type,
                        "source": source_event.resource,
                        "destination": event.resource
                    })

                    break

        return findings

    def get_findings(self, agent_name):
        return self.analyze_events(
            self.events,
            agent_name
        )
    
