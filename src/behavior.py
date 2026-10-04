# this is to look for patterns that could lead to suspicious activity

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

    def get_finding_category(self, finding_type):
        finding_rules = self.rules["behavior"]["findings"]

        if finding_type in finding_rules:
            return finding_rules[finding_type]["category"]

        return None

    def get_finding_metadata(self, finding_type):
        finding_rules = self.rules["behavior"]["findings"]

        if finding_type in finding_rules:
            return finding_rules[finding_type]

        return None

    def analyze_events(self, events, agent_name):

        agent_events = [
            event
            for event in events
            if event.agent_name == agent_name
        ]

        findings = []

        # -----------------------------------------
        # Repeated denied actions
        # -----------------------------------------

        denied_events = [
            event
            for event in agent_events
            if event.result == "DENIED"
        ]

        denied_count = len(denied_events)

        if denied_count == 1:
            findings.append({
                "type": "DENIED_ACTION",
                "count": denied_count,
                "description": "Agent attempted an action that was denied by policy.",
                "evidence": [
                    {
                        "action_type": event.action_type,
                        "resource": event.resource
                    }
                    for event in denied_events
                ]
            })

        elif denied_count >= 2:
            findings.append({
                "type": "REPEATED_DENIALS",
                "count": denied_count,
                "description": "Agent repeatedly attempted actions that were denied by policy.",
                "evidence": [
                    {
                        "action_type": event.action_type,
                        "resource": event.resource
                    }
                    for event in denied_events
                ]
            })

        # -----------------------------------------
        # Mass data access
        # -----------------------------------------

        data_access_events = [
            event
            for event in agent_events
            if event.action_type in [
                "READ_FILE",
                "READ_DATABASE"
            ]
        ]

        unique_resources = sorted(set(
            event.resource
            for event in data_access_events
        ))

        data_access_count = len(unique_resources)

        data_access_rules = self.rules["behavior"]["data_access"]

        finding_metadata = self.get_finding_metadata(
            "MASS_DATA_ACCESS"
        ) or {}

        if data_access_count >= data_access_rules["medium"]["threshold"]:
            findings.append({
                "type": "MASS_DATA_ACCESS",
                "category": self.get_finding_category(
                    "MASS_DATA_ACCESS"
                ),
                "severity": finding_metadata.get("severity"),
                "confidence": finding_metadata.get("confidence"),
                "count": data_access_count,
                "resources": unique_resources,
                "description": "Agent accessed multiple unique data resources.",
                "evidence": [
                    {
                        "action_type": event.action_type,
                        "resource": event.resource
                    }
                    for event in data_access_events
                ]
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

        code_resources = set(
            self.rules.get("code_resources", [])
        )

        for sequence_rule in sequence_rules.values():

            source = sequence_rule["source"]
            destination = sequence_rule["destination"]

            finding_type = sequence_rule["finding"]
            description = sequence_rule["description"]
            
            finding_metadata = self.get_finding_metadata(
                finding_type
            ) or {}

            within_seconds = sequence_rule["within_seconds"]

            source_event = None

            for event in agent_events:

                source_matches = False

                # ---------------------------------
                # Source: RESOURCE
                # ---------------------------------

                if source["type"] == "RESOURCE":

                    if (
                        source["value"] == "SENSITIVE_RESOURCE"
                        and event.resource in sensitive_resources
                    ):
                        source_matches = True

                # ---------------------------------
                # Source: RESOURCE_CATEGORY
                # ---------------------------------

                elif source["type"] == "RESOURCE_CATEGORY":

                    if (
                        source["value"] == "CODE_RESOURCE"
                        and event.resource in code_resources
                    ):
                        source_matches = True

                # ---------------------------------
                # Source: ACTION
                # ---------------------------------

                elif source["type"] == "ACTION":

                    if event.action_type == source["value"]:
                        source_matches = True

                # ---------------------------------
                # Store source event
                # ---------------------------------

                if source_matches:
                    source_event = event
                    continue

                if source_event is None:
                    continue

                # ---------------------------------
                # Destination matching
                # ---------------------------------

                destination_matches = False

                if destination["type"] == "RESOURCE":

                    if (
                        destination["value"] == "SENSITIVE_RESOURCE"
                        and event.resource in sensitive_resources
                    ):
                        destination_matches = True

                elif destination["type"] == "RESOURCE_CATEGORY":

                    if (
                        destination["value"] == "CODE_RESOURCE"
                        and event.resource in code_resources
                    ):
                        destination_matches = True

                elif destination["type"] == "ACTION":

                    if event.action_type == destination["value"]:
                        destination_matches = True

                # ---------------------------------
                # Check sequence timing
                # ---------------------------------

                if destination_matches:

                    time_difference = (
                        event.timestamp -
                        source_event.timestamp
                    ).total_seconds()

                    if (
                        0 <= time_difference <= within_seconds
                    ):
                        findings.append({
                            "type": finding_type,
                            "category": self.get_finding_category(
                                finding_type
                            ),
                            "severity": finding_metadata.get("severity"),
                            "confidence": finding_metadata.get("confidence"),
                            "source": source_event.resource,
                            "destination": event.resource,
                            "description": description,
                            "evidence": [
                                {
                                    "action_type": source_event.action_type,
                                    "resource": source_event.resource
                                },
                                {
                                    "action_type": event.action_type,
                                    "resource": event.resource
                                }
                            ]
                        })

                        # Prevent reusing the same source
                        source_event = None

        return findings

    def consolidate_findings(self, findings):

        consolidated = {}

        for finding in findings:

            key = (
                finding["type"],
                finding.get("source"),
                finding.get("destination")
            )

            if key not in consolidated:

                consolidated[key] = finding.copy()
                consolidated[key]["occurrences"] = 1

            else:

                consolidated[key]["occurrences"] += 1

        return list(consolidated.values())

    def get_findings(self, agent_name):

        return self.analyze_events(
            self.events,
            agent_name
        )