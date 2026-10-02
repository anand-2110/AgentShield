#Accounts and values the risk and weight of the incidents.

import json


class RiskEngine:

    def __init__(self, rules_file):
        with open(rules_file, "r") as file:
            self.rules = json.load(file)

    def assess(self, action):
        score = 0

        if action.result == "DENIED":
            score += self.rules["policy_violation"]

        if action.resource in self.rules["sensitive_resources"]:
            score += self.rules["sensitive_resource"]

        if action.action_type == "NETWORK_CONNECT":
            score += self.rules["external_communication"]    

        return score

    def explain(self, action):
        factors = []

        if action.result == "DENIED":
            factors.append({
                "type": "POLICY_VIOLATION",
                "risk": self.rules["policy_violation"]
            })

        if action.resource in self.rules["sensitive_resources"]:
            factors.append({
                "type": "SENSITIVE_RESOURCE",
                "risk": self.rules["sensitive_resource"]
            })
        if action.action_type == "NETWORK_CONNECT":
            factors.append({
                "type": "EXTERNAL_COMMUNICATION",
                "risk": self.rules["external_communication"]
            })

        return factors

    def explain_incident(self, actions):
        factors = []
        seen = set()

        for action in actions:
            action_factors = self.explain(action)

            for factor in action_factors:
                key = (factor["type"], factor["risk"])

                if key not in seen:
                    factors.append(factor)
                    seen.add(key)

        return factors
    
    def severity(self, score):
        if score >= 90:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    def assess_behavior(self, findings):
        risk = 0

        for finding in findings:
            if finding["type"] == "REPEATED_DENIALS":
                count = finding["count"]

                rules = self.rules["behavior"]["repeated_denials"]

                if count >= rules["high"]["threshold"]:
                    risk += rules["high"]["risk"]

                elif count >= rules["medium"]["threshold"]:
                    risk += rules["medium"]["risk"]

        return risk

    def assess_agent_risk(self, findings):
        return self.assess_behavior(findings)


    def assess_incident(self, actions, behavior_risk):
        action_risks = []

        for action in actions:
            action_risks.append(self.assess(action))

        highest_action_risk = max(action_risks, default=0)

        return highest_action_risk + behavior_risk