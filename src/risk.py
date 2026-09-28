import json


class RiskEngine:

    def __init__(self, rules_file):
        with open(rules_file, "r") as file:
            self.rules = json.load(file)

    def assess(self, action):
        score = 0

        if action.result == "DENIED":
            score += self.rules["policy_violation"]

        return score

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
    def assess_incident(self, actions, behavior_risk):
        action_risks = []

        for action in actions:
            action_risks.append(self.assess(action))

        highest_action_risk = max(action_risks, default=0)

        return highest_action_risk + behavior_risk