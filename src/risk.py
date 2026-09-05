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
