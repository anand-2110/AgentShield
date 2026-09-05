import json


class PolicyEngine:

    def __init__(self, policy_file):
        with open(policy_file, "r") as file:
            self.policies = json.load(file)

    def check(self, action):
        allowed_actions = self.policies.get(
            action.agent_name, {}
        ).get("allowed_actions", [])

        permission = f"{action.action_type}:{action.resource}"

        if permission in allowed_actions:
            return "ALLOWED"

        return "DENIED"
