class PolicyEngine:

    def __init__(self):
        self.policies = {
            "HR-Agent": {
                "READ_FILE:candidate.pdf",
                "READ_DATABASE:candidates",
            }
        }

    def check(self, action):
        permission = f"{action.action_type}:{action.resource}"

        if permission in self.policies.get(action.agent_name, set()):
            return "ALLOWED"

        return "DENIED"
