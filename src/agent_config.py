import json


class AgentConfigLoader:
    def __init__(self, config_file):
        with open(config_file, "r") as file:
            self.config = json.load(file)

    def get_agents(self):
        return self.config

    def get_actions(self, agent_name):
        return self.config[agent_name]["actions"]

    def get_scenario(self, agent_name):
        return self.config[agent_name]["scenario"]