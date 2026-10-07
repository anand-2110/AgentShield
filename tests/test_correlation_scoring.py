import json

from src.correlation import CorrelationEngine
from src.risk import RiskEngine


with open("configs/risk_rules.json", "r") as file:
    rules = json.load(file)


correlation_engine = CorrelationEngine(rules)
risk_engine = RiskEngine("configs/risk_rules.json")


findings = [
    {
        "type": "REPEATED_DENIALS",
        "count": 5
    },
    {
        "type": "PRIVILEGE_EXTERNAL_COMMUNICATION"
    }
]


correlations = correlation_engine.correlate(findings)

assert len(correlations) == 1

base_risk = risk_engine.assess_agent_risk(findings)

correlation_risk = risk_engine.assess_agent_risk(
    findings,
    correlations
)

assert correlation_risk == base_risk + 20

print("Correlation scoring test passed.")