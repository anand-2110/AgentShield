import json

from src.correlation import CorrelationEngine


with open("configs/risk_rules.json", "r") as file:
    rules = json.load(file)


engine = CorrelationEngine(rules)


findings = [
    {
        "type": "REPEATED_DENIALS"
    },
    {
        "type": "PRIVILEGE_EXTERNAL_COMMUNICATION"
    }
]


correlations = engine.correlate(findings)

assert len(correlations) == 1

correlation = correlations[0]

assert correlation["type"] == "CORRELATED_SUSPICIOUS_ACTIVITY"
assert correlation["rule"] == "policy_to_privilege"
assert correlation["risk_bonus"] == 20
assert correlation["severity"] == "CRITICAL"

assert "evidence" in correlation
assert len(correlation["evidence"]) == 2

assert "REPEATED_DENIALS detected" in correlation["evidence"]
assert (
    "PRIVILEGE_EXTERNAL_COMMUNICATION detected"
    in correlation["evidence"]
)

print("Correlation test passed.")


non_matching_findings = [
    {
        "type": "REPEATED_DENIALS"
    }
]


correlations = engine.correlate(
    non_matching_findings
)

assert len(correlations) == 0

print("Non-matching correlation test passed.")