
from src.risk import RiskEngine


def test_denied_action_has_zero_behavior_risk():
    risk_engine = RiskEngine("configs/risk_rules.json")

    findings = [
        {"type": "DENIED_ACTION"}
    ]

    assert risk_engine.assess_behavior(findings) == 0


def test_unusual_action_has_configured_behavior_risk():
    risk_engine = RiskEngine("configs/risk_rules.json")

    findings = [
        {"type": "UNUSUAL_ACTION"}
    ]

    assert risk_engine.assess_behavior(findings) == 20


def test_correlation_bonus_is_added_to_agent_risk():
    risk_engine = RiskEngine("configs/risk_rules.json")

    findings = [
        {"type": "UNUSUAL_ACTION"}
    ]

    correlations = [
        {"type": "TEST_CORRELATION", "risk_bonus": 20}
    ]

    assert risk_engine.assess_agent_risk(
        findings, correlations
    ) == 40
