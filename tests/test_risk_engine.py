
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


def test_agent_risk_uses_highest_incident_plus_history():
    risk_engine = RiskEngine("configs/risk_rules.json")

    result = risk_engine.assess_overall_agent_risk(
        incident_risks=[40, 70, 30],
        historical_risk=10
    )

    assert result == 80

def test_agent_risk_without_incidents_uses_history():
    risk_engine = RiskEngine("configs/risk_rules.json")

    result = risk_engine.assess_overall_agent_risk(
        incident_risks=[],
        historical_risk=30
    )

    assert result == 30

def test_overall_agent_risk_is_capped_at_100():
    risk_engine = RiskEngine("configs/risk_rules.json")

    result = risk_engine.assess_overall_agent_risk(
        incident_risks=[80],
        historical_risk=30
    )

    assert result == 100
