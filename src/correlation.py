class CorrelationEngine:
    """
    Correlates behavioral findings to identify related suspicious activity.
    """

    def __init__(self, rules):
        self.rules = rules

    def correlate(self, findings):
        """
        Check findings against configured correlation rules.
        """

        correlations = []

        correlation_rules = self.rules.get(
            "correlations",
            {}
        )

        finding_types = {
            finding["type"]
            for finding in findings
        }

        for rule_name, rule in correlation_rules.items():

            required_findings = set(
                rule.get("findings", [])
            )

            if required_findings.issubset(finding_types):

                correlations.append({
                    "type": "CORRELATED_SUSPICIOUS_ACTIVITY",
                    "rule": rule_name,
                    "findings": list(required_findings),
                    "risk_bonus": rule.get("risk_bonus", 0),
                    "severity": rule.get("severity"),
                    "description": rule.get("description"),
                    "evidence": [
                        f"{finding_type} detected"
                        for finding_type in required_findings
                    ],
                })

        return correlations