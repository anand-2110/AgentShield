class ConfidenceEngine:
    """
    Calculates confidence scores for behavioral findings.
    """

    def __init__(self, risk_rules):
        self.risk_rules = risk_rules

    def calculate(self, finding):
        """
        Calculate a confidence score between 0.00 and 1.00.
        """

        confidence = 0.50

        # Evidence strength
        evidence = finding.get("evidence", [])

        if evidence:
            confidence += 0.10

        if len(evidence) >= 3:
            confidence += 0.10

        if len(evidence) >= 5:
            confidence += 0.10

        # Temporal proximity
        time_difference = finding.get("time_difference")
        within_seconds = finding.get("within_seconds")

        if (
            time_difference is not None
            and within_seconds is not None
            and within_seconds > 0
        ):
            temporal_ratio = time_difference / within_seconds

            if temporal_ratio <= 0.25:
                confidence += 0.15

            elif temporal_ratio <= 0.50:
                confidence += 0.10

            elif temporal_ratio <= 0.75:
                confidence += 0.05

        # Historical repetition
        occurrences = finding.get("occurrences", 1)

        if occurrences >= 2:
            confidence += 0.05

        if occurrences >= 3:
            confidence += 0.05

        if occurrences >= 5:
            confidence += 0.05

        # Resource sensitivity
        resource_bonus = 0.0

        finding_type = finding.get("type")

        resource_sensitive_findings = {
            "SUSPICIOUS_DATA_FLOW",
            "PRIVILEGE_SENSITIVE_ACCESS",
            "MASS_DATA_ACCESS",
            "CODE_EXTERNAL_COMMUNICATION",
        }

        if finding_type in resource_sensitive_findings:

            sensitive_resources = self.risk_rules.get(
                "sensitive_resources",
                []
            )

            code_resources = self.risk_rules.get(
                "code_resources",
                []
            )

            for item in evidence:
                resource = item.get("resource")

                if resource in sensitive_resources:
                    resource_bonus = max(resource_bonus, 0.10)

                elif resource in code_resources:
                    resource_bonus = max(resource_bonus, 0.05)

        confidence += resource_bonus

        return round(max(0.0, min(confidence, 1.0)), 2)
