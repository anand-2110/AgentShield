class ConfidenceEngine:
    """
    Calculates confidence scores for behavioral findings.
    """

    def __init__(self):
        pass

    def calculate(self, finding):
        """
        Calculate a confidence score between 0.00 and 1.00.
        """

        confidence = 0.50

        evidence = finding.get("evidence", [])

        if evidence:
            confidence += 0.10

        if len(evidence) >= 3:
            confidence += 0.10

        if len(evidence) >= 5:
            confidence += 0.10

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

        return max(0.0, min(confidence, 1.0))