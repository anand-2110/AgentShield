class IncidentSummary:

    def generate(self, incident):
        summary = {
            "incident_id": incident.incident_id,
            "agent": incident.agent_name,
            "severity": incident.severity,
            "status": incident.status,
            "risk": incident.incident_risk,
            "event_count": len(incident.events),
            "findings": incident.findings,
            "risk_factors": incident.risk_factors,
            "description": self._generate_description(incident)
        }

        return summary

    def _generate_description(self, incident):
        descriptions = []

        for finding in incident.findings:

            if "description" in finding:
                description = finding["description"]

                if "source" in finding and "destination" in finding:
                    descriptions.append(
                        f"{description} "
                        f"Source: {finding['source']}. "
                        f"Destination: {finding['destination']}."
                    )

                else:
                    descriptions.append(description)

            elif finding["type"] == "REPEATED_DENIALS":
                descriptions.append(
                    f"{incident.agent_name} generated "
                    f"{finding['count']} denied actions."
                )

            elif finding["type"] == "DENIED_ACTION":
                descriptions.append(
                    f"{incident.agent_name} attempted "
                    f"a restricted action."
                )

        for factor in incident.risk_factors:

            if factor["type"] == "PRIVILEGE_ESCALATION":
                descriptions.append(
                    f"{incident.agent_name} attempted "
                    f"privilege escalation."
                )

            elif factor["type"] == "EXTERNAL_COMMUNICATION":
                descriptions.append(
                    f"{incident.agent_name} attempted "
                    f"external network communication."
                )

        if not descriptions:
            descriptions.append(
                "No significant behavioral findings detected."
            )

        return " ".join(descriptions)