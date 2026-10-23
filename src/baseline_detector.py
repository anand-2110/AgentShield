
class BaselineDetector:
    """
    Detects deviations from an agent's established behavior.
    Observes activity; does not enforce policies.
    """

    def __init__(
        self,
        volume_multiplier=3.0,
        minimum_baseline_events=10,
        window_seconds=60,
    ):
        if (
            isinstance(volume_multiplier, bool)
            or not isinstance(volume_multiplier, (int, float))
            or volume_multiplier <= 1
        ):
            raise ValueError("volume_multiplier must be greater than 1")

        if (
            isinstance(minimum_baseline_events, bool)
            or not isinstance(minimum_baseline_events, int)
            or minimum_baseline_events < 1
        ):
            raise ValueError("minimum_baseline_events must be positive")

        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds must be positive")

        self.volume_multiplier = volume_multiplier
        self.minimum_baseline_events = minimum_baseline_events
        self.window_seconds = window_seconds

    def detect(self, event, baseline, recent_event_count=None):
        findings = []

        if not baseline or not baseline.get("baseline_mature", False):
            return findings

        agent_name = baseline.get("agent_name")

        if event.agent_name != agent_name:
            raise ValueError("Event agent does not match baseline agent")

        known_actions = baseline.get("action_counts", {})
        if event.action_type not in known_actions:
            findings.append({
                "type": "UNUSUAL_ACTION",
                "agent": agent_name,
                "severity": "MEDIUM",
                "description": (
                    f"Agent performed an action not observed "
                    f"in its baseline: {event.action_type}"
                ),
                "evidence": {"action_type": event.action_type},
            })

        known_resources = baseline.get("resource_counts", {})
        if event.resource not in known_resources:
            findings.append({
                "type": "UNUSUAL_RESOURCE",
                "agent": agent_name,
                "severity": "MEDIUM",
                "description": (
                    f"Agent accessed a resource not observed "
                    f"in its baseline: {event.resource}"
                ),
                "evidence": {"resource": event.resource},
            })

        if recent_event_count is not None:
            if (
                isinstance(recent_event_count, bool)
                or not isinstance(recent_event_count, int)
                or recent_event_count < 0
            ):
                raise ValueError(
                    "recent_event_count must be a non-negative integer"
                )

            total_events = baseline.get("total_events", 0)
            observation_seconds = baseline.get(
                "observation_window_seconds", 0
            )

            valid_history = (
                isinstance(total_events, int)
                and not isinstance(total_events, bool)
                and total_events >= self.minimum_baseline_events
                and isinstance(observation_seconds, (int, float))
                and not isinstance(observation_seconds, bool)
                and observation_seconds > 0
            )

            if valid_history:
                expected_count = (
                    total_events
                    * self.window_seconds
                    / observation_seconds
                )

                threshold = expected_count * self.volume_multiplier

                if recent_event_count > threshold:
                    findings.append({
                        "type": "EXCESSIVE_ACTIVITY",
                        "agent": agent_name,
                        "severity": "HIGH",
                        "description": (
                            "Activity in the configured time window "
                            "exceeds the expected baseline rate."
                        ),
                        "evidence": {
                            "recent_event_count": recent_event_count,
                            "window_seconds": self.window_seconds,
                            "expected_event_count": round(
                                expected_count, 2
                            ),
                            "threshold": round(threshold, 2),
                            "volume_multiplier": self.volume_multiplier,
                        },
                    })

        return findings
