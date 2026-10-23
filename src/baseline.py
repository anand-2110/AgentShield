
from collections import Counter, defaultdict


class BaselineEngine:
    """
    Builds behavioral baselines for individual agents.
    """

    def __init__(self, minimum_events=10):
        if not isinstance(minimum_events, int) or isinstance(minimum_events, bool):
            raise ValueError("minimum_events must be a positive integer")

        if minimum_events < 1:
            raise ValueError("minimum_events must be a positive integer")

        self.minimum_events = minimum_events

    def build(self, events):
        """
        Build a baseline from AgentAction events.

        Empty input returns an empty dictionary.
        Each agent receives an independent baseline.
        """

        agent_data = defaultdict(list)

        for event in events:
            if not all(
                hasattr(event, field)
                for field in (
                    "agent_name",
                    "action_type",
                    "resource",
                    "timestamp",
                    "result",
                )
            ):
                raise ValueError(
                    "Each event must contain all AgentAction fields"
                )

            if not event.agent_name:
                raise ValueError("agent_name cannot be empty")

            agent_data[event.agent_name].append(event)

        baselines = {}

        for agent_name, agent_events in agent_data.items():
            action_counts = Counter(
                event.action_type for event in agent_events
            )

            resource_counts = Counter(
                event.resource for event in agent_events
            )

            total_events = len(agent_events)

            denied_count = sum(
                event.result == "DENIED"
                for event in agent_events
            )

            timestamps = [
                event.timestamp for event in agent_events
            ]

            observation_seconds = (
                max(timestamps) - min(timestamps)
            ).total_seconds()

            baselines[agent_name] = {
                "agent_name": agent_name,
                "total_events": total_events,
                "observation_window_seconds": observation_seconds,
                "action_counts": dict(action_counts),
                "resource_counts": dict(resource_counts),
                "denied_count": denied_count,
                "denial_rate": denied_count / total_events,
                "baseline_mature": (
                    total_events >= self.minimum_events
                ),
            }

        return baselines
