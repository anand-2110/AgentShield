
from datetime import datetime, timedelta

import pytest

from src.action import AgentAction
from src.baseline import BaselineEngine


def make_event(
    agent="HR",
    action="READ_DATABASE",
    resource="employee_records",
    result="ALLOWED",
    seconds=0,
):
    return AgentAction(
        agent_name=agent,
        action_type=action,
        resource=resource,
        timestamp=datetime(2026, 1, 1) + timedelta(seconds=seconds),
        result=result,
    )


def test_basic_baseline():
    events = [
        make_event(seconds=0),
        make_event(result="DENIED", seconds=10),
        make_event(
            action="READ_FILE",
            resource="leave_policy",
            seconds=20,
        ),
        make_event(
            agent="Research",
            action="READ_FILE",
            resource="research_data",
            seconds=30,
        ),
    ]

    baselines = BaselineEngine().build(events)

    hr = baselines["HR"]

    assert hr["total_events"] == 3
    assert hr["action_counts"]["READ_DATABASE"] == 2
    assert hr["resource_counts"]["employee_records"] == 2
    assert hr["denied_count"] == 1
    assert abs(hr["denial_rate"] - (1 / 3)) < 0.000001
    assert hr["observation_window_seconds"] == 20
    assert not hr["baseline_mature"]

    assert baselines["Research"]["total_events"] == 1


def test_empty_history():
    assert BaselineEngine().build([]) == {}


def test_mature_baseline():
    events = [
        make_event(seconds=i)
        for i in range(10)
    ]

    baseline = BaselineEngine().build(events)["HR"]

    assert baseline["total_events"] == 10
    assert baseline["baseline_mature"]


def test_custom_minimum_events():
    engine = BaselineEngine(minimum_events=2)

    baseline = engine.build([
        make_event(seconds=0),
        make_event(seconds=1),
    ])["HR"]

    assert baseline["baseline_mature"]


def test_invalid_minimum_events():
    for value in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            BaselineEngine(minimum_events=value)


def test_invalid_event():
    class IncompleteEvent:
        agent_name = "HR"

    with pytest.raises(ValueError):
        BaselineEngine().build([IncompleteEvent()])


def test_empty_agent_name():
    with pytest.raises(ValueError):
        BaselineEngine().build([make_event(agent="")])


if __name__ == "__main__":
    test_basic_baseline()
    test_empty_history()
    test_mature_baseline()
    test_custom_minimum_events()
    test_invalid_minimum_events()
    test_invalid_event()
    test_empty_agent_name()

    print("All baseline tests passed.")
