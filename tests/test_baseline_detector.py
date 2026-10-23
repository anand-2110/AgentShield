
from datetime import datetime

from src.action import AgentAction
from src.baseline_detector import BaselineDetector


def make_event(
    agent="HR",
    action="READ_DATABASE",
    resource="employee_records",
):
    return AgentAction(
        agent_name=agent,
        action_type=action,
        resource=resource,
        timestamp=datetime(2026, 1, 1),
        result="ALLOWED",
    )


def mature_baseline():
    return {
        "agent_name": "HR",
        "total_events": 10,
        "action_counts": {"READ_DATABASE": 10},
        "resource_counts": {"employee_records": 10},
        "denied_count": 0,
        "denial_rate": 0.0,
        "baseline_mature": True,
    }


def test_known_activity():
    detector = BaselineDetector()

    findings = detector.detect(
        make_event(),
        mature_baseline(),
    )

    assert findings == []


def test_unusual_action():
    detector = BaselineDetector()

    findings = detector.detect(
        make_event(action="DELETE_DATABASE"),
        mature_baseline(),
    )

    assert any(
        finding["type"] == "UNUSUAL_ACTION"
        for finding in findings
    )


def test_unusual_resource():
    detector = BaselineDetector()

    findings = detector.detect(
        make_event(resource="payroll_records"),
        mature_baseline(),
    )

    assert any(
        finding["type"] == "UNUSUAL_RESOURCE"
        for finding in findings
    )


def test_unfamiliar_action_and_resource():
    detector = BaselineDetector()

    findings = detector.detect(
        make_event(
            action="EXPORT_DATABASE",
            resource="customer_secrets",
        ),
        mature_baseline(),
    )

    assert len(findings) == 2


def test_immature_baseline_is_ignored():
    detector = BaselineDetector()
    baseline = mature_baseline()
    baseline["baseline_mature"] = False

    findings = detector.detect(make_event(), baseline)

    assert findings == []


def test_agent_mismatch():
    detector = BaselineDetector()

    try:
        detector.detect(
            make_event(agent="Research"),
            mature_baseline(),
        )
    except ValueError:
        pass
    else:
        raise AssertionError("Expected agent mismatch to raise ValueError")




def test_excessive_activity():
    detector = BaselineDetector(
        volume_multiplier=3,
        minimum_baseline_events=10,
        window_seconds=60,
    )

    baseline = mature_baseline()
    baseline["total_events"] = 60
    baseline["observation_window_seconds"] = 3600

    # Baseline rate: 1 event/minute.
    # Threshold: 3 events/minute.
    findings = detector.detect(
        make_event(),
        baseline,
        recent_event_count=4,
    )

    assert any(
        finding["type"] == "EXCESSIVE_ACTIVITY"
        for finding in findings
    )


def test_normal_activity():
    detector = BaselineDetector(
        volume_multiplier=3,
        minimum_baseline_events=10,
        window_seconds=60,
    )

    baseline = mature_baseline()
    baseline["total_events"] = 60
    baseline["observation_window_seconds"] = 3600

    findings = detector.detect(
        make_event(),
        baseline,
        recent_event_count=2,
    )

    assert not any(
        finding["type"] == "EXCESSIVE_ACTIVITY"
        for finding in findings
    )


def test_zero_duration_baseline_skips_volume_detection():
    detector = BaselineDetector()

    baseline = mature_baseline()
    baseline["total_events"] = 10
    baseline["observation_window_seconds"] = 0

    findings = detector.detect(
        make_event(),
        baseline,
        recent_event_count=100,
    )

    assert not any(
        finding["type"] == "EXCESSIVE_ACTIVITY"
        for finding in findings
    )


def test_zero_duration_baseline_skips_volume_detection():
    detector = BaselineDetector()

    baseline = mature_baseline()
    baseline["total_events"] = 10
    baseline["observation_window_seconds"] = 0

    findings = detector.detect(
        make_event(),
        baseline,
        recent_event_count=100,
    )

    assert not any(
        finding["type"] == "EXCESSIVE_ACTIVITY"
        for finding in findings
    )


def test_invalid_recent_event_count():
    detector = BaselineDetector()

    for count in (-1, True, 1.5):
        try:
            detector.detect(
                make_event(),
                mature_baseline(),
                recent_event_count=count,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "Expected invalid count to raise ValueError"
            )


def test_invalid_volume_multiplier():
    for value in (1, 0, -1, True):
        try:
            BaselineDetector(volume_multiplier=value)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "Expected invalid multiplier to raise ValueError"
            )


if __name__ == "__main__":
    test_known_activity()
    test_unusual_action()
    test_unusual_resource()
    test_unfamiliar_action_and_resource()
    test_immature_baseline_is_ignored()
    test_agent_mismatch()
    test_excessive_activity()
    test_normal_activity()
    test_invalid_recent_event_count()
    test_invalid_volume_multiplier()

    print("All baseline detector tests passed.")
