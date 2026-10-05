from src.confidence import ConfidenceEngine


engine = ConfidenceEngine()

finding = {
    "type": "SUSPICIOUS_DATA_FLOW",
    "evidence": [
        {
            "action_type": "READ_DATABASE",
            "resource": "customer_database"
        },
        {
            "action_type": "SEND_DATA",
            "resource": "external_server"
        }
    ],
    "time_difference": 3,
    "within_seconds": 10
}

confidence = engine.calculate(finding)

print(f"Confidence: {confidence}")