from src.confidence import ConfidenceEngine


risk_rules = {
    "sensitive_resources": [
        "payroll.csv",
        "employee_salary.csv",
        "passwords.db",
        "credentials.txt"
    ],
    "code_resources": [
        "source_code.py",
        "config.py",
        "main.py",
        "app.py",
        "requirements.txt"
    ]
}


engine = ConfidenceEngine(risk_rules)


test_cases = [
    {
        "name": "Normal resource",
        "finding": {
            "type": "DENIED_ACTION",
            "evidence": [
                {
                    "action_type": "READ_FILE",
                    "resource": "notes.txt"
                }
            ]
        }
    },
    {
        "name": "Code resource",
        "finding": {
            "type": "CODE_EXTERNAL_COMMUNICATION",
            "evidence": [
                {
                    "action_type": "READ_FILE",
                    "resource": "config.py"
                }
            ]
        }
    },
    {
        "name": "Sensitive resource",
        "finding": {
            "type": "SUSPICIOUS_DATA_FLOW",
            "evidence": [
                {
                    "action_type": "READ_FILE",
                    "resource": "credentials.txt"
                }
            ]
        }
    }
]


for test in test_cases:
    confidence = engine.calculate(test["finding"])

    print(
        f"{test['name']}: "
        f"{confidence:.2f}"
    )
