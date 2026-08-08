from app.core.detector import DetectionEngine


def test_failed_ssh_detection():

    logs = [
        {
            "timestamp": "Aug 08 21:00:00",
            "host": "aisop-server",
            "service": "sshd",
            "message": "Failed password for admin from 192.168.1.50 port 22 ssh2",
            "raw": "Aug 08 21:00:00 aisop-server sshd: Failed password for admin from 192.168.1.50 port 22 ssh2",
        }
    ]

    engine = DetectionEngine()

    alerts = engine.detect(logs)

    assert len(alerts) == 1

    assert alerts[0].rule_id == "AUTH-001"

    assert alerts[0].title == "Failed SSH Authentication"

    assert alerts[0].severity == "MEDIUM"

    assert alerts[0].risk_score == 50