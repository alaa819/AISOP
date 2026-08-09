
import pytest

import app.database.connection as connection
from app.database.repository import AlertRepository
from app.database.schema import initialize_database


@pytest.fixture
def test_database(tmp_path, monkeypatch):
    database_directory = tmp_path / "data"
    database_path = database_directory / "test.db"

    monkeypatch.setattr(
        connection,
        "DATABASE_DIR",
        database_directory,
    )

    monkeypatch.setattr(
        connection,
        "DATABASE_PATH",
        database_path,
    )

    initialize_database()

    return database_path


def test_create_and_get_alert(test_database):
    repository = AlertRepository()

    alert = {
        "timestamp": "2026-08-09T12:00:00",
        "host": "aisop-server",
        "service": "sshd",
        "rule_id": "AUTH-001",
        "title": "Failed SSH Authentication",
        "description": "Repeated failed SSH authentication detected.",
        "severity": "HIGH",
        "risk_score": 80,
        "recommendation": "Investigate the source IP.",
        "source_ip": "192.168.1.100",
        "raw_event": {
            "message": "Failed password for invalid user"
        },
        "analysis": "Possible brute-force activity.",
    }

    alert_id = repository.create_alert(alert)

    assert alert_id > 0

    stored_alert = repository.get_alert(alert_id)

    assert stored_alert is not None
    assert stored_alert["rule_id"] == "AUTH-001"
    assert stored_alert["severity"] == "HIGH"
    assert stored_alert["risk_score"] == 80