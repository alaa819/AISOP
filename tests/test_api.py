from fastapi.testclient import TestClient

from app.api.main import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "AISOP API"


def test_alerts_endpoint():
    response = client.get("/api/v1/alerts")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "limit" in data
    assert "offset" in data
    assert "alerts" in data


def test_statistics_endpoint():
    response = client.get("/api/v1/statistics")

    assert response.status_code == 200

    data = response.json()

    assert "total_alerts" in data
    assert "severity" in data


def test_invalid_severity():
    response = client.get(
        "/api/v1/alerts?severity=banana"
    )

    assert response.status_code == 400


def test_invalid_alert_id():
    response = client.get("/api/v1/alerts/0")

    assert response.status_code == 400


def test_missing_alert():
    response = client.get("/api/v1/alerts/999999")

    assert response.status_code == 404