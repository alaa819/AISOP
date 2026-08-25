from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user
from app.api.main import app


client = TestClient(app)


def override_get_current_user() -> dict:
    return {
        "sub": "test-user",
        "role": "ADMIN",
    }


def test_health_endpoint():
    response = client.get("/api/v1/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "AISOP API"


def test_alerts_endpoint():
    app.dependency_overrides[get_current_user] = override_get_current_user

    try:
        response = client.get("/api/v1/alerts")

        assert response.status_code == 200

        data = response.json()

        assert "count" in data
        assert "limit" in data
        assert "offset" in data
        assert "alerts" in data

    finally:
        app.dependency_overrides.clear()


def test_statistics_endpoint():
    app.dependency_overrides[get_current_user] = override_get_current_user

    try:
        response = client.get("/api/v1/statistics")

        assert response.status_code == 200

        data = response.json()

        assert "total_alerts" in data
        assert "severity" in data

    finally:
        app.dependency_overrides.clear()


def test_invalid_severity():
    app.dependency_overrides[get_current_user] = override_get_current_user

    try:
        response = client.get(
            "/api/v1/alerts?severity=banana"
        )

        assert response.status_code == 400

    finally:
        app.dependency_overrides.clear()


def test_invalid_alert_id():
    app.dependency_overrides[get_current_user] = override_get_current_user

    try:
        response = client.get("/api/v1/alerts/0")

        assert response.status_code == 400

    finally:
        app.dependency_overrides.clear()


def test_missing_alert():
    app.dependency_overrides[get_current_user] = override_get_current_user

    try:
        response = client.get("/api/v1/alerts/999999")

        assert response.status_code == 404

    finally:
        app.dependency_overrides.clear()