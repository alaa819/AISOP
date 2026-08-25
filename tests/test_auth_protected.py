from fastapi.testclient import TestClient

from app.api.main import app
from app.core.security.token import create_access_token


client = TestClient(app)


def test_alerts_requires_authentication():
    response = client.get(
        "/api/v1/alerts"
    )

    assert response.status_code == 401


def test_statistics_requires_authentication():
    response = client.get(
        "/api/v1/statistics"
    )

    assert response.status_code == 401


def test_health_is_public():
    response = client.get(
        "/api/v1/health"
    )

    assert response.status_code == 200


def test_alerts_accepts_valid_token():
    token = create_access_token(
        "ala",
        "ADMIN",
    )

    response = client.get(
        "/api/v1/alerts",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 200