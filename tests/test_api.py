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
        # ---------------------------------------------------------
# Security headers
# ---------------------------------------------------------


def test_security_headers():
    response = client.get(
        "/api/v1/health"
    )

    assert response.status_code == 200

    assert response.headers[
        "X-Content-Type-Options"
    ] == "nosniff"

    assert response.headers[
        "X-Frame-Options"
    ] == "DENY"

    assert response.headers[
        "Referrer-Policy"
    ] == "no-referrer"

    assert response.headers[
        "Content-Security-Policy"
    ] == "default-src 'self'"
    # ---------------------------------------------------------
# CORS
# ---------------------------------------------------------


def test_cors_allows_configured_origin():
    response = client.get(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:3000",
        },
    )

    assert response.status_code == 200

    assert response.headers[
        "access-control-allow-origin"
    ] == "http://localhost:3000"


def test_cors_rejects_unconfigured_origin():
    response = client.get(
        "/api/v1/health",
        headers={
            "Origin": "http://malicious-example.com",
        },
    )

    assert response.status_code == 200

    assert (
        "access-control-allow-origin"
        not in response.headers
    )
    # ---------------------------------------------------------
# Request IDs
# ---------------------------------------------------------


def test_request_id_is_generated():
    response = client.get(
        "/api/v1/health"
    )

    assert response.status_code == 200

    request_id = response.headers.get(
        "X-Request-ID"
    )

    assert request_id is not None

    import uuid

    uuid.UUID(request_id)


def test_request_id_is_preserved():
    request_id = "test-request-123"

    response = client.get(
        "/api/v1/health",
        headers={
            "X-Request-ID": request_id,
        },
    )

    assert response.status_code == 200

    assert response.headers[
        "X-Request-ID"
    ] == request_id