from fastapi.testclient import TestClient

from app.api.main import app
from app.core.security.token import create_access_token


client = TestClient(app)


def get_auth_headers(
    username: str,
    role: str,
) -> dict[str, str]:
    token = create_access_token(
        subject=username,
        role=role,
    )

    return {
        "Authorization": f"Bearer {token}",
    }


# ---------------------------------------------------------
# Authentication tests
# ---------------------------------------------------------


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


def test_admin_requires_authentication():
    response = client.get(
        "/api/v1/admin/status"
    )

    assert response.status_code == 401


def test_health_is_public():
    response = client.get(
        "/api/v1/health"
    )

    assert response.status_code == 200


# ---------------------------------------------------------
# Alerts RBAC
# ---------------------------------------------------------


def test_admin_can_access_alerts():
    response = client.get(
        "/api/v1/alerts",
        headers=get_auth_headers(
            "admin-user",
            "ADMIN",
        ),
    )

    assert response.status_code == 200


def test_analyst_can_access_alerts():
    response = client.get(
        "/api/v1/alerts",
        headers=get_auth_headers(
            "analyst-user",
            "ANALYST",
        ),
    )

    assert response.status_code == 200


def test_viewer_can_access_alerts():
    response = client.get(
        "/api/v1/alerts",
        headers=get_auth_headers(
            "viewer-user",
            "VIEWER",
        ),
    )

    assert response.status_code == 200


# ---------------------------------------------------------
# Statistics RBAC
# ---------------------------------------------------------


def test_admin_can_access_statistics():
    response = client.get(
        "/api/v1/statistics",
        headers=get_auth_headers(
            "admin-user",
            "ADMIN",
        ),
    )

    assert response.status_code == 200


def test_analyst_can_access_statistics():
    response = client.get(
        "/api/v1/statistics",
        headers=get_auth_headers(
            "analyst-user",
            "ANALYST",
        ),
    )

    assert response.status_code == 200


def test_viewer_cannot_access_statistics():
    response = client.get(
        "/api/v1/statistics",
        headers=get_auth_headers(
            "viewer-user",
            "VIEWER",
        ),
    )

    assert response.status_code == 403


# ---------------------------------------------------------
# Admin RBAC
# ---------------------------------------------------------


def test_admin_can_access_admin_status():
    response = client.get(
        "/api/v1/admin/status",
        headers=get_auth_headers(
            "admin-user",
            "ADMIN",
        ),
    )

    assert response.status_code == 200


def test_analyst_cannot_access_admin_status():
    response = client.get(
        "/api/v1/admin/status",
        headers=get_auth_headers(
            "analyst-user",
            "ANALYST",
        ),
    )

    assert response.status_code == 403


def test_viewer_cannot_access_admin_status():
    response = client.get(
        "/api/v1/admin/status",
        headers=get_auth_headers(
            "viewer-user",
            "VIEWER",
        ),
    )

    assert response.status_code == 403