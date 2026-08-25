from typing import Any

from fastapi import APIRouter, Depends

from app.api.dependencies import require_roles


router = APIRouter(
    prefix="/admin",
    tags=["Administration"],
)


@router.get("/status")
def admin_status(
    current_user: dict = Depends(
        require_roles("ADMIN")
    ),
) -> dict[str, Any]:
    """
    Return administrative system information.

    ADMIN role required.
    """

    return {
        "message": "Administrative access granted.",
        "user": current_user["username"],
        "role": current_user["role"],
    }