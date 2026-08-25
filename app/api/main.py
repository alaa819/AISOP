from fastapi import FastAPI

from app.api.routes.admin import router as admin_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.auth import router as auth_router
from app.api.routes.health import router as health_router
from app.api.routes.statistics import router as statistics_router
from app.database.schema import initialize_database


app = FastAPI(
    title="AISOP Security Operations Platform API",
    description=(
        "REST API for the AISOP security operations platform. "
        "Provides access to security alerts, statistics, "
        "system health information, authentication, "
        "and administrative operations."
    ),
    version="1.0.0",
)


initialize_database()


app.include_router(
    health_router,
    prefix="/api/v1",
    tags=["Health"],
)


app.include_router(
    auth_router,
    prefix="/api/v1",
    tags=["Authentication"],
)


app.include_router(
    alerts_router,
    prefix="/api/v1",
    tags=["Alerts"],
)


app.include_router(
    statistics_router,
    prefix="/api/v1",
    tags=["Statistics"],
)


app.include_router(
    admin_router,
    prefix="/api/v1",
)