import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.routes.admin import router as admin_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.auth import router as auth_router
from app.api.routes.health import router as health_router
from app.api.routes.statistics import router as statistics_router

from app.core.security.headers import security_headers_middleware
from app.core.security.rate_limit import limiter
from app.core.security.request_id import request_id_middleware

from app.database.schema import initialize_database


logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
    ),
)


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


# ---------------------------------------------------------
# Security middleware
# ---------------------------------------------------------

app.middleware("http")(security_headers_middleware)
app.middleware("http")(request_id_middleware)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Request-ID",
    ],
)


# ---------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


# ---------------------------------------------------------
# Database
# ---------------------------------------------------------

initialize_database()


# ---------------------------------------------------------
# API routes
# ---------------------------------------------------------

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