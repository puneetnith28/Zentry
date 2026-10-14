from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1 import auth, reports, scans
from app.core.config import get_settings
from app.core.logging import redact_sensitive_headers
from app.db.session import init_db

logger = logging.getLogger(__name__)

STATUS_CODE_TO_ERROR_CODE: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    409: "CONFLICT",
    413: "PAYLOAD_TOO_LARGE",
    422: "VALIDATION_ERROR",
    429: "RATE_LIMIT_EXCEEDED",
    500: "INTERNAL_SERVER_ERROR",
    502: "BAD_GATEWAY",
    503: "SERVICE_UNAVAILABLE",
    504: "GATEWAY_TIMEOUT",
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from app.core.config import validate_production_security
    validate_production_security(settings)
    from app.core.logging import configure_logging
    configure_logging(level=settings.log_level, json_format=(settings.log_format.lower() == "json"))
    init_db()
    try:
        from app.worker.tasks import recover_stale_scans

        recover_stale_scans()
    except Exception as exc:
        logger.warning("Failed to recover stale scans on startup: %s", exc)
    yield

    # Clean shutdown and resource disposal
    logger.info("Executing graceful shutdown: disposing database pool and connection resources...")
    from app.db.session import dispose_db
    dispose_db()
    try:
        from app.core.celery_app import celery_app
        celery_app.close()
    except Exception as exc:
        logger.warning("Error closing Celery app during shutdown: %s", exc)
    logger.info("Graceful shutdown completed successfully.")



tags_metadata = [
    {
        "name": "Authentication",
        "description": "User registration, authentication, JWT token generation, and account profile management.",
    },
    {
        "name": "Scans",
        "description": "Target submission, active scan lifecycle management, module configuration, and scan results.",
    },
    {
        "name": "Reports",
        "description": "Executive PDF report generation, secure cached downloads, and report metadata.",
    },
    {
        "name": "Health",
        "description": "Operational health probes, readiness checks, and diagnostic component statuses.",
    },
]

settings = get_settings()

app = FastAPI(
    title="Zentry Security Scanner API",
    description="Scalable, defensive website security posture scanner API providing automated risk assessment, non-intrusive network probing, and executive reporting.",
    version="1.0.0",
    openapi_tags=tags_metadata,
    contact={
        "name": "Zentry Security Engineering",
        "email": "security@zentry.local",
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan,
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi
    openapi_schema = get_openapi(
        title="Zentry Security Scanner API",
        version="1.0.0",
        description="Scalable, defensive website security posture scanner API providing automated risk assessment, non-intrusive network probing, and executive reporting.",
        routes=app.routes,
        tags=tags_metadata,
    )
    openapi_schema.setdefault("components", {})["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Enter JWT bearer token acquired from `/api/v1/auth/login`.",
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "Legacy system API key authentication header.",
        },
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID")
    if not req_id or len(req_id) > 64:
        req_id = str(uuid.uuid4())
    request.state.request_id = req_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = req_id
    return response


@app.middleware("http")
async def structured_request_logging_middleware(request: Request, call_next):
    from app.core.proxy import get_client_ip
    req_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    start_time = time.perf_counter()
    client_ip = get_client_ip(request, settings)
    request.state.client_ip = client_ip

    logger.info(
        "Request started: method=%s path=%s client_ip=%s request_id=%s",
        request.method,
        request.url.path,
        client_ip,
        req_id,
    )
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "Request headers: headers=%s request_id=%s",
            redact_sensitive_headers(dict(request.headers)),
            req_id,
        )

    try:
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.info(
            "Request finished: method=%s path=%s status=%s duration_ms=%s request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            req_id,
        )
        return response
    except Exception as exc:
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.error(
            "Request failed: method=%s path=%s duration_ms=%s request_id=%s error=%s",
            request.method,
            request.url.path,
            duration_ms,
            req_id,
            exc,
        )
        raise


@app.middleware("http")
async def limit_request_body_size(request: Request, call_next):
    req_id = getattr(request.state, "request_id", None) or str(uuid.uuid4())
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
            if length > settings.max_request_body_bytes:
                msg = f"Request payload exceeds maximum allowed size of {settings.max_request_body_bytes} bytes."
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={
                        "detail": msg,
                        "error": {
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": msg,
                            "request_id": req_id,
                        },
                    },
                    headers={"X-Request-ID": req_id},
                )
        except ValueError:
            pass

    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()
        if len(body) > settings.max_request_body_bytes:
            msg = f"Request payload exceeds maximum allowed size of {settings.max_request_body_bytes} bytes."
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={
                    "detail": msg,
                    "error": {
                        "code": "PAYLOAD_TOO_LARGE",
                        "message": msg,
                        "request_id": req_id,
                    },
                },
                headers={"X-Request-ID": req_id},
            )

    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=settings.cors_allow_methods,
    allow_headers=settings.cors_allow_headers,
)


@app.exception_handler(StarletteHTTPException)
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException | StarletteHTTPException):
    req_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    code = STATUS_CODE_TO_ERROR_CODE.get(exc.status_code, "ERROR")
    raw_message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    if exc.status_code >= 500:
        logger.error("Server error (%s) on %s [request_id=%s]: %s", exc.status_code, request.url.path, req_id, raw_message)
        message = raw_message if not any(kw in raw_message.lower() for kw in ("traceback", "file \"", "exception", "syntaxerror", "sqlalchemy")) else "An internal server error occurred."
    else:
        message = raw_message
    content = {
        "detail": message,
        "error": {
            "code": code,
            "message": message,
            "request_id": req_id,
        },
    }
    headers = dict(getattr(exc, "headers", None) or {})
    headers["X-Request-ID"] = req_id
    return JSONResponse(
        status_code=exc.status_code,
        content=content,
        headers=headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    errors = jsonable_encoder(exc.errors())
    content = {
        "detail": errors,
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed",
            "request_id": req_id,
            "details": errors,
        },
    }
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=content,
        headers={"X-Request-ID": req_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID") or str(uuid.uuid4())
    logger.exception("Unhandled server exception [request_id=%s]: %s", req_id, exc)
    content = {
        "detail": "An internal server error occurred.",
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An internal server error occurred.",
            "request_id": req_id,
        },
    }
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=content,
        headers={"X-Request-ID": req_id},
    )


app.include_router(auth.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


@app.get("/health")
def health() -> JSONResponse:
    from sqlalchemy import text
    from app.db.session import engine
    from app.core.celery_app import celery_app

    db_status = "healthy"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        logger.warning("Database health check probe failed: %s", exc)
        db_status = "unhealthy"

    broker_status = "healthy"
    try:
        broker_url = settings.celery_broker_url
        if broker_url.startswith("redis://"):
            r = redis.Redis.from_url(
                broker_url,
                socket_timeout=settings.redis_socket_timeout,
                socket_connect_timeout=settings.redis_socket_connect_timeout,
            )
            r.ping()
            r.close()
        else:
            with celery_app.connection_for_read() as conn:
                conn.connect()
    except Exception as exc:
        logger.warning("Broker health check probe failed: %s", exc)
        broker_status = "unhealthy"

    is_healthy = (db_status == "healthy" and broker_status == "healthy")
    payload = {
        "status": "ok" if is_healthy else "unhealthy",
        "components": {
            "database": {"status": db_status},
            "broker": {"status": broker_status},
        },
    }
    return JSONResponse(
        status_code=status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
        content=payload,
    )

