from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1 import auth, reports, scans
from app.core.config import get_settings
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
    init_db()
    try:
        from app.worker.tasks import recover_stale_scans

        recover_stale_scans()
    except Exception as exc:
        logger.warning("Failed to recover stale scans on startup: %s", exc)
    yield


settings = get_settings()

app = FastAPI(
    title="Zentry",
    description="Scalable Website Security Scanner",
    version="1.0.0",
    lifespan=lifespan,
)


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
def health() -> dict[str, str]:
    return {"status": "ok"}
