from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import auth, reports, scans
from app.core.config import get_settings
from app.db.session import init_db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


settings = get_settings()

app = FastAPI(
    title="Zentry",
    description="Scalable Website Security Scanner",
    version="1.0.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def limit_request_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
            if length > settings.max_request_body_bytes:
                return JSONResponse(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    content={
                        "detail": f"Request payload exceeds maximum allowed size of {settings.max_request_body_bytes} bytes."
                    },
                )
        except ValueError:
            pass

    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()
        if len(body) > settings.max_request_body_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={
                    "detail": f"Request payload exceeds maximum allowed size of {settings.max_request_body_bytes} bytes."
                },
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

app.include_router(auth.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
