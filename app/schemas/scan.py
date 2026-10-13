from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.db.models import ScanStatusEnum


class ScanOptions(BaseModel):
    ssl_scan: bool = True
    headers_scan: bool = True
    port_scan: bool = True
    tech_scan: bool = True
    subdomain_scan: bool = True
    port_list: list[int] | None = None

    @field_validator("port_list")
    @classmethod
    def validate_port_list(cls, v: list[int] | None) -> list[int] | None:
        if v is None:
            return None
        if len(v) == 0:
            raise ValueError("Port list cannot be empty when provided")

        seen: set[int] = set()
        deduped: list[int] = []
        for p in v:
            if not isinstance(p, int) or isinstance(p, bool):
                raise ValueError("All ports must be valid integers")
            if not (1 <= p <= 65535):
                raise ValueError(f"Port number {p} out of valid range 1-65535")
            if p not in seen:
                seen.add(p)
                deduped.append(p)

        if len(deduped) > 50:
            raise ValueError(
                f"Port list exceeds maximum allowed limit of 50 ports (received {len(deduped)})"
            )

        return deduped


class ScanCreateRequest(BaseModel):
    target: str
    options: ScanOptions = Field(default_factory=ScanOptions)


class ScanCreateResponse(BaseModel):
    scan_id: UUID
    status: ScanStatusEnum
    user_id: UUID | None = None


class FindingSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResultPayload(BaseModel):
    target: str
    scanned_at: str
    modules: dict[str, Any] = Field(default_factory=dict)
    summary: FindingSummary = Field(default_factory=FindingSummary)


class ScanDetailResponse(BaseModel):
    scan_id: UUID
    target_url: str
    status: ScanStatusEnum
    created_at: datetime
    updated_at: datetime
    user_id: UUID | None = None
    result: ScanResultPayload | None = None
    error_message: str | None = None
