from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.db.models import ScanStatusEnum


class ScanOptions(BaseModel):
    ssl_scan: bool = True
    headers_scan: bool = True
    port_scan: bool = True
    tech_scan: bool = True
    subdomain_scan: bool = True
    port_list: list[int] | None = None


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
