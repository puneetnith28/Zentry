from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ErrorDetail(BaseModel):
    model_config = ConfigDict(extra="allow")

    code: str
    message: str
    request_id: str | None = None
    details: Any | None = None


class StandardErrorResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    detail: Any
    error: ErrorDetail

