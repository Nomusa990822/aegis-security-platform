from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IPClassification(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    UNSPECIFIED = "unspecified"


class EnrichmentStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class ProviderStatus(str, Enum):
    SUCCESS = "success"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class IPAddressRequest(BaseModel):
    ip_address: str = Field(
        ...,
        description="IPv4 or IPv6 address to investigate",
        examples=["8.8.8.8"],
    )

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("A valid IPv4 or IPv6 address is required") from exc


class ProviderResult(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    provider: str
    status: ProviderStatus
    reputation: str | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    error: str | None = None


class IPIntelligenceAssessment(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    ip_address: str
    classification: IPClassification
    is_global: bool
    enrichment_status: EnrichmentStatus = EnrichmentStatus.PENDING
    threat_score: int = Field(default=0, ge=0, le=100)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reputation: str = "unknown"
    categories: list[str] = Field(default_factory=list)
    provider_results: list[ProviderResult] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    assessed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError("A valid IPv4 or IPv6 address is required") from exc
