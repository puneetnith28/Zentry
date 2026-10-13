import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Index, String, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    is_superuser: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    scans: Mapped[list["ScanJob"]] = relationship(
        "ScanJob", back_populates="owner", cascade="all, delete-orphan"
    )


class InvalidStateTransitionError(ValueError):
    """Raised when an invalid scan status transition is attempted."""

    def __init__(self, from_status: "ScanStatusEnum", to_status: "ScanStatusEnum") -> None:
        self.from_status = from_status
        self.to_status = to_status
        super().__init__(
            f"Cannot transition scan job from {from_status.value} to {to_status.value}"
        )


class ScanStatusEnum(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

    @classmethod
    def terminal_statuses(cls) -> set["ScanStatusEnum"]:
        return {cls.COMPLETED, cls.FAILED, cls.CANCELLED}

    @classmethod
    def active_statuses(cls) -> set["ScanStatusEnum"]:
        return {cls.PENDING, cls.RUNNING}

    @classmethod
    def valid_transitions(cls) -> dict["ScanStatusEnum", set["ScanStatusEnum"]]:
        return {
            cls.PENDING: {cls.RUNNING, cls.FAILED, cls.CANCELLED},
            cls.RUNNING: {cls.COMPLETED, cls.FAILED, cls.CANCELLED},
            cls.COMPLETED: set(),
            cls.FAILED: set(),
            cls.CANCELLED: set(),
        }

    def can_transition_to(self, target: "ScanStatusEnum") -> bool:
        return target in self.valid_transitions().get(self, set())


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[ScanStatusEnum] = mapped_column(
        Enum(
            ScanStatusEnum,
            name="scan_status",
            native_enum=False,
            values_callable=lambda obj: [e.value for e in obj],
            length=20,
        ),
        default=ScanStatusEnum.PENDING,
        nullable=False,
        index=True,
    )
    options: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_scan_jobs_user_id_created_at", "user_id", "created_at"),
        Index("ix_scan_jobs_created_at", "created_at"),
    )

    owner: Mapped[User | None] = relationship("User", back_populates="scans")

    def can_transition_to(self, new_status: ScanStatusEnum) -> bool:
        return self.status.can_transition_to(new_status)

    def transition_to(self, new_status: ScanStatusEnum) -> None:
        if not self.can_transition_to(new_status):
            raise InvalidStateTransitionError(self.status, new_status)
        self.status = new_status
