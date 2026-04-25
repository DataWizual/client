import os
import enum
import logging
from uuid import uuid4
from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Float,
    create_engine,
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, declarative_base, sessionmaker
from sqlalchemy.sql import func

logger = logging.getLogger(__name__)

# Extract DB host early — needed for SSL mode decision
db_host = os.getenv("DB_HOST", "127.0.0.1")

# Database connection configuration with environment fallbacks
DB_URL = os.getenv("AUDITOR_DB_URL")

if not DB_URL:
    user = os.getenv("DB_USER", "auditor")
    password = os.getenv("DB_PASSWORD")
    if not password:
        raise EnvironmentError(
            "DB_PASSWORD environment variable is not set. "
            "Cannot connect to database without explicit credentials."
        )
    port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", "auditor_pro")
    DB_URL = f"postgresql://{user}:{password}@{db_host}:{port}/{db_name}"
    # ✅ Clear password from memory after use
    del password

# SSL configuration: smart defaults
# - Local connections (127.0.0.1/localhost): sslmode='prefer' (SSL optional)
# - Remote connections: sslmode='require' (SSL mandatory)
# - Override with DB_SSLMODE env var
is_local = db_host in ("127.0.0.1", "localhost")
default_ssl = "prefer" if is_local else "require"
ssl_mode = os.getenv("DB_SSLMODE", default_ssl)
connect_args = {"sslmode": ssl_mode} if "postgresql" in DB_URL else {}


def get_engine():
    """Lazy engine factory — creates engine only when first called."""
    return create_engine(
        DB_URL,
        connect_args=connect_args,
        pool_pre_ping=True,
        echo=False,
    )


engine = get_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ValidationStatus(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    WONTFIX = "wontfix"


class Client(Base):
    """
    Top-level organizational entity representing a customer or department.
    """

    __tablename__ = "clients"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False, unique=True)
    contact_email = Column(String(255))
    created_at = Column(DateTime, server_default=func.now())
    projects = relationship(
        "Project",
        back_populates="client",
        lazy="selectin",
    )


class Project(Base):
    """
    Represents a specific source code repository or infrastructure project.
    """

    __tablename__ = "projects"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    client_id = Column(UUID(as_uuid=True), ForeignKey("clients.id"), nullable=False)
    name = Column(String(255), nullable=False)
    repository_url = Column(String(1000))

    client = relationship("Client", back_populates="projects")
    scans = relationship(
        "ScanRecord",
        back_populates="project",
        lazy="selectin",
    )
    baseline_rules = relationship(
        "BaselineRule",
        back_populates="project",
        lazy="selectin",
    )


class ScanRecord(Base):
    """
    Historical log of an individual security audit execution.
    """

    __tablename__ = "scan_records"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    started_at = Column(DateTime, server_default=func.now())
    finished_at = Column(DateTime, server_default=func.now())
    status = Column(String(100))  # e.g., COMPLETED, FAILED
    # triggered_by = Column(String, nullable=True, default="manual")
    decision_action = Column(String(100))  # e.g., PASS, FAIL, WARN
    rationale = Column(Text)

    project = relationship("Project", back_populates="scans")
    findings = relationship(
        "FindingRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class FindingRecord(Base):
    __tablename__ = "findings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_records.id"), nullable=False)
    rule_id = Column(String, index=True, nullable=False)
    file_path = Column(String, index=True, nullable=False)
    line = Column(Integer, nullable=False)
    column = Column(Integer, default=0)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    cvss_score = Column(Float, default=0.0)
    detector = Column(String(100), index=True)
    status = Column(SQLEnum(ValidationStatus), default=ValidationStatus.PENDING)
    found_at = Column(DateTime, server_default=func.now())
    reach_status = Column(String(20), nullable=True, default="UNKNOWN")

    scan = relationship(
        "ScanRecord",
        back_populates="findings",
        lazy="selectin",
    )


class SystemMetadata(Base):
    """
    Persistent storage for system-wide configuration, license keys, and DB versioning.
    Recovered from legacy version (RCA Item 10).
    """

    __tablename__ = "system_metadata"
    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class BaselineRule(Base):
    """
    Global or project-specific rules to suppress or downgrade specific findings.
    Ensures 'Most Specific Rule Wins' logic during matching.
    """

    __tablename__ = "baseline_rules"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    rule_id = Column(String, index=True, nullable=False)
    path_glob = Column(Text)
    action = Column(String(100), nullable=False)  # e.g., suppress, downgrade
    is_active = Column(Boolean, default=True)

    project = relationship(
        "Project",
        back_populates="baseline_rules",
        lazy="selectin",
    )


def init_db():
    """Initializes database schema and creates all tables."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")


if __name__ == "__main__":
    # Safety gate for automated schema creation
    if os.getenv("ALLOW_INIT_DB") == "true":
        init_db()
    else:
        print("Error: Automated DB init is disabled. Set ALLOW_INIT_DB=true to run.")
