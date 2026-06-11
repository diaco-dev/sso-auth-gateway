# models.py - Complete user and OAuth models
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
import uuid
from sqlalchemy.dialects.postgresql import UUID
Base = declarative_base()


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    VIEWER = "viewer"


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(50))
    last_name = Column(String(50))
    mobile = Column(String(20), unique=True, index=True, nullable=True)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    is_verified = Column(Boolean, default=False)
    # Relationships
    tokens = relationship("Token", back_populates="user")
    authorization_codes = relationship("AuthorizationCode", back_populates="user")


class OAuth2Client(Base):
    __tablename__ = "oauth2_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, index=True)
    client_id = Column(String(100), unique=True, index=True, nullable=False)
    client_secret = Column(String(255), nullable=False)
    client_name = Column(String(100), nullable=False)
    redirect_uris = Column(Text, nullable=False)  # JSON string
    allowed_scopes = Column(Text, default="openid profile email")
    client_type = Column(String(20), default="confidential")  # confidential, public
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, index=True)
    code = Column(String(255), unique=True, index=True, nullable=False)
    client_id = Column(String(100), ForeignKey("oauth2_clients.client_id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    scope = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="authorization_codes")
    client = relationship("OAuth2Client")


class Token(Base):
    __tablename__ = "tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, index=True)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(String(255), unique=True, index=True)
    client_id = Column(String(255), ForeignKey("oauth2_clients.client_id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    scope = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    audience = Column(String(100))
    revoked = Column(Boolean, default=False)
    replaced_by = Column(String, nullable=True)
    # Relationships
    user = relationship("User", back_populates="tokens")
    client = relationship("OAuth2Client")
