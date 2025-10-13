# schemas.py - Pydantic models
from pydantic import BaseModel, EmailStr,Field,validator
from typing import Optional, List, Literal
from enum import Enum
from uuid import UUID
from datetime import datetime
from app.core.config import settings


class UserRoleSchema(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    VIEWER = "viewer"

class UserStatusSchema(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    mobile: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: Optional[UserRoleSchema] = UserRoleSchema.USER

class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    mobile: str
    first_name: Optional[str]
    last_name: Optional[str]
    role: UserRoleSchema
    status: UserStatusSchema
    created_at: datetime
    last_login: Optional[datetime]


class UserInfo(BaseModel):
    sub: str
    username: str
    email: str
    mobile: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role: str
    status: str

class ClientRegister(BaseModel):
    client_name: str
    redirect_uris: List[str]
    allowed_scopes: Optional[str] = "openid profile email"

class ClientResponse(BaseModel):
    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: List[str]


class LoginRequest(BaseModel):
    username: str
    password: str
    client_id: Optional[str] = settings.OAUTH_CLIENT_ID
    scope: Optional[str] = "openid profile email"
    state: Optional[str] = None

class LoginPasswordRequest(BaseModel):
    email_or_mobile: str
    password: str
    client_id: Optional[str] = settings.OAUTH_CLIENT_ID
    scope: Optional[str] = "openid profile email"
    state: Optional[str] = None


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"
    user: dict
    scope: str

class AuthorizeRequest(BaseModel):
    client_id: str
    redirect_uri: str
    scope: str = "openid profile email"
    response_type: str = "code"
    state: Optional[str] = None

class AuthorizeResponse(BaseModel):
    client_valid: bool
    client_name: Optional[str] = None
    requested_scopes: list
    state: Optional[str] = None
    message: str



class SendCodeRequest(BaseModel):
    email_or_mobile: str
    mode: Literal["register", "login", "forgot_password"]

class LoginOtpRequest(BaseModel):
    email_or_mobile: str
    code: str
    state: str | None = None
    scope: str = "openid profile"

class LoginOtpResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str
    user: dict
    scope: str | None
    state: str
    redirect_url: str


class RegisterRequest(BaseModel):
    email_or_mobile: Optional[str] = ""
    email: str
    mobile: str
    code: str
    first_name: Optional[str] = ""
    last_name: Optional[str] = ""
    password: str
    re_password: str


class RegisterResponse(BaseModel):
    message: str



class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=6)
    password: str = Field(..., min_length=8)
    re_password: str = Field(..., min_length=8)
    @validator("re_password")
    def passwords_match(cls, v, values):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v

class ChangePasswordResponse(BaseModel):
    message: str

class ResetPasswordRequest(BaseModel):
    email_or_mobile: str
    code: str
    password: str = Field(..., min_length=8)
    re_password: str = Field(..., min_length=8)

    @validator("re_password")
    def passwords_match(cls, v, values):
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v

class ResetPasswordResponse(BaseModel):
    message: str