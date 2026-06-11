# config.py - Configuration management
from pydantic_settings import BaseSettings
from typing import Optional
from pydantic import computed_field

class Settings(BaseSettings):
    # Application settings
    APP_NAME: str = "FioTrix SSO"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # PostgreSQL Database settings
    SSO_POSTGRES_HOST: str
    SSO_POSTGRES_PORT: int
    SSO_POSTGRES_USER: str
    SSO_POSTGRES_PASSWORD: str
    SSO_POSTGRES_DB: str
    # DATABASE_URL: Optional[str] = None
    @computed_field
    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql://{self.SSO_POSTGRES_USER}:{self.SSO_POSTGRES_PASSWORD}"
            f"@{self.SSO_POSTGRES_HOST}:{self.SSO_POSTGRES_PORT}/{self.SSO_POSTGRES_DB}"
        )
    # Security
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS: int
    REFRESH_TOKEN_EXPIRE_MINUTES : int

    # Keys
    PRIVATE_KEY_PATH: str
    PUBLIC_KEY_PATH: str

    # CORS
    ALLOWED_ORIGINS: list
    OAUTH_CLIENT_ID: str
    OAUTH_CLIENT_SECRET: str
    OAUTH_REDIRECT_URI: str

    # Redis settings
    REDIS_HOST: str
    REDIS_PORT: int
    REDIS_DB: int =0
    REDIS_PASSWORD: Optional[str] = None
    # REDIS_URL: Optional[str] = None

    @computed_field
    @property
    def REDIS_URL(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # Celery settings
    @computed_field
    @property
    def broker_url(self) -> str:
        return self.REDIS_URL

    @computed_field
    @property
    def result_backend(self) -> str:
        return self.REDIS_URL

    # Email settings
    MAIL_USERNAME: str = "noreply@fiotrix.com"
    MAIL_PASSWORD: str
    MAIL_FROM: str = "noreply@fiotrix.com"
    MAIL_PORT: int = 587         # TLS
    MAIL_SERVER: str
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    USE_CREDENTIALS: bool = True

    farazsms_api_key: str
    farazsms_sender: str ="+983000505"
    FARAZSMS_PATTERN_CODE:str

    # Role redirects
    ROLE_REDIRECTS : dict= {
        "USER": "https://panel.fiotrix.com/",
        "ADMIN": "https://ops.fiotrix.com/",
    }

    # Environment
    ENVIRONMENT: str = "development"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()