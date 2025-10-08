import jwt
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.core.config import settings
from app.models import User, OAuth2Client, AuthorizationCode, Token

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


#--------------------------------------- Load RSA keys
def load_keys():
    keys_dir = Path("../keys")
    keys_dir.mkdir(exist_ok=True)

    private_key_path = Path(settings.PRIVATE_KEY_PATH)
    public_key_path = Path(settings.PUBLIC_KEY_PATH)

    # Generate keys if they don't exist
    if not private_key_path.exists() or not public_key_path.exists():
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Save private key
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        public_key = private_key.public_key()
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    # Load keys
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return private_key, public_key

private_key, public_key = load_keys()

#--------------------------------------- Hash Password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

#--------------------------------------- Verify password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def generate_jwt(user_id: int, client_id: str, scope: str, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "client_id": client_id,
        "scope": scope,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
        "iss": "oauth-idp",
    }
    return jwt.encode(payload, private_key, algorithm=settings.ALGORITHM)


def validate_client(db: Session, client_id: str, client_secret: str) -> bool:
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()
    return client and client.client_secret == client_secret


def authenticate_user(db: Session, username: str, password: str) -> User:
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return None
    if user.status != "active":
        return None
    return user


def generate_authorization_code(db: Session, client_id: str, user_id: int, scope: str) -> str:
    code = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    auth_code = AuthorizationCode(
        code=code,
        client_id=client_id,
        user_id=user_id,
        scope=scope,
        expires_at=expires_at
    )
    db.add(auth_code)
    db.commit()
    return code


def generate_tokens(db: Session, client_id: str, user_id: int, scope: str, role: str) -> dict:
    access_token = generate_jwt(user_id, client_id, scope, role)
    refresh_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    token = Token(
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=client_id,
        user_id=user_id,
        scope=scope,
        expires_at=expires_at
    )
    db.add(token)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "token_type": "Bearer",
        "scope": scope,
    }

def generate_jwt_role(user_id: int, client_id: str, scope: str, role: str, audience: str) -> str:
    payload = {
        "sub": str(user_id),
        "client_id": client_id,
        "scope": scope,
        "role": role,
        "aud": audience,  # <-- اضافه شد
        "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
        "iss": "oauth-idp",
    }
    return jwt.encode(payload, private_key, algorithm=settings.ALGORITHM)


def generate_tokens_role(db: Session, client_id: str, user_id: int, scope: str, role: str, audience: str) -> dict:
    access_token = generate_jwt_role(user_id, client_id, scope, role, audience)
    refresh_token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    token = Token(
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=client_id,
        user_id=user_id,
        scope=scope,
        expires_at=expires_at
    )
    db.add(token)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "token_type": "Bearer",
        "scope": scope,
    }