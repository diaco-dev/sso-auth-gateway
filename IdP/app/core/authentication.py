import uuid
import jwt
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.core.config import settings
from app.models import User, OAuth2Client, AuthorizationCode, Token
import hashlib
from fastapi.security import OAuth2PasswordBearer
import logging
from fastapi import  HTTPException
from fastapi.templating import Jinja2Templates

# --------------------logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------- load template
templates = Jinja2Templates(directory="app/templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

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
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

#--------------------------------------- Hash refresh token
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

#--------------------------------------- Verify password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

#--------------------------------------- validation client id
def validate_client(db: Session, client_id: str, client_secret: str) -> bool:
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()
    return client and client.client_secret == client_secret

#--------------------------------------- authenticate user
def authenticate_user(db: Session, username: str, password: str) -> User:
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return None
    if user.status != "active":
        return None
    return user

#--------------------------------------- authenticate custom
def authenticate_email_mobile(db: Session, email_or_mobile: str, password: str) -> User | None:
    # detect login field
    if "@" in email_or_mobile:
        user = db.query(User).filter(User.email == email_or_mobile).first()
    else:
        user = db.query(User).filter(User.mobile == email_or_mobile).first()

    # validate
    if not user or not verify_password(password, user.password_hash):
        return None
    if user.status != "active":
        return None
    return user

#--------------------------------------- generate code
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

#--------------------------------------- generate basic jwt
# --------------- V2
def generate_jwt(user_id: int, client_id: str, scope: str, role: str) -> str:
    jti = str(uuid.uuid4())

    payload = {
        "sub": str(user_id),
        "client_id": client_id,
        "scope": scope,
        "role": role,
        "aud": client_id,
        "jti": jti,
        "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
        "iss": "oauth-idp",
    }
    return jwt.encode(payload, private_key, algorithm=settings.ALGORITHM)


#v1
# def generate_jwt(user_id: int, client_id: str, scope: str, role: str) -> str:
#     payload = {
#         "sub": str(user_id),
#         "client_id": client_id,
#         "scope": scope,
#         "role": role,
#         "exp": datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
#         "iat": datetime.utcnow(),
#         "iss": "oauth-idp",
#     }
#     return jwt.encode(payload, private_key, algorithm=settings.ALGORITHM)

#--------------------------------------- generate token
def generate_tokens(db: Session, client_id: str, user_id: int, scope: str, role: str) -> dict:
    access_token = generate_jwt(user_id, client_id, scope, role)
    refresh_token = secrets.token_urlsafe(64)
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


#--------------------------------------- generate jwt role base
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

#--------------------------------------- generate token role base
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

#-----------------------------------common function for generating response------------------------------
def build_login_response(db: Session, user: User, scope: str, state: str | None = None):
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Normalize role to uppercase string
    role = str(user.role.value).upper()

    redirect_url = settings.ROLE_REDIRECTS.get(role)
    if not redirect_url:
        raise HTTPException(
            status_code=400,
            detail=f"No panel defined for this role: {role}"
        )

    # Generate authorization code internally (برای SSO)
    auth_code = generate_authorization_code(db, settings.OAUTH_CLIENT_ID, user.id, scope)

    tokens = generate_tokens_role(
        db=db,
        client_id=settings.OAUTH_CLIENT_ID,
        user_id=user.id,
        scope=scope,
        role=role,
        audience=role
    )

    code_obj = db.query(AuthorizationCode).filter(
        AuthorizationCode.code == auth_code
    ).first()
    if code_obj:
        code_obj.used = True
        db.commit()

    user_info = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": role,
        "status": user.status.value
    }

    return {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "expires_in": tokens["expires_in"],
        "token_type": "Bearer",
        "user": user_info,
        "scope": tokens["scope"],
        "state": state or secrets.token_urlsafe(32),
        "redirect_url": redirect_url,
    }