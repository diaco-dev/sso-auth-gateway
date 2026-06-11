# main.py - FastAPI application
from fastapi import FastAPI, Form, Request, Depends
from fastapi.exceptions import RequestValidationError
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
import json
from app.core.database import engine, get_db
from .models import Base
from .schemas import *
from app.core.authentication import *
from app.core.config import settings
from jose import jwt, JWTError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from .utils.exception import http_exception_handler, request_validation_exception_handler, general_exception_handler
# Routers
from app.routers.auth import router as auth_router
from app.routers.core import router as core_router
import hashlib
bearer_scheme = HTTPBearer()

# ============================================================
#API
# ============================================================
# Tags metadata for Swagger/Redoc
TAGS_META = [
    {"name": "Auth", "description": "OAuth 2.0 connection & authentication."},
    {"name": "Core", "description": "Core application endpoints."},
    {"name": "System", "description": "System, health, and monitoring."},
]

# Prefix → Tag mapping for auto-tagging
PREFIX_TO_TAG = {
    "/api/v1/auth": "Auth",
    "/api/v1/core": "Core",
    "/health": "System",
    "/metrics": "System",
    "/": "System",
}

def _infer_tag(path: str) -> str:
    """Infer tag from path prefix."""
    for p in sorted(PREFIX_TO_TAG, key=len, reverse=True):
        if path.startswith(p):
            return PREFIX_TO_TAG[p]
    return "System"

# ============================================================
# Lifespan context manager
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown events."""
    print(" Starting FioTrix AI application...")

    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
        print("Database tables ready")
    except Exception as e:
        error_str = str(e)
        if (
            "already exists" in error_str
            and ("idx_" in error_str or "relation" in error_str or "duplicate" in error_str.lower())
        ):
            print("Tables or indexes already exist — safe to ignore")
        else:
            print(f"Error creating tables: {e}")

    yield
    print("Shutting down FioTrix application...")


# ============================================================
# App Configuration
# ============================================================
app = FastAPI(
    title="OAuth Identity Provider",
    description="Production-ready OAuth 2.0 Identity Provider with RBAC",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
    openapi_tags=TAGS_META,
)
# ============================================================
# CORS
# ============================================================
origins=["http://localhost:5174", "http://127.0.0.1:5174", "https://account.fiotrix.com", "https://ops.fiotrix.com","https://panel.fiotrix.com","https://dejban.fiotrix.com"]
app.add_middleware(
    CORSMiddleware,
    # allow_origins=settings.ALLOWED_ORIGINS,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Routers
# ============================================================
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(core_router, prefix="/api/v1/core", tags=["Core"])

# ============================================================
# Exception handlers (global)
# ============================================================
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, request_validation_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)


# ============================================================
# Health check system
# ============================================================
@app.get("/health", tags=["System"], summary="Health check")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

# Root endpoint
@app.get("/", tags=["System"], summary="Root endpoint")
async def root():
    return {
        "message": "CEOAssist Core API is running",
        "version": "v1",
        "status": "healthy",
    }

# Debug: list all routes
@app.get("/__routes__", include_in_schema=False)
def list_routes():
    """List all registered routes (debugging)."""
    out = []
    for r in app.routes:
        methods = getattr(r, "methods", None)
        path = getattr(r, "path", None)
        name = getattr(r, "name", None)
        if methods and path:
            out.append({"methods": sorted(list(methods)), "path": path, "name": name})
    return sorted(out, key=lambda x: x["path"])


# ----------------------------------------------------------------------------------------------------------------------
# Client Registration Endpoint
# ----------------------------------------------------------------------------------------------------------------------
@app.post("/register-client", response_model=ClientResponse, include_in_schema=False)
async def register_client(client_data: ClientRegister, db: Session = Depends(get_db)):
    """Register a new OAuth client"""
    client_id = f"client_{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)

    client = OAuth2Client(
        client_id=client_id,
        client_secret=client_secret,
        client_name=client_data.client_name,
        redirect_uris=json.dumps(client_data.redirect_uris),
        allowed_scopes=client_data.allowed_scopes
    )

    db.add(client)
    db.commit()

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_data.client_name,
        "redirect_uris": client_data.redirect_uris
    }

# ----------------------------------------------------------------------------------------------------------------------
# Replace the existing /authorize endpoint with this:
# ----------------------------------------------------------------------------------------------------------------------
@app.post("/authorize", response_model=AuthorizeResponse, include_in_schema=False)
async def authorize(request: AuthorizeRequest, db: Session = Depends(get_db)):
    """Validate OAuth client and return client info for frontend"""
    if request.response_type != "code":
        raise HTTPException(status_code=400, detail="Invalid response_type. Only 'code' is supported")

    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == request.client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client:
        return AuthorizeResponse(
            client_valid=False,
            requested_scopes=[],
            state=request.state,
            message="Invalid client_id"
        )

    redirect_uris = json.loads(client.redirect_uris)
    if request.redirect_uri not in redirect_uris:
        return AuthorizeResponse(
            client_valid=False,
            client_name=client.client_name,
            requested_scopes=[],
            state=request.state,
            message="Invalid redirect_uri"
        )

    requested_scopes = request.scope.split(" ") if request.scope else []

    return AuthorizeResponse(
        client_valid=True,
        client_name=client.client_name,
        requested_scopes=requested_scopes,
        state=request.state,
        message="Client validation successful. Proceed with login."
    )

# ----------------------------------------------------------------------------------------------------------------------
# login
# ----------------------------------------------------------------------------------------------------------------------
@app.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Direct login endpoint that returns tokens and user info"""

    # Authenticate user
    user = authenticate_user(db, request.username, request.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Generate tokens
    tokens = generate_tokens(db, request.client_id or "direct", user.id, request.scope, user.role.value)

    # Prepare user info
    user_info = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "mobile": user.mobile,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role.value,
        "status": user.status.value
    }

    return LoginResponse(
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        expires_in=tokens["expires_in"],
        token_type=tokens["token_type"],
        user=user_info,
        scope=tokens["scope"]
    )

# ----------------------------------------------------------------------------------------------------------------------
# oauth
# ----------------------------------------------------------------------------------------------------------------------
@app.post("/oauth/authorize" , include_in_schema=False)
async def oauth_authorize(
        username: str = Form(...),
        password: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        scope: str = Form(...),
        state: str = Form(None),
        db: Session = Depends(get_db)
):
    """Generate authorization code for OAuth flow (for compatibility with existing OAuth clients)"""

    # Validate client
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == client_id,
        OAuth2Client.is_active == True
    ).first()

    if not client:
        raise HTTPException(status_code=400, detail="Invalid client")

    redirect_uris = json.loads(client.redirect_uris)
    if redirect_uri not in redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid redirect URI")

    # Authenticate user
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Generate authorization code
    code = generate_authorization_code(db, client_id, user.id, scope)

    # Return JSON instead of redirect
    return {
        "code": code,
        "state": state,
        "redirect_uri": redirect_uri,
        "message": "Authorization code generated successfully"
    }



# ----------------------------------------------------------------------------------------------------------------------
# # Add refresh token endpoint:
# ----------------------------------------------------------------------------------------------------------------------

@app.post("/refresh")
async def refresh_token(
    request: Request,
    db: Session = Depends(get_db)
):
    print("🚀 [refresh_token] called")

    # 🔹 گرفتن refresh_token از cookie
    refresh_token = request.cookies.get("refresh_token")
    print(f"🔹 refresh_token from cookie: {refresh_token[:10]}..." if refresh_token else "❌ No refresh_token cookie found")

    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token not provided")

    refresh_hash = hash_token(refresh_token)
    print(f"🔹 refresh_hash: {refresh_hash}")

    token_obj = db.query(Token).filter(
        Token.refresh_token == refresh_hash,
        Token.revoked == False
    ).first()

    if not token_obj:
        print("❌ Token not found or revoked")
        raise HTTPException(status_code=400, detail="Invalid or expired refresh token")

    if token_obj.expires_at < datetime.utcnow():
        print("❌ Token expired")
        raise HTTPException(status_code=400, detail="Expired refresh token")

    # 🔹 گرفتن user
    user = db.query(User).filter(User.id == token_obj.user_id).first()
    if not user:
        print("❌ User not found")
        raise HTTPException(status_code=401, detail="User not found")

    if user.status != "active":
        print(f"❌ User inactive: {user.status}")
        raise HTTPException(status_code=401, detail="User not active")

    # 🔹 revoke توکن قدیمی
    token_obj.revoked = True

    # 🔹 ساخت توکن جدید
    new_tokens = generate_tokens(
        db=db,
        client_id=token_obj.client_id,
        user_id=token_obj.user_id,
        scope=token_obj.scope,
        role=user.role.value
    )

    token_obj.replaced_by = hash_token(new_tokens["refresh_token"])
    db.commit()
    print("💾 Tokens updated and committed")

    # ✅ ست‌کردن کوکی جدید
    response = JSONResponse(content={
        "expires_in": new_tokens["expires_in"],
        "token_type": new_tokens["token_type"],
        "scope": new_tokens["scope"],
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "mobile": user.mobile,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role.value,
            "status": user.status.value,
        }
    })

    response.set_cookie(
        key="refresh_token",
        value=new_tokens["refresh_token"],
        domain=".fiotrix.com",
        path="/",
        httponly=True,
        secure=True,
        samesite="None",
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60 - 2
    )
    response.set_cookie(
        key="access_token",
        value=new_tokens["access_token"],
        httponly=True,
        domain=".fiotrix.com",
        secure=True,
        samesite="Lax",
        path="/",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60 - 2
    )
    print("✅ Refresh successful")
    return response


# ----------------------------------------------------------------------------------------------------------------------
# UserInfo endpoint with role information
# ----------------------------------------------------------------------------------------------------------------------
#====V2=====#
@app.get("/userinfo", response_model=UserInfo, include_in_schema=False)
async def userinfo(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    def fingerprint_of_key(pem_str: str) -> str:
        return hashlib.sha256(pem_str.encode()).hexdigest()[:12]

    print("🔸 [userinfo] incoming Authorization token start:", (token or "")[:60])
    try:
        header = jwt.get_unverified_header(token)
        print("🔸 [userinfo] token header:", header)
    except Exception as e:
        print("🔸 [userinfo] cannot read token header:", repr(e))

    print("🔸 [userinfo] expected algorithm:", settings.ALGORITHM)
    print("🔸 [userinfo] expected audience:", settings.OAUTH_CLIENT_ID)
    print("🔸 [userinfo] expected issuer:", getattr(settings, "OAUTH_ISSUER", "oauth-idp"))

    try:
        pub_pem = public_key if isinstance(public_key, str) else public_key.public_bytes(...)
        print("🔸 [userinfo] public key fingerprint:", fingerprint_of_key(pub_pem))
    except Exception as e:
        print("🔸 [userinfo] unable to fingerprint public key:", repr(e))

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[settings.ALGORITHM],
            audience=settings.OAUTH_CLIENT_ID,
            issuer=getattr(settings, "OAUTH_ISSUER", "oauth-idp")
        )
        print("✅ [userinfo] Token decoded successfully:", payload)

        user = db.query(User).filter(User.id == UUID(payload["sub"])).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        return UserInfo(
            sub=str(user.id),
            username=user.username,
            email=user.email,
            mobile=user.mobile,
            first_name=user.first_name,
            last_name=user.last_name,
            role=user.role.value,
            status=user.status.value,
        )

    except JWTError as e:
        print("❌ [userinfo] JWT decode failed:", type(e).__name__, str(e))
        raise HTTPException(status_code=401, detail=f"Invalid token: {type(e).__name__} {str(e)}")
    except Exception as e:
        print("❌ [userinfo] Unexpected error during decode:", repr(e))
        raise

# ----------------------------------------------------------------------------------------------------------------------
# JWKS endpoint
# ----------------------------------------------------------------------------------------------------------------------
#====V2=====#
@app.get("/.well-known/jwks.json" , include_in_schema=False)
async def jwks():
    public_numbers = public_key.public_numbers()

    import base64
    def int_to_base64url(val):
        byte_length = (val.bit_length() + 7) // 8
        bytes_val = val.to_bytes(byte_length, 'big')
        return base64.urlsafe_b64encode(bytes_val).decode('ascii').rstrip('=')

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "1",  # شناسه کلید (برای rotation بعدی تغییر می‌کنی)
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e),
            }
        ]
    }
# ============================================================
# logout
# ============================================================
@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    """
    Logout endpoint that revokes tokens stored in cookies.
    """
    print("🚪 [logout] called")

    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if not access_token and not refresh_token:
        print("❌ No cookies found")
        raise HTTPException(status_code=400, detail="No active session")

    revoked_any = False

    # 🔹 Revoke refresh token if exists
    if refresh_token:
        refresh_hash = hash_token(refresh_token)
        token_obj = db.query(Token).filter(
            Token.refresh_token == refresh_hash,
            Token.revoked == False
        ).first()
        if token_obj:
            token_obj.revoked = True
            token_obj.revoked_at = datetime.utcnow()
            revoked_any = True

    # 🔹 Commit revocations
    if revoked_any:
        db.commit()
        print("✅ Token(s) revoked successfully")
    else:
        print("⚠️ No valid token found in DB")

    # 🔹 Prepare response
    response = JSONResponse(content={"message": "Logout successful"})

    # 🔸 Delete cookies
    response.delete_cookie(
        key="access_token",
        domain=".fiotrix.com",
        path="/"
    )
    response.delete_cookie(
        key="refresh_token",
        domain=".fiotrix.com",
        path="/"
    )

    # 🔹 CORS headers for .fiotrix.com
    origin = request.headers.get("origin")
    if origin and origin.endswith(".fiotrix.com"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Credentials"] = "true"

    print("🚪 Cookies deleted, logout complete")
    return response
# ============================================================
# App start
# ============================================================
# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(
#         "app.main:app",
#         host=settings.HOST,
#         port=settings.PORT,
#         reload=settings.DEBUG,
#     )