from fastapi import APIRouter, Depends, HTTPException
from typing import  List
import json
from app.core.authentication import *
from app.core.authentication import authenticate_user, generate_authorization_code, generate_tokens
from app.core.database import get_db
from app.models import OAuth2Client, AuthorizationCode
from app.schemas import LoginResponse, LoginRequest, UserResponse, UserRegister, UserRoleSchema
from app.core.config import settings

#=========== API ============
router = APIRouter()

#=========== config ============
CLIENT_ID = settings.OAUTH_CLIENT_ID
CLIENT_SECRET = settings.OAUTH_CLIENT_SECRET
REDIRECT_URI = settings.OAUTH_REDIRECT_URI


#-------------------- login idp / check client_id ------------------------
@router.post("/integrated_login", response_model=LoginResponse)
async def integrated_login(payload: LoginRequest, db: Session = Depends(get_db)):
    username = payload.username
    password = payload.password
    scope = payload.scope
    """Integrated login endpoint that authenticates user, validates client, and returns tokens"""

    # Generate state for CSRF protection
    generated_state = secrets.token_urlsafe(32)

    # Validate client (from env, not frontend)
    client = db.query(OAuth2Client).filter(
        OAuth2Client.client_id == CLIENT_ID,
        OAuth2Client.is_active == True
    ).first()

    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if client.client_secret != CLIENT_SECRET:
        raise HTTPException(status_code=401, detail="Invalid server client_secret")

    redirect_uris = json.loads(client.redirect_uris)
    if REDIRECT_URI not in redirect_uris:
        raise HTTPException(status_code=400, detail="Invalid server redirect_uri")

    # Authenticate user
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user.status != "active":
        raise HTTPException(status_code=401, detail="User not active")

    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()

    # Generate authorization code internally
    auth_code = generate_authorization_code(db, CLIENT_ID, user.id, scope)

    # Exchange code for tokens internally
    tokens = generate_tokens(db, CLIENT_ID, user.id, scope, user.role.value)

    # Mark code as used
    code_obj = db.query(AuthorizationCode).filter(
        AuthorizationCode.code == auth_code
    ).first()
    if code_obj:
        code_obj.used = True
        db.commit()

    # Prepare user info
    user_info = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
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
        scope=tokens["scope"],
        state=generated_state
    )


# ----------------------- User Idp Registration -----------------------------
@router.post("/register", response_model=UserResponse)
async def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        mobile=user_data.mobile,
        password_hash=hash_password(user_data.password),
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        role=user_data.role
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


# -----------------------  Admin : for user management -----------------------
@router.get("/admin/users", response_model=List[UserResponse])
async def list_users(db: Session = Depends(get_db)):
    """Admin endpoint to list all users"""
    users = db.query(User).all()
    return users

# -----------------------  Admin : for user details -----------------------
@router.put("/admin/users/{user_id}/role")
async def update_user_role(user_id: int, role: UserRoleSchema, db: Session = Depends(get_db)):
    """Admin endpoint to update user role"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = role
    user.updated_at = datetime.utcnow()
    db.commit()

    return {"message": "User role updated successfully"}

