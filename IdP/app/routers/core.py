from uuid import UUID
from fastapi import APIRouter, status,Request
from app.core.authentication import hash_password, verify_password, \
    public_key, oauth2_scheme, authenticate_email_mobile, build_login_response
from app.core.redis import get_redis
from app.schemas import SendCodeRequest, RegisterRequest, RegisterResponse, ChangePasswordRequest, \
    ChangePasswordResponse, LoginResponse, LoginOtpRequest, ResetPasswordResponse, ResetPasswordRequest, \
    LoginPasswordRequest
from app.core.tasks import send_verification_email, send_verification_sms
import random, string
from redis import Redis
from app.core.config import settings
import logging
from jose import jwt, JWTError
from fastapi.responses import JSONResponse
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import User
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

redis_conn = Redis.from_url(settings.REDIS_URL, decode_responses=True)



router = APIRouter()


#----------------------------login httponly----------------------
@router.post("/login-only")
async def login_only(
    payload: LoginPasswordRequest,
    request: Request,  # ✅ از fastapi.Request
    db: Session = Depends(get_db)
):
    user = authenticate_email_mobile(db, payload.email_or_mobile, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username, email, or mobile")

    login_data = build_login_response(db, user, payload.scope, payload.state)
    if not login_data.get("access_token") or not login_data.get("refresh_token"):
        raise HTTPException(status_code=500, detail="Failed to generate valid tokens")

    user_info = {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role,
        "status": user.status.value
    }

    response = JSONResponse(content={
        "user": user_info,
        "scope": login_data["scope"],
        "state": login_data["state"],
        "redirect_url": login_data["redirect_url"]
    })

    # ست کردن کوکی‌ها
    response.set_cookie(
        key="access_token",
        value=login_data["access_token"],
        domain=".fiotrix.com",
        path="/",
        httponly=True,
        secure=True,
        samesite="None",
        max_age=86400
    )
    response.set_cookie(
        key="refresh_token",
        value=login_data["refresh_token"],
        domain=".fiotrix.com",
        path="/",
        httponly=True,
        secure=True,
        samesite="None",
        max_age=2592000
    )

    # CORS
    origin = request.headers.get("origin")
    if origin and origin.endswith(".fiotrix.com"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Credentials"] = "true"

    return response





#--------------------------------------------------send code
@router.post("/send-code")
async def send_code(data: SendCodeRequest, db: Session = Depends(get_db),redis: Redis = Depends(get_redis)):
    email_or_mobile = data.email_or_mobile
    mode = data.mode
    user_field = "email" if "@" in email_or_mobile else "mobile"

    if user_field == "email":
        user_exists = db.query(User).filter(User.email == email_or_mobile).first()
    else:
        user_exists = db.query(User).filter(User.mobile == email_or_mobile).first()

    if mode == "register" and user_exists:
        raise HTTPException(status_code=400, detail="This account already exists.")
    elif mode in ["login", "forgot_password"] and not user_exists:
        raise HTTPException(status_code=400, detail="This account does not exist.")

    # generate 6-digit verification code
    verification_code = "".join(random.choices(string.digits, k=6))
    # redis_conn.set(f"verification_code:{email_or_mobile}", verification_code, ex=120)
    await redis.set(f"verification_code:{email_or_mobile}", verification_code, ex=120)

    # ارسال کد با Celery
    if user_field == "email":
        send_verification_email.delay(email_or_mobile, verification_code)
    else:
        send_verification_sms.delay(email_or_mobile, verification_code)

    return {"message": "Verification code sent successfully."}


#--------------------------------------------------Registration endpoint
@router.post("/register", response_model=RegisterResponse)
async def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
    redis=Depends(get_redis)
):
    email_or_mobile = data.email_or_mobile
    email = data.email
    mobile = data.mobile
    code = data.code
    user_field = "email" if "@" in email_or_mobile else "mobile"

    print(f"[DEBUG] email_or_mobile: {email_or_mobile}, user_field: {user_field}")
    print(f"[DEBUG] entered password: {data.password}, re_password: {data.re_password}")

    # validate passwords
    if data.password != data.re_password:
        print("[DEBUG] Passwords do not match")
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    # check verification code in Redis
    stored_code = await redis.get(f"verification_code:{email_or_mobile}")
    print(f"[DEBUG] Redis stored code: {stored_code}, entered code: {code}")

    if not stored_code:
        print("[DEBUG] Verification code expired")
        raise HTTPException(status_code=400, detail="Verification code expired")
    if stored_code != code:
        print("[DEBUG] Invalid verification code")
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # truncate password to 72 chars for bcrypt
    password_to_hash = data.password[:72]
    print(f"[DEBUG] password_to_hash (first 72 chars): {password_to_hash}")

    user = User(
        username=email_or_mobile,
        email=data.email,
        mobile=data.mobile,
        first_name=data.first_name,
        last_name=data.last_name,
        password_hash=hash_password(password_to_hash),
        is_verified=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    print(f"[DEBUG] User created with ID: {user.id}")

    # حذف کد Redis
    await redis.delete(f"verification_code:{email_or_mobile}")
    print(f"[DEBUG] Verification code deleted from Redis")

    return {"message": "User registered successfully"}



# ---------------- OTP Login
@router.post("/login-otp", response_model=LoginResponse)
async def login_otp(payload: LoginOtpRequest, db: Session = Depends(get_db), redis=Depends(get_redis)):
    email_or_mobile = payload.email_or_mobile
    code = payload.code

    user_field = "email" if "@" in email_or_mobile else "mobile"
    user = db.query(User).filter(getattr(User, user_field) == email_or_mobile).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    stored_code = await redis.get(f"verification_code:{email_or_mobile}")
    if not stored_code or stored_code != code:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # if not user.is_verified:
    #     raise HTTPException(status_code=403, detail="User account is not verified")

    await redis.delete(f"verification_code:{email_or_mobile}")

    return build_login_response(db, user, payload.scope, payload.state)

# ----------------  Login
@router.post("/login", response_model=LoginResponse)
async def login_password(payload: LoginPasswordRequest, db: Session = Depends(get_db)):
    user = authenticate_email_mobile(db, payload.email_or_mobile, payload.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username, email, or mobile")

    return build_login_response(db, user, payload.scope, payload.state)

#--------------------------------------------------Password change endpoint
@router.post("/change-password", response_model=ChangePasswordResponse)
async def change_password(
    body: ChangePasswordRequest,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    try:
        # Decode JWT
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[settings.ALGORITHM],
            audience=settings.OAUTH_CLIENT_ID,
            issuer="oauth-idp"
        )
        user_id = UUID(payload["sub"])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    # Fetch user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Verify old password
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password")

    # Prevent reusing the same password
    if verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password cannot be same as old password")

    # Hash & save new password
    user.password_hash = hash_password(body.password)
    db.add(user)
    db.commit()

    return ChangePasswordResponse(message="Password changed successfully")


# ---------------- ENDPOINT ----------------
@router.post("/reset-password", response_model=ResetPasswordResponse)
async def reset_password(
    data: ResetPasswordRequest,
    db: Session = Depends(get_db),
    redis=Depends(get_redis)
):
    email_or_mobile = data.email_or_mobile
    code = data.code
    user_field = "email" if "@" in email_or_mobile else "mobile"

    # check verification code in Redis
    stored_code = await redis.get(f"verification_code:{email_or_mobile}")
    if not stored_code:
        raise HTTPException(status_code=400, detail="Verification code expired")
    if stored_code != code:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    # fetch user
    user = db.query(User).filter(getattr(User, user_field) == email_or_mobile).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # truncate password for bcrypt (72 chars)
    password_to_hash = data.password[:72]

    # update password
    user.password_hash = hash_password(password_to_hash)
    db.add(user)
    db.commit()
    db.refresh(user)

    # delete verification code from Redis
    await redis.delete(f"reset_code:{email_or_mobile}")

    return ResetPasswordResponse(message="Password reset successfully")