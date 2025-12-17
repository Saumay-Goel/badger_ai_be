from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Response, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import RedirectResponse, JSONResponse
from datetime import datetime, timedelta, timezone
from authlib.integrations.starlette_client import OAuth
from sqlalchemy.orm import Session
from jose import jwt, JWTError

from .. import schemas, crud
from ..core import security
from ..core.config import settings
from ..database import get_db
from ..utils import generate_otp, send_otp_email, send_welcome_email

router = APIRouter()

oauth = OAuth()
oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)


def set_auth_cookie(response: Response, access_token: str):
    response.set_cookie(
        key="token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        expires=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False
    )


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_token_from_cookie_or_header(request: Request):
    token = request.cookies.get("token")
    if token:
        return token.replace("Bearer ", "")

    auth_header = request.headers.get("Authorization")
    if auth_header:
        return auth_header.replace("Bearer ", "")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


async def get_current_user_from_cookie(
        token: str = Depends(get_token_from_cookie_or_header),
        db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


@router.post("/login", response_model=schemas.Token)
async def login_for_access_token(
        response: Response,
        background_tasks: BackgroundTasks,
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):
    user = crud.authenticate_user(db, email=form_data.username, password=form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_verified:
        otp = generate_otp()
        user.otp = otp
        user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
        db.commit()
        background_tasks.add_task(send_otp_email, user.email, otp)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "ACCOUNT_NOT_VERIFIED"},
            background=background_tasks
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    set_auth_cookie(response, access_token)

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(key="token")
    return {"message": "Logged out successfully"}


@router.post("/signup", response_model=schemas.User, status_code=201)
def register_user(
        user_in: schemas.UserCreate,
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    user = crud.get_user_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_by_name = crud.get_user_by_username(db, username=user_in.username)
    if user_by_name:
        raise HTTPException(status_code=400, detail="Username already taken")

    new_user = crud.signup(db, user=user_in)
    otp = generate_otp()
    new_user.otp = otp
    new_user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.commit()

    background_tasks.add_task(send_otp_email, new_user.email, otp)
    return new_user


@router.post("/verify-otp")
def verify_user_otp(
        response: Response,
        data: schemas.VerifyOTP,
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    user = crud.get_user_by_email(db, email=data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_verified:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = security.create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        set_auth_cookie(response, access_token)
        return {
            "message": "Account already verified",
            "access_token": access_token,
            "token_type": "bearer"
        }

    if not user.otp or user.otp != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    if datetime.now(timezone.utc) > user.otp_expires_at:
        raise HTTPException(status_code=400, detail="OTP Expired")

    user.is_verified = True
    user.otp = None
    user.otp_expires_at = None
    db.commit()

    background_tasks.add_task(send_welcome_email, user.email, user.username)

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    set_auth_cookie(response, access_token)

    return {
        "message": "Email verified successfully.",
        "access_token": access_token,
        "token_type": "bearer"
    }


@router.post("/resend-otp")
def resend_otp(
        data: schemas.ResendOTP,
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    user = crud.get_user_by_email(db, email=data.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_verified:
        return {"message": "User is already verified. Please log in."}

    if user.otp_expires_at and user.otp_expires_at > datetime.now(timezone.utc) + timedelta(minutes=8):
        raise HTTPException(status_code=429, detail="Please wait before requesting new code.")

    new_otp = generate_otp()
    user.otp = new_otp
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.commit()
    background_tasks.add_task(send_otp_email, user.email, new_otp)
    return {"message": "Verification code resent successfully."}


@router.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_user_from_cookie)):
    return current_user


@router.get("/google/login")
async def login_via_google(request: Request):
    redirect_uri = "http://localhost:8000/auth/google/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback")
async def auth_google_callback(
        request: Request,
        db: Session = Depends(get_db)
):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get("userinfo")
        if not user_info:
            raise Exception("No user info")
    except Exception as e:
        print(f"OAuth Error: {e}")
        return RedirectResponse(url="http://localhost:3000/login?error=oauth_failed")

    email = user_info.get('email')

    user = crud.get_user_by_email(db, email=email)

    if not user:
        user = crud.create_google_user(db, email=email)
    else:
        if not user.is_verified:
            user.is_verified = True
            db.commit()

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    response = RedirectResponse(url="http://localhost:3000/dashboard")

    set_auth_cookie(response, access_token)

    return response
