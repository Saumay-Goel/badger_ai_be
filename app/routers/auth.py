from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone

from starlette.responses import JSONResponse, Response

from app.core.dependencies import get_current_active_user
from sqlalchemy.orm import Session
from .. import schemas, crud
from ..core import security
from ..core.config import settings
from ..database import get_db
from ..utils import generate_otp, send_otp_email, send_welcome_email

router = APIRouter()


@router.post("/login", response_model=schemas.Token)
async def login_for_access_token(
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
        print(f'LOG----> Generated OTP {otp}')
        user.otp = otp
        user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
        db.commit()
        print(f'LOG----> Saved OTP to db')
        background_tasks.add_task(send_otp_email, user.email, otp)
        print("LOG----> Not Verified")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "ACCOUNT_NOT_VERIFIED"},
            background=background_tasks
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
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
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    user_by_name = crud.get_user_by_username(db, username=user_in.username)
    if user_by_name:
        raise HTTPException(
            status_code=400,
            detail="Username already taken"
        )

    new_user = crud.signup(db, user=user_in)

    otp = generate_otp()
    new_user.otp = otp
    new_user.otp_expires_at = datetime.utcnow() + timedelta(minutes=10)
    db.commit()

    background_tasks.add_task(send_otp_email, new_user.email, otp)

    return new_user


@router.post("/verify-otp")
def verify_user_otp(
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
        raise HTTPException(
            status_code=429,
            detail="Please wait a few minutes before requesting a new code."
        )

    new_otp = generate_otp()
    user.otp = new_otp
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.commit()

    background_tasks.add_task(send_otp_email, user.email, new_otp)

    return {"message": "Verification code resent successfully."}


@router.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_active_user)):
    print(current_user)
    return current_user
