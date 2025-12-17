from __future__ import annotations
from pydantic import BaseModel, EmailStr
from typing import Optional


class VerifyOTP(BaseModel):
    email: str
    otp: str


class ResendOTP(BaseModel):
    email: EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class User(UserBase):
    id: int

    class Config:
        from_attributes = True


class UserInDB(UserBase):
    password: str
