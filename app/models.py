# app/models.py
from sqlalchemy import Boolean, Column, Integer, String, DateTime
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String, nullable=True)
    password = Column(String)
    disabled = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    otp = Column(String, nullable=True)
    otp_expires_at = Column(DateTime, nullable=True)
