# app/crud.py
from sqlalchemy.orm import Session
from . import models, schemas
from .core.security import verify_password, get_password_hash
from .core import security


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()


def signup(db: Session, user: schemas.UserCreate):
    password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        password=password,
        is_verified=False
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email=email)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_google_user(db: Session, email: str):
    base_username = email.split("@")[0]
    username = base_username
    counter = 1

    while get_user_by_username(db, username):
        username = f"{base_username}{counter}"
        counter += 1

    random_password = security.generate_random_password()
    hashed_password = security.get_password_hash(random_password)

    db_user = models.User(
        email=email,
        username=username,
        full_name=base_username,
        password=hashed_password,
        is_verified=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
