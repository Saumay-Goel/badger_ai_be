from jose import jwt, JWTError
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .config import settings
from app import schemas, crud
from app.database import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_token_from_cookie_or_header(request: Request):
    token = request.cookies.get("access_token")
    if token:
        return token.replace("Bearer ", "")

    auth_header = request.headers.get("Authorization")
    if auth_header:
        return auth_header.replace("Bearer ", "")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


async def get_current_user(
        token: str = Depends(get_token_from_cookie_or_header), db: Session = Depends(get_db)
):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credential_exception

    user = crud.get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credential_exception
    return user


async def get_current_active_user(
        current_user: schemas.UserInDB = Depends(get_current_user)
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
