import secrets
from fastapi import HTTPException
from jose import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from pydantic import EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models import RefreshToken, User
from app.schemas.user import SUserChangePassword
from app.config.settings import get_settings

app_config = get_settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_pwd: str, hashed_pwd: str) -> bool:
    return pwd_context.verify(plain_pwd, hashed_pwd)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=app_config.access_token_expire_minutes
    )
    to_encode.update({"exp": expire})
    auth_data = app_config.get_auth_data()
    encode_jwt = jwt.encode(
        to_encode, auth_data["secret_key"], algorithm=auth_data["algorithm"]
    )
    return encode_jwt


def create_refresh_token():
    return secrets.token_urlsafe(64)


async def save_refresh_token(user_id: int, token: str, db: AsyncSession):
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=app_config.refresh_token_expire_days
    )
    db_token = RefreshToken(user_id=user_id, token=token, expires_at=expires_at)
    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)

    return db_token


async def get_user_by_refresh_token(token: str, db: AsyncSession):
    result = await db.execute(
        select(RefreshToken)
        .where(
            RefreshToken.token == token,
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
        .options(selectinload(RefreshToken.user))
    )
    token_record = result.scalar_one_or_none()
    return token_record.user if token_record else None


async def authenticate_user(email: EmailStr, password: str, db: AsyncSession):
    q = select(User).where(User.email==email)
    res = await db.execute(q)
    user = res.scalar_one_or_none()
    if not user or not user.is_active or verify_password(password, user.hashed_password) is False:
        return None
    return user


async def change_password(user: User, data: SUserChangePassword, db: AsyncSession):
    if not pwd_context.verify(data.current_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect current password")

    new_hashed_pass = pwd_context.hash(data.new_password)
    user.hashed_password = new_hashed_pass
    
    db.add(user)
    await db.commit()
    await db.refresh(user)


all = [
    "create_access_token",
    "create_refresh_token",
    "save_refresh_token",
    "get_user_by_refresh_token",
    "authenticate_user",
    "change_password"
]
