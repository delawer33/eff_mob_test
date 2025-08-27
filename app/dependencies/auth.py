from jose import jwt, JWTError
from fastapi import Request, status, HTTPException, Depends
from fastapi.security.utils import get_authorization_scheme_param
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.config.settings import get_settings
from app.dao import UserDAO
from app.models import User
from app.db.base import get_async_db_session

app_settings = get_settings()

def get_token(request: Request):
    auth = request.headers.get("Authorization")
    scheme, param = get_authorization_scheme_param(auth)

    token = None
    if scheme.lower() == "bearer" and param:
        token = param
    else:
        token = request.cookies.get("users_access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Токен не найден"
        )
    return token


async def get_current_user(token: str = Depends(get_token), db=Depends(get_async_db_session)):
    try:
        auth_data = app_settings.get_auth_data()
        payload = jwt.decode(
            token, auth_data["secret_key"], algorithms=[auth_data["algorithm"]]
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Токен не валидный"
        )

    expire = payload.get("exp")
    expire_time = datetime.fromtimestamp(int(expire), tz=timezone.utc)
    if (not expire) or (expire_time < datetime.now(timezone.utc)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Токен Истек"
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не найден ID пользователя",
        )

    q = select(User).where(User.id == int(user_id)).options(selectinload(User.role))
    q = await db.execute(q)
    user = q.scalar_one_or_none()
    if not user or user.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь с таким ID не найден",
        )

    return user


async def get_current_user_admin(user: User = Depends(get_current_user)):
    if user.role.name != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="У вас нет прав администратора",
        )
    return user
