from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Optional
from app.schemas.role import SRoleResponse


class SUserRegister(BaseModel):
    username: str = Field(
        ...,
        min_length=5,
        max_length=20,
        description="Имя пользователя, от 5 до 20 знаков",
    )
    email: EmailStr = Field(..., description="Электронная почта")
    full_name: str = Field(..., description="Полное имя")
    password: str = Field(
        ...,
        min_length=5,
        max_length=50,
        description="Пароль, от 5 до 50 знаков",
    )
    password2: str = Field(
        ...,
        min_length=5,
        max_length=50,
        description="Подтверждение пароля, от 5 до 50 знаков",
    )
    # role_id: int = Field(..., description="id роли из таблицы Roles")


class SUserAuth(BaseModel):
    email: EmailStr = Field(..., description="Электронная почта")
    password: str = Field(
        ...,
        min_length=5,
        max_length=50,
        description="Пароль, от 5 до 50 знаков",
    )

class SUserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: str
    is_active: bool
    role: SRoleResponse
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )


class SUserUpdate(BaseModel):
    username: Optional[str] = None
    full_name: Optional[str] = None


class SUserChangePassword(BaseModel):
    old_password: str = Field(..., min_length=5, max_length=50)
    new_password: str = Field(..., min_length=5, max_length=50)

