
from fastapi import (
    APIRouter,
    HTTPException,
    status,
    Response,
    Request,
    Depends,
)
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload
from app.utils.auth import (
    get_password_hash,
    authenticate_user,
    create_access_token,
    change_password as utils_change_pwd
)
from app.dao import UserDAO, RoleDAO
from app.schemas.user import SUserRegister, SUserAuth, SUserUpdate, SUserResponse, SUserChangePassword
from app.schemas.role import SRoleAssignRequest, SRoleResponse, SRoleCreate, SRoleUpdate
from app.schemas.business_element import SBusinessElResponse
from app.schemas.access_role_rule import SAccessRoleRuleUpdate, SAccessRoleRuleResponse
from app.models import User, RefreshToken, Role, AccessRoleRule, BusinessElement
from app.db.base import get_async_db_session
from app.dependencies.auth import get_current_user, get_current_user_admin
from app.utils import (
    get_user_by_refresh_token,
    create_refresh_token,
    save_refresh_token,
    AccessControlService
)
from app.config.settings import get_settings

app_settings = get_settings()

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.get("/", response_model=List[SRoleResponse])
async def get_roles(db: AsyncSession = Depends(get_async_db_session), current_user=Depends(get_current_user_admin)):
    result = await db.execute(select(Role))
    role = result.scalars().all()
    return role


@router.post("/", response_model=SRoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_in: SRoleCreate,
    db: AsyncSession = Depends(get_async_db_session),
    current_user = Depends(get_current_user_admin)
):
    result = await db.execute(select(Role).where(Role.name == role_in.name))
    existing_role = result.scalars().first()
    if existing_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role with this name already exists"
        )

    new_role = Role(name=role_in.name)
    db.add(new_role)
    await db.commit()
    await db.refresh(new_role)
    return new_role


@router.get("/{role_id}", response_model=SRoleResponse)
async def get_role(
    role_id: int,
    db: AsyncSession = Depends(get_async_db_session),
    current_user = Depends(get_current_user_admin)
):
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalars().first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return role

@router.patch("/{role_id}", response_model=SRoleResponse)
async def update_role(
    role_id: int,
    role_in: SRoleUpdate,
    db: AsyncSession = Depends(get_async_db_session),
    current_user = Depends(get_current_user_admin)
):
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalars().first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    if role_in.name is not None:
        result = await db.execute(select(Role).where(Role.name == role_in.name, Role.id != role_id))
        duplicate_role = result.scalars().first()
        if duplicate_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Another role with this name already exists"
            )
        role.name = role_in.name

    db.add(role)
    await db.commit()
    await db.refresh(role)
    return role

@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: int,
    db: AsyncSession = Depends(get_async_db_session),
    current_user = Depends(get_current_user_admin)
):
    result = await db.execute(select(Role).where(Role.id == role_id))
    role = result.scalars().first()
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    if role.name == 'admin':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You can't delete admin role")

    await db.delete(role)
    await db.commit()
