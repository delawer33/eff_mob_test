from fastapi import (
    APIRouter,
    HTTPException,
    status,
    Response,
    Request,
    Depends,
)
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
from app.schemas.role import SRoleAssignRequest
from app.models import User, RefreshToken, Role
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

router = APIRouter(prefix="/users", tags=["User"])


@router.patch("/{user_id}", response_model=SUserResponse)
async def update_user(
    user_id: int,
    user_update: SUserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        read_all = await AccessControlService.can(
            user_role_id=current_user.role_id,
            action="update",
            element_name="users",
            is_owner=False,
            db=db,
        )
        is_owner = (user.id == current_user.id)

        if not (read_all or is_owner):
            raise HTTPException(status_code=403, detail="Access denied")
        update_data = user_update.model_dump(exclude_unset=True)

        if update_data["username"] is not None:
            result = await db.execute(select(User).where(User.username == update_data["username"]))
            user_same_uname = result.scalars().first()
            if user_same_uname:
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Пользователь с таким username уже существует")

        for field, value in update_data.items():
            setattr(user, field, value)

        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@router.post("/change-password")
async def change_password(
    data: SUserChangePassword,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        await utils_change_pwd(current_user, data, db)
        return {"msg": "Password updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: int,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session)
):
    try:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        delete_all_perm = await AccessControlService.can(
            user_role_id=current_user.role_id,
            action="delete",
            element_name="users",
            is_owner=False,
            db=db,
        )
        is_owner = user.id == current_user.id

        if not (delete_all_perm or is_owner):
            raise HTTPException(status_code=403, detail="Access denied")
        
        response.delete_cookie("users_access_token")
        response.delete_cookie("users_refresh_token")
        user.is_active = False
        db.add(user)
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
