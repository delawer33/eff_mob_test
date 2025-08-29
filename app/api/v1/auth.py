import logging
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

logger = logging.getLogger(__name__)

if app_settings.DEBUG:
    logger.setLevel(logging.INFO)
else:
    logger.setLevel(logging.ERROR)

handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s:     %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register/", response_model=SUserResponse)
async def register_user(request: Request, user_data: SUserRegister, db: AsyncSession=Depends(get_async_db_session)) -> dict:
    try:
        q = select(User).where(or_(User.email == user_data.email, User.username == user_data.username))
        q = await db.execute(q)
        user = q.scalars().all()
        if user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists",
            )
        user_dict = user_data.model_dump()
        q = await db.execute(select(Role).where(Role.name == "guest"))
        role = q.scalar_one_or_none()
        if not role:
            raise Exception("guest role not found")
        
        if user_dict["password"] != user_dict["password2"]:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        user_dict["hashed_password"] = get_password_hash(user_data.password)
        user_dict["role_id"] = role.id
        user_dict.pop("password")
        user_dict.pop("password2")
        user = User(**user_dict)
        db.add(user)
        try:
            await db.commit()
            logger.info(f"User registered successfully: {user.username}")
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Database error during user registration: {type(e).__name__}: {e}")
            raise HTTPException(status_code=500, detail="A database error occurred during registration.")
                
        result = await db.execute(
            select(User)
            .options(selectinload(User.role))
            .where(User.id == user.id)
        )
        user_with_role = result.scalars().first()
        return user_with_role

    except SQLAlchemyError as e:
        logger.error(f"Database error in register_user: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A database error occurred.",
        )

    except HTTPException as e:
        raise e

    except Exception as e:
        logger.error(f"Unexpected error in register_user: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal server error occurred."
        )


@router.post("/login/")
async def login_user(
    request: Request,
    response: Response,
    user_data: SUserAuth,
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        user = await authenticate_user(
            email=user_data.email,
            password=user_data.password,
            db=db
        )
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        old_refresh_token = request.cookies.get("users_refresh_token")

        if not old_refresh_token:
            try:
                body = await request.json()
                old_refresh_token = body.get("refresh_token")
            except Exception as e:
                logger.error(f"JSON parse error in login_user: {type(e).__name__}: {e}")
                old_refresh_token = None
        if old_refresh_token:
            await db.execute(
                delete(RefreshToken).where(
                    RefreshToken.token == old_refresh_token
                )
            )
            await db.commit()

        access_token = create_access_token({"sub": str(user.id)})
        refresh_token = create_refresh_token()

        await save_refresh_token(user.id, refresh_token, db)
        logger.info(f"User logged in successfully: {user.email}")

        response.set_cookie(
            key="users_access_token",
            value=access_token,
            httponly=True,
            max_age=app_settings.access_token_expire_minutes * 60,
            # secure=True  --- для https в проде
        )

        response.set_cookie(
            key="users_refresh_token",
            value=refresh_token,
            httponly=True,
            max_age=app_settings.refresh_token_expire_days * 24 * 60 * 60,
            # secure=True  --- для https в проде
        )

        return {"access_token": access_token, "refresh_token": refresh_token}

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in login_user: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A database error occurred.",
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in login_user: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal server error occurred."
        )


@router.post("/refresh/")
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        refresh_token = request.cookies.get("users_refresh_token")

        if not refresh_token:
            try:
                body = await request.json()
                refresh_token = body.get("refresh_token")
            except Exception as e:
                logger.error(f"JSON parse error in refresh_token: {type(e).__name__}: {e}")
                refresh_token = None

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found",
            )

        user = await get_user_by_refresh_token(refresh_token, db)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        new_access_token = create_access_token({"sub": str(user.id)})
        new_refresh_token = create_refresh_token()

        await save_refresh_token(user.id, new_refresh_token, db)

        await db.execute(
            delete(RefreshToken).where(RefreshToken.token == refresh_token)
        )
        await db.commit()
        logger.info(f"Token refreshed successfully for user: {user.id}")

        response.set_cookie(
            key="users_access_token",
            value=new_access_token,
            httponly=True,
            max_age=app_settings.access_token_expire_minutes * 60,
            # secure=True для прода
        )

        response.set_cookie(
            key="users_refresh_token",
            value=new_refresh_token,
            httponly=True,
            max_age=app_settings.refresh_token_expire_days * 24 * 60 * 60,
            # secure=True для прода
        )

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        }

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in refresh_token: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A database error occurred.",
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in refresh_token: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal server error occurred."
        )


@router.get("/me/", response_model=SUserResponse)
async def get_me(user_data: User = Depends(get_current_user)):
    user_data.full_name = " " # TODO: убрать заглушку
    return user_data


@router.post("/logout/")
async def logout_user(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_async_db_session),
    user: User = Depends(get_current_user),
):
    try:
        refresh_token = request.cookies.get("users_refresh_token")
        if refresh_token:
            await db.execute(
                delete(RefreshToken).where(RefreshToken.token == refresh_token)
            )
            await db.commit()
        logger.info(f"User logged out successfully for user: {user.id}")

        response.delete_cookie("users_access_token")
        response.delete_cookie("users_refresh_token")

        return {"message": "Logged out successfully"}

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in logout_user: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A database error occurred.",
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in logout_user: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An internal server error occurred."
        )

@router.post("/assign_role")
async def assign_role(
    request: SRoleAssignRequest,
    current_user: User = Depends(get_current_user_admin),
    db: AsyncSession = Depends(get_async_db_session)
):
    try:
        if request.identifier_type == "email":
            condition = User.email == request.user_identifier
        else:
            condition = User.username == request.user_identifier

        result = await db.execute(
            select(User)
            .options(selectinload(User.role))
            .where(condition)
        )
        user = result.scalars().first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        result_role = await db.execute(
            select(Role).where(Role.name == request.role_name)
        )
        role = result_role.scalars().first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        user.role_id = role.id
        db.add(user)
        await db.commit()
        logger.info(f"Role '{role.name}' assigned to user {user.username}.")

        return {"message": f"Role '{role.name}' assigned to user {user}"}

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in assign_role: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="A database error occurred.",
        )
    
    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in assign_role: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")


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
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="User with this username already exists")

        for field, value in update_data.items():
            setattr(user, field, value)

        db.add(user)
        await db.commit()
        await db.refresh(user)
        logger.info(f"User {user_id} updated successfully.")
        return user

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in update_user: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in update_user: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")


@router.post("/change-password")
async def change_password(
    data: SUserChangePassword,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        await utils_change_pwd(current_user, data, db)
        logger.info(f"Password changed successfully for user: {current_user.id}")
        return {"msg": "Password updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in change_password: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")


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
        logger.info(f"User {user_id} deactivated successfully.")
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in deactivate_user: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in deactivate_user: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")