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
)
from app.dao import UserDAO, RoleDAO
from app.schemas.user import SUserRegister, SUserAuth, SUserUpdate, SUserResponse
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

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/register/", response_model=SUserResponse)
async def register_user(request: Request, user_data: SUserRegister, db=Depends(get_async_db_session)) -> dict:
    try:
        q = select(User).where(or_(User.email == user_data.email, User.username == user_data.username))
        q = await db.execute(q)
        user = q.scalars().all()
        if user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Пользователь уже существует",
            )
        user_dict = user_data.model_dump()
        role = await RoleDAO.find_one_or_none(name="guest")
        if not role:
            pass
            # TODO: u know
        
        if user_dict["password"] != user_dict["password2"]:
            raise HTTPException(status_code=400, detail="Пароли не совпадают")

        user_dict["hashed_password"] = get_password_hash(user_data.password)
        user_dict["role_id"] = role.id
        user_dict.pop("password")
        user_dict.pop("password2")
        user = User(**user_dict)
        db.add(user)
        try:
            await db.commit()
        except SQLAlchemyError as e:
            await db.rollback()
            raise e
                
        result = await db.execute(
            select(User)
            .options(selectinload(User.role))
            .where(User.id == user.id)
        )
        user_with_role = result.scalars().first()
        return user_with_role

    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка базы данных",
        )

    except HTTPException as e:
        raise e

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
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
                detail="Неверная почта или пароль",
            )

        old_refresh_token = request.cookies.get("users_refresh_token")

        if not old_refresh_token:
            try:
                body = await request.json()
                old_refresh_token = body.get("refresh_token")
            except Exception as e:
                print(f"JSON parse error: {str(e)}")
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

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка базы данных",
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
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
                print(f"JSON parse error: {str(e)}")
                refresh_token = None

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh токен не найден",
            )

        user = await get_user_by_refresh_token(refresh_token, db)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Недействительный refresh токен",
            )

        new_access_token = create_access_token({"sub": str(user.id)})
        new_refresh_token = create_refresh_token()

        await save_refresh_token(user.id, new_refresh_token, db)

        await db.execute(
            delete(RefreshToken).where(RefreshToken.token == refresh_token)
        )
        await db.commit()

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
        raise e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка базы данных",
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
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

        response.delete_cookie("users_access_token")
        response.delete_cookie("users_refresh_token")

        return {"message": "Успешный выход из системы"}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка базы данных",
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
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
            raise HTTPException(status_code=404, detail="Пользователь не найден")

        result_role = await db.execute(
            select(Role).where(Role.name == request.role_name)
        )
        role = result_role.scalars().first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена")

        user.role_id = role.id
        db.add(user)
        await db.commit()

        return {"message": f"Пользователю {user} назначена роль {role.name}"}

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка базы данных",
        )
    
    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

