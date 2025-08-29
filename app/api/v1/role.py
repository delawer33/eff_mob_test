import logging
from fastapi import (
    APIRouter,
    HTTPException,
    status,
    Depends,
)
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from app.schemas.role import SRoleResponse, SRoleCreate, SRoleUpdate
from app.models import Role
from app.db.base import get_async_db_session
from app.dependencies.auth import get_current_user_admin
from app.config.settings import get_settings

app_settings = get_settings()

logger = logging.getLogger(__name__)

if app_settings.DEBUG:
    logger.setLevel(logging.INFO)
else:
    logger.setLevel(logging.ERROR)

handler = logging.StreamHandler()
formatter = logging.Formatter("%(levelname)s:     %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.get("/", response_model=List[SRoleResponse])
async def get_roles(
    db: AsyncSession = Depends(get_async_db_session),
    current_user=Depends(get_current_user_admin),
):
    try:
        result = await db.execute(select(Role))
        role = result.scalars().all()
        logger.info(f"Retrieved {len(role)} roles.")
        return role

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in get_roles: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in get_roles: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@router.post(
    "/", response_model=SRoleResponse, status_code=status.HTTP_201_CREATED
)
async def create_role(
    role_in: SRoleCreate,
    db: AsyncSession = Depends(get_async_db_session),
    current_user=Depends(get_current_user_admin),
):
    try:
        result = await db.execute(select(Role).where(Role.name == role_in.name))
        existing_role = result.scalars().first()
        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role with this name already exists",
            )

        new_role = Role(name=role_in.name)
        db.add(new_role)
        await db.commit()
        await db.refresh(new_role)
        logger.info(
            f"Role created with ID: {new_role.id}, Name: {new_role.name}"
        )
        return new_role

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in create_role: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(
            f"Unexpected error in create_role: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@router.get("/{role_id}", response_model=SRoleResponse)
async def get_role(
    role_id: int,
    db: AsyncSession = Depends(get_async_db_session),
    current_user=Depends(get_current_user_admin),
):
    try:
        result = await db.execute(select(Role).where(Role.id == role_id))
        role = result.scalars().first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
            )
        logger.info(f"Retrieved role with ID: {role_id}, Name: {role.name}")
        return role

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in get_role: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in get_role: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@router.patch("/{role_id}", response_model=SRoleResponse)
async def update_role(
    role_id: int,
    role_in: SRoleUpdate,
    db: AsyncSession = Depends(get_async_db_session),
    current_user=Depends(get_current_user_admin),
):
    try:
        result = await db.execute(select(Role).where(Role.id == role_id))
        role = result.scalars().first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
            )

        if role_in.name is not None:
            result = await db.execute(
                select(Role).where(
                    Role.name == role_in.name, Role.id != role_id
                )
            )
            duplicate_role = result.scalars().first()
            if duplicate_role:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Another role with this name already exists",
                )
            role.name = role_in.name

        db.add(role)
        await db.commit()
        await db.refresh(role)
        logger.info(
            f"Role {role_id} updated successfully. New Name: {role.name}"
        )
        return role

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in update_role: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(
            f"Unexpected error in update_role: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: int,
    db: AsyncSession = Depends(get_async_db_session),
    current_user=Depends(get_current_user_admin),
):
    try:
        result = await db.execute(select(Role).where(Role.id == role_id))
        role = result.scalars().first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
            )
        if role.name == "admin":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You can't delete admin role",
            )

        await db.delete(role)
        await db.commit()
        logger.info(f"Role {role_id} deleted successfully. Name: {role.name}")

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in delete_role: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(
            f"Unexpected error in delete_role: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )
