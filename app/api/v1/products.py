from fastapi import (
    APIRouter,
    HTTPException,
    status,
    Response,
    Request,
    Depends,
    Query
)
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import delete, select, or_
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import joinedload
from app.utils.auth import (
    get_password_hash,
    authenticate_user,
    create_access_token,
)
from app.utils.access_control import AccessControlService
from app.dao import UserDAO, RoleDAO
from app.schemas.user import SUserRegister, SUserAuth, SUserResponse
from app.schemas.product import SProductResponse, SProductCreate, SProductUpdate
from app.models import User, RefreshToken, Role, Product
from app.db.base import get_async_db_session
from app.dependencies.auth import get_current_user, get_current_user_admin
from app.utils import (
    get_user_by_refresh_token,
    create_refresh_token,
    save_refresh_token,
)
from app.config.settings import get_settings

app_settings = get_settings()

router = APIRouter(prefix="/products", tags=["Products"])

@router.get("/", response_model=List[SProductResponse])
async def get_all_products(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
    name: Optional[str] = Query(None, description="Filter by product name"),
    min_price: Optional[float] = Query(None, description="Minimum price"),
    max_price: Optional[float] = Query(None, description="Maximum price"),
    owner_username: Optional[str] = Query(None, description="Filter by owner's username"),
    owner_email: Optional[str] = Query(None, description="Filter by owner's email"),
):
    try:
        can_read_all = await AccessControlService.can(
            user_role_id=current_user.role_id,
            action="read",
            element_name="products",
            is_owner=False,
            db=db,
        )

        query = select(Product).options(joinedload(Product.owner))

        if not can_read_all:
            query = query.where(Product.owner_id == current_user.id)

        if name:
            query = query.where(Product.name.ilike(f"%{name}%"))
        if min_price is not None:
            query = query.where(Product.price >= min_price)
        if max_price is not None:
            query = query.where(Product.price <= max_price)
        if owner_username:
            query = query.join(Product.owner).where(User.username.ilike(f"%{owner_username}%"))
        if owner_email:
            query = query.join(Product.owner).where(User.email.ilike(f"%{owner_email}%"))

        result = await db.execute(query)
        products = result.scalars().all()
        return products
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except HTTPException as e:
        await db.rollback()
        raise e
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/{product_id}", response_model=SProductResponse)
async def get_product(
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session)
):
    try:
        can_read_all = await AccessControlService.can(current_user.role_id, "read", "products", is_owner=False, db=db)
        can_read_own = await AccessControlService.can(current_user.role_id, "read", "products", is_owner=True, db=db)

        result = await db.execute(select(Product).where(Product.id == product_id))
        product = result.scalars().first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        if not can_read_all and (product.owner_id != current_user.id or not can_read_own):
            raise HTTPException(status_code=403, detail="Access denied")
        return product
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except HTTPException as e:
        await db.rollback()
        raise e
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/", response_model=SProductResponse, status_code=status.HTTP_201_CREATED)
async def create_product(
    product_in: SProductCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session)
):
    try:
        can_create = await AccessControlService.can(current_user.role_id, "create", "products", is_owner=False, db=db)
        if not can_create:
            raise HTTPException(status_code=403, detail="Access denied")

        new_product = Product(**product_in.model_dump(), owner_id=current_user.id)
        db.add(new_product)
        await db.commit()
        await db.refresh(new_product)
        return new_product
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except HTTPException as e:
        await db.rollback()
        raise e
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.patch("/{product_id}", response_model=SProductResponse)
async def update_product(
    product_id: int,
    product_in: SProductUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session)
):
    try:
        result = await db.execute(select(Product).where(Product.id == product_id))
        product = result.scalars().first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        can_update_all = await AccessControlService.can(current_user.role_id, "update", "products", is_owner=False, db=db)
        can_update_own = await AccessControlService.can(current_user.role_id, "update", "products", is_owner=True, db=db)

        if not can_update_all and (product.owner_id != current_user.id or not can_update_own):
            raise HTTPException(status_code=403, detail="Access denied")

        for field, value in product_in.model_dump(exclude_unset=True).items():
            setattr(product, field, value)
        db.add(product)
        await db.commit()
        await db.refresh(product)
        return product
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_product(
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session)
):
    try:
        result = await db.execute(select(Product).where(Product.id == product_id))
        product = result.scalars().first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        can_delete_all = await AccessControlService.can(current_user.role_id, "delete", "products", is_owner=False, db=db)
        can_delete_own = await AccessControlService.can(current_user.role_id, "delete", "products", is_owner=True, db=db)

        if not can_delete_all and (product.owner_id != current_user.id or not can_delete_own):
            raise HTTPException(status_code=403, detail="Access denied")

        await db.delete(product)
        await db.commit()
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except HTTPException as e:
        await db.rollback()
        raise e
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")