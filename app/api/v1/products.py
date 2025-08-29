import logging
from fastapi import APIRouter, HTTPException, status, Depends, Query
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from app.utils.access_control import AccessControlService
from app.schemas.product import SProductResponse, SProductCreate, SProductUpdate
from app.models import User, Product
from app.db.base import get_async_db_session
from app.dependencies.auth import get_current_user
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

router = APIRouter(prefix="/products", tags=["Products"])


@router.get("/", response_model=List[SProductResponse])
async def get_all_products(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
    name: Optional[str] = Query(None, description="Filter by product name"),
    min_price: Optional[float] = Query(None, description="Minimum price"),
    max_price: Optional[float] = Query(None, description="Maximum price"),
    owner_username: Optional[str] = Query(
        None, description="Filter by owner's username"
    ),
    owner_email: Optional[str] = Query(
        None, description="Filter by owner's email"
    ),
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
            query = query.join(Product.owner).where(
                User.username.ilike(f"%{owner_username}%")
            )
        if owner_email:
            query = query.join(Product.owner).where(
                User.email.ilike(f"%{owner_email}%")
            )

        result = await db.execute(query)
        products = result.scalars().all()
        logger.info(f"Retrieved {len(products)} products.")
        return products
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            f"Database error in get_all_products: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )
    except HTTPException as e:
        await db.rollback()
        raise e
    except Exception as e:
        await db.rollback()
        logger.error(
            f"Unexpected error in get_all_products: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@router.get("/{product_id}", response_model=SProductResponse)
async def get_product(
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        can_read_all = await AccessControlService.can(
            current_user.role_id, "read", "products", is_owner=False, db=db
        )
        can_read_own = await AccessControlService.can(
            current_user.role_id, "read", "products", is_owner=True, db=db
        )

        result = await db.execute(
            select(Product).where(Product.id == product_id)
        )
        product = result.scalars().first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        if not can_read_all and (
            product.owner_id != current_user.id or not can_read_own
        ):
            raise HTTPException(status_code=403, detail="Access denied")
        logger.info(f"Retrieved product with ID: {product_id}")
        return product

    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in get_product: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(
            f"Unexpected error in get_product: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@router.post(
    "/", response_model=SProductResponse, status_code=status.HTTP_201_CREATED
)
async def create_product(
    product_in: SProductCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        can_create = await AccessControlService.can(
            current_user.role_id, "create", "products", is_owner=False, db=db
        )
        if not can_create:
            raise HTTPException(status_code=403, detail="Access denied")

        new_product = Product(
            **product_in.model_dump(), owner_id=current_user.id
        )
        db.add(new_product)
        await db.commit()
        await db.refresh(new_product)
        logger.info(f"Product created with ID: {new_product.id}")
        return new_product
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            f"Database error in create_product: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )
    except HTTPException as e:
        await db.rollback()
        raise e
    except Exception as e:
        await db.rollback()
        logger.error(
            f"Unexpected error in create_product: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@router.patch("/{product_id}", response_model=SProductResponse)
async def update_product(
    product_id: int,
    product_in: SProductUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        result = await db.execute(
            select(Product).where(Product.id == product_id)
        )
        product = result.scalars().first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        can_update_all = await AccessControlService.can(
            current_user.role_id, "update", "products", is_owner=False, db=db
        )
        can_update_own = await AccessControlService.can(
            current_user.role_id, "update", "products", is_owner=True, db=db
        )

        if not can_update_all and (
            product.owner_id != current_user.id or not can_update_own
        ):
            raise HTTPException(status_code=403, detail="Access denied")

        for field, value in product_in.model_dump(exclude_unset=True).items():
            setattr(product, field, value)
        db.add(product)
        await db.commit()
        await db.refresh(product)
        logger.info(f"Product {product_id} updated successfully.")
        return product
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            f"Database error in update_product: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception as e:
        await db.rollback()
        logger.error(
            f"Unexpected error in update_product: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )


@router.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_product(
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        result = await db.execute(
            select(Product).where(Product.id == product_id)
        )
        product = result.scalars().first()
        if not product:
            raise HTTPException(status_code=404, detail="Product not found")

        can_delete_all = await AccessControlService.can(
            current_user.role_id, "delete", "products", is_owner=False, db=db
        )
        can_delete_own = await AccessControlService.can(
            current_user.role_id, "delete", "products", is_owner=True, db=db
        )

        if not can_delete_all and (
            product.owner_id != current_user.id or not can_delete_own
        ):
            raise HTTPException(status_code=403, detail="Access denied")

        await db.delete(product)
        await db.commit()
        logger.info(f"Product {product_id} deleted successfully.")
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(
            f"Database error in delete_product: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="A database error occurred."
        )
    except HTTPException as e:
        await db.rollback()
        raise e
    except Exception as e:
        await db.rollback()
        logger.error(
            f"Unexpected error in delete_product: {type(e).__name__}: {e}"
        )
        raise HTTPException(
            status_code=500, detail="An internal server error occurred."
        )
