import logging
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
from sqlalchemy import delete, select, or_, and_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload
from app.utils.auth import (
    get_password_hash,
    authenticate_user,
    create_access_token,
    change_password as utils_change_pwd
)
from app.schemas.user import SUserRegister, SUserAuth, SUserUpdate, SUserResponse, SUserChangePassword
from app.schemas.role import SRoleAssignRequest, SRoleResponse
from app.schemas.business_element import SBusinessElResponse
from app.schemas.access_role_rule import SAccessRoleRuleUpdate, SAccessRoleRuleResponse, SAccessRoleRuleCreate
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

logger = logging.getLogger(__name__)

if app_settings.DEBUG:
    logger.setLevel(logging.INFO)
else:
    logger.setLevel(logging.ERROR)

handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)s:     %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

router = APIRouter(prefix="/permissions", tags=["Permissions"])


@router.post("/access-rules/", response_model=SAccessRoleRuleResponse)
async def create_access_rule(
    access_rule_in: SAccessRoleRuleCreate,
    current_user: User = Depends(get_current_user_admin),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        existing_rule_query = select(AccessRoleRule).where(
            (AccessRoleRule.role_id == access_rule_in.role_id) & 
            (AccessRoleRule.element_id == access_rule_in.element_id)
        )
        existing_rule_result = await db.execute(existing_rule_query)
        existing_rule = existing_rule_result.scalars().first()
        if existing_rule:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Access rule for this role and element already exists"
            )
        
        role_q = select(Role).where(Role.id == access_rule_in.role_id)
        role = await db.execute(role_q)
        role = role.scalar_one_or_none()
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role with id={access_rule_in.role_id} does not exist"
            )
        
        be_id = select(BusinessElement).where(BusinessElement.id == access_rule_in.element_id)
        be = await db.execute(be_id)
        be = be.scalar_one_or_none()
        if be is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Business element with id={access_rule_in.element_id} does not exist"
            )

        new_rule = AccessRoleRule(
            role_id=access_rule_in.role_id,
            element_id=access_rule_in.element_id,
            read_permission=access_rule_in.read_permission,
            read_all_permission=access_rule_in.read_all_permission,
            create_permission=access_rule_in.create_permission,
            update_permission=access_rule_in.update_permission,
            update_all_permission=access_rule_in.update_all_permission,
            delete_permission=access_rule_in.delete_permission,
            delete_all_permission=access_rule_in.delete_all_permission,
        )
        db.add(new_rule)
        await db.commit()
        await db.refresh(new_rule)
        logger.info(f"Created new access rule: {new_rule.id}")
        return new_rule
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in create_access_rule: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in create_access_rule: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")


@router.get("/access-rules/", response_model=List[SAccessRoleRuleResponse])
async def get_access_rules(
    role_id: Optional[int] = Query(None, description="Filter by role ID"),
    element_id: Optional[int] = Query(None, description="Filter by business element ID"),
    db: AsyncSession = Depends(get_async_db_session),
    current_user = Depends(get_current_user_admin)
):
    try:
        conditions = []
        if role_id is not None:
            conditions.append(AccessRoleRule.role_id == role_id)
        if element_id is not None:
            conditions.append(AccessRoleRule.element_id == element_id)

        if conditions:
            filter_cond = and_(*conditions)
            query = select(AccessRoleRule).where(filter_cond)
        else:
            query = select(AccessRoleRule)

        result = await db.execute(query)
        rules = result.scalars().all()
        
        if not rules:
            raise HTTPException(status_code=404, detail="No access rules found for the given filters")

        logger.info(f"Retrieved {len(rules)} access rules.")
        return rules
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in get_access_rules: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in get_access_rules: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")

@router.get("/business-elements/", response_model=List[SBusinessElResponse])
async def get_business_elements(db: AsyncSession = Depends(get_async_db_session), current_user=Depends(get_current_user_admin)):
    try:
        result = await db.execute(select(BusinessElement))
        be = result.scalars().all()
        logger.info(f"Retrieved {len(be)} business elements.")
        return be
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in get_business_elements: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in get_business_elements: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")

@router.get("/access-rules/{rule_id}", response_model=SAccessRoleRuleResponse)
async def get_access_rule_by_id(
    rule_id: int,
    db: AsyncSession = Depends(get_async_db_session),
    current_user = Depends(get_current_user_admin),
):
    try:
        result = await db.execute(select(AccessRoleRule).where(AccessRoleRule.id == rule_id))
        rule = result.scalars().first()
        if not rule:
            raise HTTPException(status_code=404, detail="Access role rule not found")
        logger.info(f"Retrieved access rule with ID: {rule_id}")
        return rule
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in get_access_rule_by_id: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in get_access_rule_by_id: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")


@router.patch("/access-rules/{rule_id}", response_model=SAccessRoleRuleResponse)
async def update_access_rule_by_id(
    rule_id: int,
    rule_update: SAccessRoleRuleUpdate,
    current_user: User = Depends(get_current_user_admin),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        result = await db.execute(select(AccessRoleRule).where(AccessRoleRule.id == rule_id).options(selectinload(AccessRoleRule.role)))
        rule = result.scalars().first()
        if not rule:
            raise HTTPException(status_code=404, detail="Access rule not found")

        for field, value in rule_update.model_dump(exclude_unset=True).items():
            setattr(rule, field, value)

        db.add(rule)
        await db.commit()
        await db.refresh(rule)
        logger.info(f"Updated access rule with ID: {rule_id}")
        return rule
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in update_access_rule_by_id: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in update_access_rule_by_id: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")

@router.patch("/access-rules/")
async def update_access_rule(
    role_id: int,
    element_id: int,
    rule_update: SAccessRoleRuleUpdate,
    current_user: User = Depends(get_current_user_admin),
    db: AsyncSession = Depends(get_async_db_session),
):
    try:
        result = await db.execute(select(AccessRoleRule).where(
            (AccessRoleRule.role_id == role_id) & (AccessRoleRule.element_id == element_id)
        ))
        rule = result.scalars().first()
        if not rule:
            raise HTTPException(status_code=404, detail="Access rule not found")

        for field, value in rule_update.model_dump(exclude_unset=True).items():
            setattr(rule, field, value)

        db.add(rule)
        await db.commit()
        await db.refresh(rule)
        logger.info(f"Updated access rule for role_id={role_id} and element_id={element_id}")
        return rule
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in update_access_rule: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in update_access_rule: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")


@router.delete("/access-rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_access_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_async_db_session),
    current_user = Depends(get_current_user_admin)
):
    try:
        result = await db.execute(select(AccessRoleRule).where(AccessRoleRule.id == rule_id))
        rule = result.scalars().first()
        if not rule:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access rule not found")

        await db.delete(rule)
        await db.commit()
        logger.info(f"Deleted access rule with ID: {rule_id}")
    
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error in delete_access_rule: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="A database error occurred.")
    
    except HTTPException as e:
        await db.rollback()
        raise e
    
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error in delete_access_rule: {type(e).__name__}: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred.")
