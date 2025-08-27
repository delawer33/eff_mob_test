from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models import AccessRoleRule, BusinessElement

class AccessControlService:        
    @classmethod
    async def can(cls, user_role_id: int, action: str, element_name: str, is_owner: bool, db: AsyncSession) -> bool:
        q = (
            select(AccessRoleRule)
            .join(BusinessElement)
            .where(AccessRoleRule.role_id == user_role_id)
            .where(BusinessElement.name == element_name)
        )
        result = await db.execute(q)
        rule = result.scalars().first()

        if not rule:
            return False # если для этой роли не настроены разрешения, то тоже False

        if action == "read":
            return rule.read_all_permission or (rule.read_permission and is_owner)
        elif action == "create":
            return rule.create_permission
        elif action == "update":
            return rule.update_all_permission or (rule.update_permission and is_owner)
        elif action == "delete":
            return rule.delete_all_permission or (rule.delete_permission and is_owner)
        else:
            return False


__all__ = [
    "AccessControlService"
]
