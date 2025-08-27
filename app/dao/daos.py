from .base import BaseDAO

from app.models import User, RefreshToken, Role, BusinessElement, AccessRoleRule 


class RefreshTokenDAO(BaseDAO):
    model = RefreshToken

class RoleDAO(BaseDAO):
    model = Role

class BusinessElementDAO(BaseDAO):
    model = BusinessElement

class AccessRoleRuleDAO(BaseDAO):
    model = AccessRoleRule

__all__ = [
    "RefreshTokenDAO",
    "RoleDAO",
    "BusinessElementDAO",
    "AccessRoleRuleDAO",
]
