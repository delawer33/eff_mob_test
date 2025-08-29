from pydantic import BaseModel, ConfigDict
from typing import Optional

from .role import SRoleResponse

class SAccessRoleRuleBase(BaseModel):
    role_id: int
    element_id: int
    read_permission: Optional[bool]
    read_all_permission: Optional[bool]
    create_permission: Optional[bool]
    update_permission: Optional[bool]
    update_all_permission: Optional[bool]
    delete_permission: Optional[bool]
    delete_all_permission: Optional[bool]

class SAccessRoleRuleCreate(SAccessRoleRuleBase):
    pass

class SAccessRoleRuleUpdate(BaseModel):
    read_permission: Optional[bool] = False
    read_all_permission: Optional[bool] = False
    create_permission: Optional[bool] = False
    update_permission: Optional[bool] = False
    update_all_permission: Optional[bool] = False
    delete_permission: Optional[bool] = False
    delete_all_permission: Optional[bool] = False

class SAccessRoleRuleResponse(SAccessRoleRuleBase):
    id: int

    model_config = ConfigDict(
        from_attributes=True
    )
