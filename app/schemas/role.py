from pydantic import BaseModel, ConfigDict
from typing import Literal


class SRoleBase(BaseModel):
    name: str


class SRoleUpdate(BaseModel):
    name: str


class SRoleCreate(SRoleBase):
    pass


class SRoleResponse(SRoleBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class SRoleAssignRequest(BaseModel):
    user_identifier: str
    identifier_type: Literal["email", "username"]
    role_name: str
