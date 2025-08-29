from pydantic import BaseModel, ConfigDict


class SBusinessElBase(BaseModel):
    name: str


class SBusinessElResponse(SBusinessElBase):
    id: int

    model_config = ConfigDict(from_attributes=True)
