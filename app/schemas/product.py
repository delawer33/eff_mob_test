from typing import Optional
from pydantic import BaseModel, ConfigDict

class SProductBase(BaseModel):
    name: str
    description: Optional[str]
    price: float

class SProductCreate(SProductBase):
    pass

class SProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None

class SProductResponse(SProductBase):
    name: str
    description: str
    price: float

    model_config = ConfigDict(
        from_attributes=True
    )