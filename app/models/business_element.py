from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship

from app.db.base import Base


class BusinessElement(Base):
    __tablename__ = "business_elements"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    access_rules = relationship("AccessRoleRule", back_populates="element")


__all__ = ["BusinessElement"]
