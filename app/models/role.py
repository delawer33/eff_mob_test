from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship

from app.db.base import Base


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    access_rules = relationship(
        "AccessRoleRule", back_populates="role", cascade="all, delete-orphan"
    )


__all__ = ["Role"]
