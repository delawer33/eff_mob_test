from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.orm import declarative_base, relationship

from app.db.base import Base


class AccessRoleRule(Base):
    __tablename__ = "access_roles_rules"

    id = Column(Integer, primary_key=True, index=True)

    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    element_id = Column(
        Integer, ForeignKey("business_elements.id"), nullable=False
    )

    read_permission = Column(Boolean, default=False)
    read_all_permission = Column(Boolean, default=False)
    create_permission = Column(Boolean, default=False)
    update_permission = Column(Boolean, default=False)
    update_all_permission = Column(Boolean, default=False)
    delete_permission = Column(Boolean, default=False)
    delete_all_permission = Column(Boolean, default=False)

    role = relationship("Role", back_populates="access_rules")
    element = relationship("BusinessElement", back_populates="access_rules")


__all__ = ["AccessRoleRule"]
