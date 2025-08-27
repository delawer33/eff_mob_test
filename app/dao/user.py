from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from app.db.base import async_session_maker

from .base import BaseDAO
from app.models import User 


class UserDAO(BaseDAO):
    model = User

    @classmethod
    async def add(cls, **values):
        async with async_session_maker() as session:
            async with session.begin():
                new_instance = cls.model(**values)
                session.add(new_instance)
                try:
                    await session.commit()
                except SQLAlchemyError as e:
                    await session.rollback()
                    raise e
                
                result = await session.execute(
                    select(cls.model)
                    .options(selectinload(cls.model.role))
                    .where(cls.model.id == new_instance.id)
                )
                instance_with_role = result.scalars().first()
                return instance_with_role


all = [
    "UserDAO",
]