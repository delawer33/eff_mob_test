import asyncio

from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)
from app.db.base import Base
from app.config.settings import get_settings
from app.models import Role, BusinessElement, AccessRoleRule, User
from app.db.base import async_session_maker, engine
from app.utils.auth import get_password_hash

DB_URL = str(get_settings().DB_URL)

engine = create_async_engine(DB_URL)

async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    
    async with async_session_maker() as session:
        roles = [
            Role(name="admin"),
            Role(name="manager"),
            Role(name="user"),
            Role(name="guest"),
        ]
        session.add_all(roles)
        await session.commit()
        
        elements = [
            BusinessElement(name="users"),
            BusinessElement(name="products"),
            BusinessElement(name="stores"),
            BusinessElement(name="orders"),
            BusinessElement(name="access_rules"),
        ]
        session.add_all(elements)
        await session.commit()

        def get_role(name):
            return next(r for r in roles if r.name == name)

        def get_element(name):
            return next(e for e in elements if e.name == name)
        
        access_rules = []

        # Admin: все права на все элементы
        for el in elements:
            access_rules.append(AccessRoleRule(
                role_id=get_role("admin").id,
                element_id=el.id,
                read_permission=True, read_all_permission=True,
                create_permission=True,
                update_permission=True, update_all_permission=True,
                delete_permission=True, delete_all_permission=True
            ))

        # Manager: почти все права, но нет delete_all и некоторые ограничения
        for el in elements:
            access_rules.append(AccessRoleRule(
                role_id=get_role("manager").id,
                element_id=el.id,
                read_permission=True, read_all_permission=True,
                create_permission=True,
                update_permission=True, update_all_permission=False,
                delete_permission=True, delete_all_permission=False
            ))

        # User: права только над своими объектами
        for el in elements:
            access_rules.append(AccessRoleRule(
                role_id=get_role("user").id,
                element_id=el.id,
                read_permission=True, read_all_permission=False,
                create_permission=True,
                update_permission=True, update_all_permission=False,
                delete_permission=True, delete_all_permission=False
            ))

        # Guest: только чтение своих данных
        access_rules.append(AccessRoleRule(
            role_id=get_role("guest").id,
            element_id=get_element("products").id,
            read_permission=True, read_all_permission=False,
            create_permission=False,
            update_permission=False, update_all_permission=False,
            delete_permission=False, delete_all_permission=False
        ))

        session.add_all(access_rules)
        await session.commit()

        admin_role = get_role("admin")
        admin_user = User(
            username="admin",
            email="admin@example.com",
            hashed_password=get_password_hash("admin_password"),
            role_id=admin_role.id
        )
        session.add(admin_user)
        await session.commit()

asyncio.run(init_db())

print("Тестовые данные успешно созданы!")
