import pytest_asyncio
import asyncio
from typing import AsyncGenerator, Generator, Callable, Awaitable
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.base import get_async_db_session, Base
from app.models import *
from app.config.settings import get_settings

settings = get_settings()

SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="session")
def event_loop() -> Generator:
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with TestingSessionLocal() as session:
        yield session

@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db():
        yield db_session
    app.dependency_overrides[get_async_db_session] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test/api/v1") as ac:
        yield ac
    app.dependency_overrides.clear()

@pytest_asyncio.fixture(scope="session", autouse=True)
async def seed_acl():
    async with TestingSessionLocal() as session:
        role_names = ["admin", "manager", "user", "guest"]
        existing_roles = {r.name for r in (await session.execute(select(Role))).scalars().all()}
        for name in role_names:
            if name not in existing_roles:
                session.add(Role(name=name))
        await session.commit()

        element_names = ["users", "products", "stores", "orders", "access_rules"]
        existing_elements = {e.name for e in (await session.execute(select(BusinessElement))).scalars().all()}
        for name in element_names:
            if name not in existing_elements:
                session.add(BusinessElement(name=name))
        await session.commit()

        roles = {r.name: r for r in (await session.execute(select(Role))).scalars().all()}
        elements = {e.name: e for e in (await session.execute(select(BusinessElement))).scalars().all()}

        async def has_rule(role_id: int, element_id: int) -> bool:
            q = select(AccessRoleRule).where(
                AccessRoleRule.role_id == role_id,
                AccessRoleRule.element_id == element_id,
            )
            return (await session.execute(q)).scalars().first() is not None

        for el in elements.values():
            if not await has_rule(roles["admin"].id, el.id):
                session.add(AccessRoleRule(
                    role_id=roles["admin"].id,
                    element_id=el.id,
                    read_permission=True, read_all_permission=True,
                    create_permission=True,
                    update_permission=True, update_all_permission=True,
                    delete_permission=True, delete_all_permission=True
                ))

        for el in elements.values():
            if not await has_rule(roles["manager"].id, el.id):
                session.add(AccessRoleRule(
                    role_id=roles["manager"].id,
                    element_id=el.id,
                    read_permission=True, read_all_permission=True,
                    create_permission=True,
                    update_permission=True, update_all_permission=False,
                    delete_permission=True, delete_all_permission=False
                ))

        for el in elements.values():
            if not await has_rule(roles["user"].id, el.id):
                session.add(AccessRoleRule(
                    role_id=roles["user"].id,
                    element_id=el.id,
                    read_permission=True, read_all_permission=False,
                    create_permission=True,
                    update_permission=True, update_all_permission=False,
                    delete_permission=True, delete_all_permission=False
                ))

        if not await has_rule(roles["guest"].id, elements["products"].id):
            session.add(AccessRoleRule(
                role_id=roles["guest"].id,
                element_id=elements["products"].id,
                read_permission=True, read_all_permission=False,
                create_permission=False,
                update_permission=False, update_all_permission=False,
                delete_permission=False, delete_all_permission=False
            ))

        await session.commit()

@pytest_asyncio.fixture
def user_payload_factory() -> Callable[[str, str], dict]:
    def _make(username: str, email: str) -> dict:
        return {
            "username": username,
            "email": email,
            "password": "testpassword123",
            "password2": "testpassword123",
            "full_name": "Test User"
        }
    return _make

@pytest_asyncio.fixture
async def create_user_via_api(client: AsyncClient, user_payload_factory: Callable[[str, str], dict]) -> Callable[[str, str], Awaitable[dict]]:
    async def _create(username: str, email: str) -> dict:
        payload = user_payload_factory(username, email)
        resp = await client.post("/auth/register/", json=payload)
        data: dict = {}
        try:
            if resp.headers.get("content-type", "").startswith("application/json"):
                data = resp.json()
        except Exception:
            data = {}
        if not isinstance(data, dict) or "id" not in data:
            async with TestingSessionLocal() as session:
                q = await session.execute(select(User).where(User.email == email))
                user = q.scalar_one_or_none()
                if user:
                    return {"id": user.id, "email": user.email, "username": user.username}
        return data
    return _create

@pytest_asyncio.fixture
def test_user_data(user_payload_factory: Callable[[str, str], dict]):
    return user_payload_factory("testuser", "testuser@example.com")

@pytest_asyncio.fixture
def test_product_data():
    return {
        "name": "Test Product",
        "description": "Test Description",
        "price": 99.99,
        "stock": 10
    }

@pytest_asyncio.fixture
def test_role_data():
    return {
        "name": "test_role"
    }

@pytest_asyncio.fixture
async def test_guest_user(db_session: AsyncSession) -> User:
    q = await db_session.execute(select(Role).where(Role.name == "guest"))
    role = q.scalar_one_or_none()
    user = User(
        username="testuser",
        email="testuser@example.com",
        role=role.id,
        hashed_password="fakehashed",
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
def test_access_rule_data():
    return {
        "role_id": 1,
        "element_id": 1,
        "read_permission": True,
        "read_all_permission": False,
        "create_permission": True,
        "update_permission": False,
        "update_all_permission": False,
        "delete_permission": False,
        "delete_all_permission": False
    }