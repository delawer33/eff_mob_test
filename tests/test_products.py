import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.main import app
from app.dependencies.auth import get_current_user
from app.models import User, Product, Role


@pytest.mark.asyncio
async def test_get_all_products_owner_only(
    client: AsyncClient, create_user_via_api, db_session: AsyncSession
):
    u = await create_user_via_api("powner", "powner@example.com")
    q = await db_session.execute(select(Role).where(Role.name == "guest"))
    role = q.scalar_one()
    uid = u["id"]

    async def _override_user():
        return type("U", (), {"id": uid, "role_id": role.id})()

    app.dependency_overrides[get_current_user] = _override_user
    try:
        resp = await client.get("/products/")
        assert resp.status_code == 200
        assert resp.json() == []
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_create_product_success(
    client: AsyncClient, create_user_via_api, db_session: AsyncSession
):
    u = await create_user_via_api("pcreator", "pcreator@example.com")
    q = await db_session.execute(select(Role).where(Role.name == "user"))
    role = q.scalar_one()
    uid = u["id"]

    async def _override_user():
        return type("U", (), {"id": uid, "role_id": role.id})()

    app.dependency_overrides[get_current_user] = _override_user
    try:
        payload = {
            "name": "Prod A",
            "description": "Desc",
            "price": 10.5,
            "stock": 3,
        }
        resp = await client.post("/products/", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Prod A"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_get_product_success(
    client: AsyncClient, create_user_via_api, db_session: AsyncSession
):
    u = await create_user_via_api("pgetuser", "pget@example.com")
    q = await db_session.execute(select(Role).where(Role.name == "user"))
    role = q.scalar_one()
    uid = u["id"]

    async def _override_user():
        return type("U", (), {"id": uid, "role_id": role.id})()

    app.dependency_overrides[get_current_user] = _override_user
    try:
        c = await client.post(
            "/products/",
            json={
                "name": "Prod B",
                "description": "B",
                "price": 20.0,
                "stock": 5,
            },
        )
        assert c.status_code == 201
        prod = c.json()
        pid = prod.get("id") if isinstance(prod, dict) else None
        if pid is None:
            pq = await db_session.execute(
                select(Product).where(
                    Product.owner_id == uid, Product.name == "Prod B"
                )
            )
            pid = pq.scalar_one().id
        r = await client.get(f"/products/{pid}")
        assert r.status_code == 200
        body = r.json()
        if isinstance(body, dict) and "id" in body:
            assert body["id"] == pid
        else:
            assert body.get("name") == "Prod B"
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_get_product_not_found(
    client: AsyncClient, create_user_via_api, db_session: AsyncSession
):
    u = await create_user_via_api("pnone", "pnone@example.com")
    q = await db_session.execute(select(Role).where(Role.name == "guest"))
    role = q.scalar_one()
    uid = u["id"]

    async def _override_user():
        return type("U", (), {"id": uid, "role_id": role.id})()

    app.dependency_overrides[get_current_user] = _override_user
    try:
        r = await client.get("/products/999999")
        assert r.status_code == 404
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_update_product_success(
    client: AsyncClient, create_user_via_api, db_session: AsyncSession
):
    u = await create_user_via_api("pupduser", "pupd@example.com")
    q = await db_session.execute(select(Role).where(Role.name == "user"))
    role = q.scalar_one()
    uid = u["id"]

    async def _override_user():
        return type("U", (), {"id": uid, "role_id": role.id})()

    app.dependency_overrides[get_current_user] = _override_user
    try:
        c = await client.post(
            "/products/",
            json={
                "name": "Prod C",
                "description": "C",
                "price": 30.0,
                "stock": 2,
            },
        )
        assert c.status_code == 201
        prod = c.json()
        pid = prod.get("id") if isinstance(prod, dict) else None
        if pid is None:
            pq = await db_session.execute(
                select(Product).where(
                    Product.owner_id == uid, Product.name == "Prod C"
                )
            )
            pid = pq.scalar_one().id
        upd = await client.patch(f"/products/{pid}", json={"price": 33.0})
        assert upd.status_code == 200
        assert upd.json()["price"] == 33.0
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_update_product_not_found(
    client: AsyncClient, create_user_via_api, db_session: AsyncSession
):
    u = await create_user_via_api("pupduser2", "pupd2@example.com")
    q = await db_session.execute(select(Role).where(Role.name == "guest"))
    role = q.scalar_one()
    uid = u["id"]

    async def _override_user():
        return type("U", (), {"id": uid, "role_id": role.id})()

    app.dependency_overrides[get_current_user] = _override_user
    try:
        upd = await client.patch("/products/424242", json={"price": 33.0})
        assert upd.status_code == 404
    finally:
        app.dependency_overrides.pop(get_current_user, None)


@pytest.mark.asyncio
async def test_delete_product_success(
    client: AsyncClient, create_user_via_api, db_session: AsyncSession
):
    u = await create_user_via_api("pdeluser", "pdel@example.com")
    q = await db_session.execute(select(Role).where(Role.name == "user"))
    role = q.scalar_one()
    uid = u["id"]

    async def _override_user():
        return type("U", (), {"id": uid, "role_id": role.id})()

    app.dependency_overrides[get_current_user] = _override_user
    try:
        c = await client.post(
            "/products/",
            json={
                "name": "Prod D",
                "description": "D",
                "price": 40.0,
                "stock": 1,
            },
        )
        assert c.status_code == 201
        prod = c.json()
        pid = prod.get("id") if isinstance(prod, dict) else None
        if pid is None:
            pq = await db_session.execute(
                select(Product).where(
                    Product.owner_id == uid, Product.name == "Prod D"
                )
            )
            pid = pq.scalar_one().id
        d = await client.delete(f"/products/{pid}")
        assert d.status_code == 204
    finally:
        app.dependency_overrides.pop(get_current_user, None)
