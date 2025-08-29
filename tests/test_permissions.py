import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.main import app
from app.dependencies.auth import get_current_user_admin
from app.models import Role, BusinessElement, AccessRoleRule


async def _override_admin_user(admin_role_id: int):
    return type("U", (), {"role_id": admin_role_id})()


@pytest.mark.asyncio
async def test_create_access_rule_success(
    client: AsyncClient, db_session: AsyncSession
):
    role = (
        await db_session.execute(select(Role).where(Role.name == "guest"))
    ).scalar_one()
    element = (
        await db_session.execute(
            select(BusinessElement).where(BusinessElement.name == "stores")
        )
    ).scalar_one()

    exists = (
        (
            await db_session.execute(
                select(AccessRoleRule).where(
                    AccessRoleRule.role_id == role.id,
                    AccessRoleRule.element_id == element.id,
                )
            )
        )
        .scalars()
        .first()
    )
    if exists:
        await db_session.delete(exists)
        await db_session.commit()

    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        payload = {
            "role_id": role.id,
            "element_id": element.id,
            "read_permission": True,
            "read_all_permission": False,
            "create_permission": True,
            "update_permission": False,
            "update_all_permission": False,
            "delete_permission": False,
            "delete_all_permission": False,
        }
        resp = await client.post("/permissions/access-rules/", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["role_id"] == role.id
        assert data["element_id"] == element.id
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_create_access_rule_duplicate(
    client: AsyncClient, db_session: AsyncSession
):
    role = (
        await db_session.execute(select(Role).where(Role.name == "guest"))
    ).scalar_one()
    element = (
        await db_session.execute(
            select(BusinessElement).where(BusinessElement.name == "orders")
        )
    ).scalar_one()

    rule = (
        (
            await db_session.execute(
                select(AccessRoleRule).where(
                    AccessRoleRule.role_id == role.id,
                    AccessRoleRule.element_id == element.id,
                )
            )
        )
        .scalars()
        .first()
    )
    if rule is None:
        rule = AccessRoleRule(
            role_id=role.id,
            element_id=element.id,
            read_permission=True,
            read_all_permission=False,
            create_permission=False,
            update_permission=False,
            update_all_permission=False,
            delete_permission=False,
            delete_all_permission=False,
        )
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)

    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        payload = {
            "role_id": role.id,
            "element_id": element.id,
            "read_permission": True,
            "read_all_permission": False,
            "create_permission": False,
            "update_permission": False,
            "update_all_permission": False,
            "delete_permission": False,
            "delete_all_permission": False,
        }
        resp = await client.post("/permissions/access-rules/", json=payload)
        assert resp.status_code == 400
        assert "already exists" in resp.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_get_access_rules_list(
    client: AsyncClient, db_session: AsyncSession
):
    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        resp = await client.get("/permissions/access-rules/")
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            assert isinstance(resp.json(), list)
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_get_access_rule_by_id(
    client: AsyncClient, db_session: AsyncSession
):
    role = (
        await db_session.execute(select(Role).where(Role.name == "guest"))
    ).scalar_one()
    element = (
        await db_session.execute(
            select(BusinessElement).where(BusinessElement.name == "stores")
        )
    ).scalar_one()

    rule = AccessRoleRule(
        role_id=role.id,
        element_id=element.id,
        read_permission=True,
        read_all_permission=False,
        create_permission=False,
        update_permission=False,
        update_all_permission=False,
        delete_permission=False,
        delete_all_permission=False,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)

    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        r = await client.get(f"/permissions/access-rules/{rule.id}")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == rule.id
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_update_access_rule_by_id(
    client: AsyncClient, db_session: AsyncSession
):
    role = (
        await db_session.execute(select(Role).where(Role.name == "guest"))
    ).scalar_one()
    element = (
        await db_session.execute(
            select(BusinessElement).where(BusinessElement.name == "orders")
        )
    ).scalar_one()

    rule = AccessRoleRule(
        role_id=role.id,
        element_id=element.id,
        read_permission=True,
        read_all_permission=False,
        create_permission=False,
        update_permission=False,
        update_all_permission=False,
        delete_permission=False,
        delete_all_permission=False,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)

    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        resp = await client.patch(
            f"/permissions/access-rules/{rule.id}",
            json={"update_permission": True},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["update_permission"] is True
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_update_access_rule_by_pair(
    client: AsyncClient, db_session: AsyncSession
):
    role = (
        await db_session.execute(select(Role).where(Role.name == "guest"))
    ).scalar_one()
    element = (
        await db_session.execute(
            select(BusinessElement).where(BusinessElement.name == "orders")
        )
    ).scalar_one()

    rule = (
        (
            await db_session.execute(
                select(AccessRoleRule).where(
                    AccessRoleRule.role_id == role.id,
                    AccessRoleRule.element_id == element.id,
                )
            )
        )
        .scalars()
        .first()
    )
    if rule is None:
        rule = AccessRoleRule(
            role_id=role.id,
            element_id=element.id,
            read_permission=True,
            read_all_permission=False,
            create_permission=False,
            update_permission=False,
            update_all_permission=False,
            delete_permission=False,
            delete_all_permission=False,
        )
        db_session.add(rule)
        await db_session.commit()
        await db_session.refresh(rule)

    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        resp = await client.patch(
            "/permissions/access-rules/",
            params={"role_id": role.id, "element_id": element.id},
            json={"delete_permission": True},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["delete_permission"] is True
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_delete_access_rule_success(
    client: AsyncClient, db_session: AsyncSession
):
    role = (
        await db_session.execute(select(Role).where(Role.name == "guest"))
    ).scalar_one()
    element = (
        await db_session.execute(
            select(BusinessElement).where(BusinessElement.name == "stores")
        )
    ).scalar_one()

    rule = AccessRoleRule(
        role_id=role.id,
        element_id=element.id,
        read_permission=True,
        read_all_permission=False,
        create_permission=False,
        update_permission=False,
        update_all_permission=False,
        delete_permission=False,
        delete_all_permission=False,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)

    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        resp = await client.delete(f"/permissions/access-rules/{rule.id}")
        assert resp.status_code == 204
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)
