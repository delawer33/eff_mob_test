import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.main import app
from app.dependencies.auth import get_current_user_admin
from app.models import Role


async def _override_admin_user(admin_role_id: int):
    return type("U", (), {"role_id": admin_role_id})()


@pytest.mark.asyncio
async def test_get_roles(client: AsyncClient, db_session: AsyncSession):
    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        resp = await client.get("/roles/")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_create_role_success(
    client: AsyncClient, db_session: AsyncSession
):
    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        resp = await client.post("/roles/", json={"name": "qa_engineer"})
        if resp.status_code == 400:
            assert resp.json()["detail"] == "Role with this name already exists"
        else:
            assert resp.status_code == 201
            assert resp.json()["name"] == "qa_engineer"
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_create_role_duplicate(
    client: AsyncClient, db_session: AsyncSession
):
    existing = (
        await db_session.execute(
            select(Role).where(Role.name == "duplicate_role")
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = Role(name="duplicate_role")
        db_session.add(existing)
        await db_session.commit()
    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        resp = await client.post("/roles/", json={"name": "duplicate_role"})
        assert resp.status_code == 400
        assert resp.json()["detail"] == "Role with this name already exists"
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_get_role_success_and_not_found(
    client: AsyncClient, db_session: AsyncSession
):
    r = (
        await db_session.execute(select(Role).where(Role.name == "support"))
    ).scalar_one_or_none()
    if r is None:
        r = Role(name="support")
        db_session.add(r)
        await db_session.commit()
        await db_session.refresh(r)
    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        ok = await client.get(f"/roles/{r.id}")
        assert ok.status_code == 200
        assert ok.json()["name"] == "support"
        nf = await client.get("/roles/999999")
        assert nf.status_code == 404
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_update_role_success_and_duplicate_name(
    client: AsyncClient, db_session: AsyncSession
):
    base = (
        await db_session.execute(
            select(Role).where(Role.name == "role_to_update")
        )
    ).scalar_one_or_none()
    if base is None:
        base = Role(name="role_to_update")
        db_session.add(base)
        await db_session.commit()
        await db_session.refresh(base)
    other = (
        await db_session.execute(select(Role).where(Role.name == "taken_name"))
    ).scalar_one_or_none()
    if other is None:
        other = Role(name="taken_name")
        db_session.add(other)
        await db_session.commit()
    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        ok = await client.patch(
            f"/roles/{base.id}", json={"name": "updated_role_name"}
        )
        assert ok.status_code == 200
        assert ok.json()["name"] == "updated_role_name"
        dup = await client.patch(
            f"/roles/{base.id}", json={"name": "taken_name"}
        )
        assert dup.status_code == 400
        assert (
            dup.json()["detail"] == "Another role with this name already exists"
        )
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)


@pytest.mark.asyncio
async def test_delete_role_success_and_protected(
    client: AsyncClient, db_session: AsyncSession
):
    del_role = (
        await db_session.execute(select(Role).where(Role.name == "temp_delete"))
    ).scalar_one_or_none()
    if del_role is None:
        del_role = Role(name="temp_delete")
        db_session.add(del_role)
        await db_session.commit()
        await db_session.refresh(del_role)
    admin_role = (
        await db_session.execute(select(Role).where(Role.name == "admin"))
    ).scalar_one()

    async def _admin():
        return await _override_admin_user(admin_role.id)

    app.dependency_overrides[get_current_user_admin] = _admin
    try:
        ok = await client.delete(f"/roles/{del_role.id}")
        assert ok.status_code == 204
        protected = (
            await db_session.execute(select(Role).where(Role.name == "admin"))
        ).scalar_one()
        cant = await client.delete(f"/roles/{protected.id}")
        assert cant.status_code == 400
        assert "can't delete admin" in cant.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_current_user_admin, None)
