import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import User, Role
from app.main import app
from app.dependencies.auth import get_current_user_admin


class TestAuth:
    @pytest.mark.asyncio
    async def test_register_user_success(self, client: AsyncClient, test_user_data: dict):
        resp = await client.post("/auth/register/", json=test_user_data)
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert data["username"] == test_user_data["username"]
        assert data["email"] == test_user_data["email"]

    @pytest.mark.asyncio
    async def test_register_user_already_exists(self, client: AsyncClient, user_payload_factory):
        payload = user_payload_factory("dupuser", "dupuser@example.com")
        resp1 = await client.post("/auth/register/", json=payload)
        assert resp1.status_code == 200
        resp2 = await client.post("/auth/register/", json=payload)
        assert resp2.status_code == 409
        assert "User already exists" in resp2.json()["detail"]

    @pytest.mark.asyncio
    async def test_register_user_passwords_mismatch(self, client: AsyncClient, user_payload_factory):
        bad = user_payload_factory("pwuser", "pwuser@example.com")
        bad["password2"] = "different_password"
        resp = await client.post("/auth/register/", json=bad)
        assert resp.status_code == 400
        assert "Passwords do not match" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_login_user_success(self, client: AsyncClient, create_user_via_api):
        await create_user_via_api("loginuser", "login@example.com")
        login_data = {"email": "login@example.com", "password": "testpassword123"}
        resp = await client.post("/auth/login/", json=login_data)
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    @pytest.mark.asyncio
    async def test_login_user_invalid_credentials(self, client: AsyncClient, create_user_via_api):
        await create_user_via_api("badlogin", "badlogin@example.com")
        login_data = {"email": "badlogin@example.com", "password": "wrongpassword"}
        resp = await client.post("/auth/login/", json=login_data)
        assert resp.status_code == 401
        assert "Invalid email or password" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, client: AsyncClient, create_user_via_api):
        await create_user_via_api("refresher", "refresher@example.com")
        login_data = {"email": "refresher@example.com", "password": "testpassword123"}
        login_resp = await client.post("/auth/login/", json=login_data)
        assert login_resp.status_code == 200
        body = login_resp.json()
        resp = await client.post("/auth/refresh/", json={"refresh_token": body["refresh_token"]})
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, client: AsyncClient):
        resp = await client.post("/auth/refresh/", json={"refresh_token": "invalid"})
        assert resp.status_code == 401
        assert "Invalid refresh token" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_logout_user_success(self, client: AsyncClient, create_user_via_api):
        await create_user_via_api("logoutuser", "logout@example.com")
        login_data = {"email": "logout@example.com", "password": "testpassword123"}
        login_resp = await client.post("/auth/login/", json=login_data)
        assert login_resp.status_code == 200
        resp = await client.post("/auth/logout/")
        assert resp.status_code == 200
        assert "Logged out successfully" in resp.json()["message"]

    @pytest.mark.asyncio
    async def test_assign_role_success(self, client: AsyncClient, db_session: AsyncSession, create_user_via_api):
        user_json = await create_user_via_api("roleuser", "roleuser@example.com")
        res = await db_session.execute(select(Role).where(Role.name == "admin"))
        admin_role = res.scalar_one_or_none()
        if admin_role is None:
            admin_role = Role(name="admin")
            db_session.add(admin_role)
            await db_session.commit()
            await db_session.refresh(admin_role)
        async def _override_admin():
            return type("U", (), {"role_id": admin_role.id})()
        app.dependency_overrides[get_current_user_admin] = _override_admin
        try:
            req = {"identifier_type": "email", "user_identifier": "roleuser@example.com", "role_name": "admin"}
            resp = await client.post("/auth/assign_role", json=req)
            assert resp.status_code == 200
            assert "Role 'admin' assigned to user" in resp.json()["message"]
        finally:
            app.dependency_overrides.pop(get_current_user_admin, None)

    @pytest.mark.asyncio
    async def test_update_user_success(self, client: AsyncClient, create_user_via_api):
        u = await create_user_via_api("to-update", "to-update@example.com")
        login_data = {"email": "to-update@example.com", "password": "testpassword123"}
        login_resp = await client.post("/auth/login/", json=login_data)
        assert login_resp.status_code == 200
        resp = await client.patch(f"/auth/{u['id']}", json={"username": "newname"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "newname"

    @pytest.mark.asyncio
    async def test_change_password_success(self, client: AsyncClient, create_user_via_api):
        await create_user_via_api("pwduser", "pwduser@example.com")
        login_data = {"email": "pwduser@example.com", "password": "testpassword123"}
        login_resp = await client.post("/auth/login/", json=login_data)
        assert login_resp.status_code == 200
        payload = {"current_password": "testpassword123", "new_password": "newpassword123", "confirm_password": "newpassword123"}
        resp = await client.post("/auth/change-password", json=payload)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_deactivate_user_success(self, client: AsyncClient, create_user_via_api):
        u = await create_user_via_api("to-deactivate", "to-deactivate@example.com")
        login_data = {"email": "to-deactivate@example.com", "password": "testpassword123"}
        login_resp = await client.post("/auth/login/", json=login_data)
        assert login_resp.status_code == 200
        resp = await client.delete(f"/auth/{u['id']}")
        assert resp.status_code == 204
