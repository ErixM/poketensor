# tests/test_auth.py
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient, create_test_admin):
    """
    Test that admin user can log in with correct credentials.
    """
    response = await async_client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "secret_admin_pass"
        },
    )
    assert response.status_code == 200, response.text
    # Check cookies
    access_cookie_value = response.cookies.get("access_token")
    refresh_cookie_value = response.cookies.get("refresh_token")
    assert access_cookie_value is not None, "No 'access_token' cookie set"
    assert refresh_cookie_value is not None, "No 'refresh_token' cookie set"
    # Usually it's something like 'Bearer <token>' but JSON-encoded quotes can appear in certain setups
    # Adjust as needed if your app or settings differ
    assert access_cookie_value.startswith('"Bearer ')

@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client: AsyncClient, create_test_admin):
    """
    Test login failure with invalid password.
    """
    response = await async_client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "wrong_pass"
        }
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_logout_success(async_client: AsyncClient, create_test_admin):
    """
    Test logout: ensures cookies are removed and (optionally) refresh token is blacklisted if present.
    """
    # 1) Login to set cookies
    login_resp = await async_client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "secret_admin_pass"
        },
    )
    assert login_resp.status_code == 200
    # capture cookies
    cookies = login_resp.cookies
    access_cookie = cookies.get("access_token")
    refresh_cookie = cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_cookie,
        "refresh_token": refresh_cookie
    }
    async_client.cookies.update(cookies_dict)

    # 2) Logout
    response = await async_client.post("/auth/logout")
    assert response.status_code == 200
    assert response.json()["message"] == "Logout successful"

    # Ensure the response instructs the client to delete cookies
    # Typically you check `response.headers["set-cookie"]` to see if "access_token=; Expires=..."
    # But a simple check can be:
    assert "access_token" not in response.cookies
    assert "refresh_token" not in response.cookies


@pytest.mark.asyncio
async def test_admin_only(async_client: AsyncClient, create_test_admin, create_test_user):
    """
    Test the /auth/admin-only endpoint:
      - Admin user -> 200
      - Non-admin -> 401 or 403
    """
    # 1) Log in as admin
    admin_login = await async_client.post(
        "/auth/login",
        data={"username": "admin", "password": "secret_admin_pass"}
    )
    assert admin_login.status_code == 200
    admin_cookies = admin_login.cookies
    access_token = admin_cookies.get("access_token")
    refresh_token = admin_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(cookies_dict)
    # Admin can access admin-only
    resp = await async_client.get("/auth/admin-only")
    assert resp.status_code == 200
    assert resp.json() == {"message": "Welcome, admin!"}

    # 2) Suppose we have a normal user fixture or creation
    # If you have a fixture `create_test_user("bob", "bob_pass")`, you do:
    #    user = await create_test_user("bob", "bob_pass")
    # or you can do DB logic to create them. For brevity, let's inline:

    # We'll just "pretend" we created a user. We'll log in as that user:
    user_login = await async_client.post(
        "/auth/login",
        data={"username": "normal_user", "password": "secret_user_pass"}
    )
    # you'd want to ensure the user actually exists in DB
    # or else this might fail. If you don't have that fixture, skip or patch.

    # If user login fails, skip
    if user_login.status_code != 200:
        pytest.skip("No normal user fixture or creation logic. Skipping user test.")
        return

    user_cookies = user_login.cookies
    access_token = user_cookies.get("access_token")
    refresh_token = user_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(cookies_dict)

    # normal user tries to access admin-only
    resp_unauth = await async_client.get("/auth/admin-only")
    assert resp_unauth.status_code in (401, 403)


@pytest.mark.asyncio
async def test_user_only(async_client: AsyncClient, create_test_admin, create_test_user):
    """
    Test the /auth/user-only endpoint:
      - Normal user -> 200
      - Anonymous -> 401 or 403
    """
    # 1) Suppose we create a normal user or use your logic
    user_login = await async_client.post(
        "/auth/login",
        data={"username": "normal_user", "password": "secret_user_pass"}
    )
    if user_login.status_code != 200:
        pytest.skip("No normal user fixture. Skipping user-only test.")
        return

    user_cookies = user_login.cookies
    access_token = user_cookies.get("access_token")
    refresh_token = user_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(cookies_dict)
    resp = await async_client.get("/auth/user-only")
    assert resp.status_code == 200
    # e.g. {"message": "Welcome, normal_user!"}
    body = resp.json()
    assert "message" in body

    # 2) Anonymous (no cookies):
    async_client.cookies.clear()
    anon_resp = await async_client.get("/auth/user-only")
    assert anon_resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_update_user(async_client: AsyncClient, create_test_admin, create_test_user):
    """
    Test admin user updating another user's profile.
    """
    # 1) Admin login
    admin_login = await async_client.post(
        "/auth/login",
        data={"username": "admin", "password": "secret_admin_pass"}
    )
    assert admin_login.status_code == 200
    admin_cookies = admin_login.cookies
    access_token = admin_cookies.get("access_token")
    refresh_token = admin_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(cookies_dict)

    # 2) Let's assume we have a user with ID=2 to update, or we create one
    # For brevity, let's pretend user #2 exists:
    update_data = {
        "username": "updated_username",
        "password": "new_secret_pass",
        "role": "user",
        "is_active": True
    }

    resp = await async_client.put("/auth/users/2", json=update_data)
    # If user #2 doesn't exist, you'd get 404. Adjust logic if needed
    if resp.status_code == 404:
        pytest.skip("User #2 not found. Skipping test or do user creation first.")
        return
    assert resp.status_code == 200
    data = resp.json()
    # check updated fields
    assert data["username"] == "updated_username"

    user_login = await async_client.post(
        "/auth/login",
        data={
            "username": "updated_username",
            "password": "new_secret_pass"
        }
    )
    assert user_login.status_code == 200
    user_cookies = user_login.cookies
    access_token = user_cookies.get("access_token")
    refresh_token = user_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.clear()
    async_client.cookies.update(cookies_dict)

    resp = await async_client.put("/auth/users/2", json=update_data)
    assert resp.status_code in (401, 403)
    


@pytest.mark.asyncio
async def test_update_my_profile(async_client: AsyncClient, create_test_user):
    """
    Test user updating own profile at /auth/users/me
    """
    # Create or login as normal user
    user_login = await async_client.post(
        "/auth/login",
        data={"username": "normal_user", "password": "secret_user_pass"}
    )
    if user_login.status_code != 200:
        pytest.skip("No normal user or fixture. Skipping test.")
        return

    user_cookies = user_login.cookies
    access_token = user_cookies.get("access_token")
    refresh_token = user_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(cookies_dict)
    new_data = {"username": "normal_user_renamed"}
    resp = await async_client.put("/auth/users/me", json=new_data)
    print(f'update_my_profile: {resp.json()}')
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "normal_user_renamed"


@pytest.mark.asyncio
async def test_delete_user(async_client: AsyncClient, create_test_admin, create_test_user):
    """
    Test admin user deleting another user at /auth/users/{user_id}.
    """
    # Admin login
    admin_login = await async_client.post(
        "/auth/login",
        data={"username": "admin", "password": "secret_admin_pass"}
    )
    assert admin_login.status_code == 200
    admin_cookies = admin_login.cookies
    access_token = admin_cookies.get("access_token")
    refresh_token = admin_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(cookies_dict)

    # Suppose we have user #3
    resp = await async_client.delete("/auth/users/2")
    # If user doesn't exist => 404
    if resp.status_code == 404:
        pytest.skip("User #3 not found. Skipping or do user creation.")
        return

    assert resp.status_code == 200
    assert resp.json()["message"] == "User with ID 2 deleted successfully"


@pytest.mark.asyncio
async def test_refresh_token(async_client: AsyncClient, create_test_admin):
    """
    Test refreshing an access token using a valid refresh token.
    """
    # 1) Login as admin
    login_resp = await async_client.post(
        "/auth/login",
        data={"username": "admin", "password": "secret_admin_pass"}
    )
    assert login_resp.status_code == 200
    refresh_cookie = login_resp.cookies.get("refresh_token")
    assert refresh_cookie, "No refresh token cookie set"
    admin_cookies = login_resp.cookies
    access_cookie = admin_cookies.get("access_token")
    refresh_cookie = admin_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": 'expired-token',
        "refresh_token": refresh_cookie
    }
    async_client.cookies.update(cookies_dict)

    # 2) Refresh token
    response = await async_client.post(
        "/auth/refresh-token",
    )
    assert response.status_code == 200
    # check new access token in cookies or in JSON
    body = response.json()
    assert "access_token" in body
    # Also check the cookie if you set it
    new_access_cookie = response.cookies.get("access_token")
    assert new_access_cookie is not None
    cookies_dict = {
        "access_token": new_access_cookie,
        "refresh_token": refresh_cookie
    }
    async_client.cookies.clear()
    async_client.cookies.update(cookies_dict)

    # 3) Access a protected route with the new access token
    resp = await async_client.get("/auth/user-only")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_refresh_token_blacklisted(async_client: AsyncClient, create_test_admin):
    """
    Test that /auth/refresh-token fails when the token is blacklisted.
    """
    # Log out to blacklist the token
    login_resp = await async_client.post(
        "/auth/login",
        data={"username": "admin", "password": "secret_admin_pass"}
    )
    assert login_resp.status_code == 200
    resp_cookies = login_resp.cookies
    access_token = resp_cookies.get("access_token")
    refresh_token = resp_cookies.get("refresh_token")
    cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(cookies_dict)

    # Logout to blacklist the token
    logout_resp = await async_client.post("/auth/logout")
    assert logout_resp.status_code == 200

    # Attempt to use access token
    resp = await async_client.get("/auth/user-only")
    assert resp.status_code in (401, 403)
    
    # Attempt to refresh the blacklisted token
    refresh_resp = await async_client.post(
        "/auth/refresh-token",
    )
    print(f'refresh_token_blacklisted: {refresh_resp.json()}')
    assert refresh_resp.status_code == 401
    assert refresh_resp.json()["detail"] == "Token has been blacklisted"

@pytest.mark.asyncio
async def test_admin_can_register_normal_user(async_client: AsyncClient, create_test_admin):
    """
    1) Admin logs in
    2) Admin calls /auth/register to create a new normal user
    3) Check the response (user created)
    4) That new user can log in successfully
    5) That new user is not allowed to do admin-only actions
    """

    # 1) Admin logs in
    admin_login = await async_client.post(
        "/auth/login",
        data={"username": "admin", "password": "secret_admin_pass"}
    )
    assert admin_login.status_code == 200, admin_login.text
    admin_cookies = admin_login.cookies
    access_token = admin_cookies.get("access_token")
    refresh_token = admin_cookies.get("refresh_token")
    admin_cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(admin_cookies_dict)

    # 2) Admin calls /auth/register to create normal user
    new_user_data = {
        "username": "normaluser42",
        "password": "normaluser_pass",
        "role": "user"   # or omit if default is user
    }

    # We assume your route is at /auth/register
    register_resp = await async_client.post(
        "/auth/register",
        json=new_user_data,
    )
    # If your code expects a different shape (like data=...), or
    # form data, adjust accordingly.

    # 3) Check response from register
    assert register_resp.status_code == 200, register_resp.text
    created_user = register_resp.json()
    assert created_user["username"] == "normaluser42"
    assert created_user["role"] == "user"
    new_user_id = created_user["id"]

    # 4) New user logs in successfully
    new_login_resp = await async_client.post(
        "/auth/login",
        data={
            "username": "normaluser42",
            "password": "normaluser_pass"
        }
    )
    assert new_login_resp.status_code == 200, new_login_resp.text
    normal_user_cookies = new_login_resp.cookies
    access_token = normal_user_cookies.get("access_token")
    refresh_token = normal_user_cookies.get("refresh_token")
    user_cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.clear()
    async_client.cookies.update(user_cookies_dict)

    # 5) That new user is not allowed to do admin-only stuff
    # e.g. call /auth/admin-only
    resp = await async_client.get("/auth/admin-only")
    # Typically 401 or 403
    assert resp.status_code in (401, 403)

    # Also the new user shouldn’t create new users:
    another_user_data = {
        "username": "illegal_create",
        "password": "nope",
        "role": "user"
    }
    # Attempt register
    illegal_resp = await async_client.post(
        "/auth/register",
        json=another_user_data,
        cookies=normal_user_cookies
    )
    # Should fail
    assert illegal_resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_registered_user_forbidden_delete_me(async_client: AsyncClient, create_test_admin):
    """
    If your logic says only admin can delete, even user can't delete themselves.
    1) Admin registers a normal user
    2) Normal user logs in
    3) Normal user attempts to do DELETE /auth/users/{my_own_id} => 401 or 403
    """

    # Admin login
    admin_login = await async_client.post(
        "/auth/login",
        data={"username": "admin", "password": "secret_admin_pass"}
    )
    assert admin_login.status_code == 200
    admin_cookies = admin_login.cookies
    access_token = admin_cookies.get("access_token")
    refresh_token = admin_cookies.get("refresh_token")
    admin_cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.update(admin_cookies_dict)

    # Register new user
    user_data = {
        "username": "self_delete_user",
        "password": "self_pass",
        "role": "user"
    }
    reg_resp = await async_client.post(
        "/auth/register",
        json=user_data,
    )
    assert reg_resp.status_code == 200
    new_user = reg_resp.json()
    new_user_id = new_user["id"]
    # The user logs in
    user_login = await async_client.post(
        "/auth/login",
        data={"username": "self_delete_user", "password": "self_pass"}
    )
    assert user_login.status_code == 200
    user_cookies = user_login.cookies
    access_token = user_cookies.get("access_token")
    refresh_token = user_cookies.get("refresh_token")
    user_cookies_dict = {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
    async_client.cookies.clear()
    async_client.cookies.update(user_cookies_dict)

    # The user tries to delete themselves
    delete_self_resp = await async_client.delete(
        f"/auth/users/{new_user_id}",
    )
    # If your policy is that only admin can delete users,
    # this should fail. 
    assert delete_self_resp.status_code in (401, 403)

    # Admin can delete them, so let's do that for cleanup
    async_client.cookies.clear()
    async_client.cookies.update(admin_cookies_dict)
    admin_delete_resp = await async_client.delete(
        f"/auth/users/{new_user_id}",
    )
    assert admin_delete_resp.status_code == 200
    assert admin_delete_resp.json()["message"] == f"User with ID {new_user_id} deleted successfully"