from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from datetime import timedelta
from jose import jwt, JWTError
from sqlalchemy.future import select

from app.schemas.user import UserCreate, UserOut, UserUpdate
from app.crud.user import (
    get_user_by_username,
    create_user,
    get_user_by_id,
    update_user_crud,
    delete_user_crud,
    blacklist_token
)
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token
)
from app.db.session import get_db
from app.api.deps import get_current_admin, get_current_user, get_refresh_token_from_cookie, get_access_token_from_cookie
from app.models.user import User, BlacklistedToken
from app.core.config import settings

router = APIRouter()

@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    Allows any user (admin or normal) to log in with username and password.
    Sets 'access_token' and 'refresh_token' in HTTP-only cookies.
    """
    user = await get_user_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Generate tokens
    access_token = create_access_token(data={"sub": user.username})
    refresh_token = create_refresh_token(data={"sub": user.username})

    # Set tokens in HTTP-only cookies
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=True,   # Use Secure=True in production
        samesite="Strict",
        max_age=30 * 60  # 30 minutes
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,   # Use Secure=True in production
        samesite="Strict",
        max_age=7 * 24 * 60 * 60  # 7 days
    )
    return response

@router.post("/logout")
async def logout(
    db: AsyncSession = Depends(get_db),
    refresh_token: str = Depends(get_refresh_token_from_cookie),
    access_token: str = Depends(get_access_token_from_cookie),
):
    """
    Logs out the user by clearing cookies. Blacklists refresh_token if provided.
    """
    response = JSONResponse(content={"message": "Logout successful"})
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    # Blacklist refresh token
    if refresh_token:
        await blacklist_token(db, refresh_token, timedelta(days=0))

    # Blacklist access token
    if access_token:
        await blacklist_token(db, access_token, timedelta(minutes=0))

    return response

@router.post("/register", response_model=UserOut)
async def register(
    user: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Allows an admin to create/register a new user (normal or admin).
    """
    # Check if username is already taken
    db_user = await get_user_by_username(db, user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    new_user = await create_user(db, UserCreate(
        username=user.username,
        password=hashed_password,
        role=user.role
    ))
    return new_user

@router.get("/admin-only")
async def read_admin_data(current_admin: User = Depends(get_current_admin)):
    """
    Test endpoint accessible only by admin. 
    Fails with 401/403 if not an admin.
    """
    return {"message": "Welcome, admin!"}

@router.get("/user-only")
async def read_user_data(current_user: User = Depends(get_current_user)):
    """
    Test endpoint accessible only by a logged-in user (admin or normal).
    """
    return {"message": f"Welcome, {current_user.username}!"}

@router.put("/users/me", response_model=UserOut)
async def update_my_profile(
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Allow a logged-in user to update their own profile (username, password, etc.).
    """
    updated_user = await update_user_crud(db, current_user.id, user_update)
    return updated_user

@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Allow admin to update any user's information by user_id.
    """
    db_user = await get_user_by_id(db, user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    updated_user = await update_user_crud(db, user_id, user_update)
    return updated_user

@router.delete("/users/{user_id}", response_model=dict)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_admin: User = Depends(get_current_admin),
):
    """
    Allow admin to delete any user by user_id.
    """
    db_user = await get_user_by_id(db, user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    await delete_user_crud(db, user_id)
    return {"message": f"User with ID {user_id} deleted successfully"}

@router.post("/refresh-token")
async def refresh_token(
    db: AsyncSession = Depends(get_db),
    refresh_token: str = Depends(get_refresh_token_from_cookie),
):
    """
    Endpoint to get a new access token given a valid (non-blacklisted) refresh token.
    """
    # Check if token is blacklisted
    result = await db.execute(
        select(BlacklistedToken).filter(BlacklistedToken.token == refresh_token)
    )
    if result.scalars().first():
        raise HTTPException(status_code=401, detail="Token has been blacklisted")

    # Decode and validate refresh token
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = await get_user_by_username(db, username)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Generate new access token
    new_access_token = create_access_token(data={"sub": user.username})
    response = JSONResponse(content={"access_token": new_access_token})
    response.set_cookie(
        key="access_token",
        value=f"Bearer {new_access_token}",
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=30 * 60  # 30 minutes
    )
    return response
