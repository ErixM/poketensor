from fastapi import Depends, HTTPException, status, Request
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.crud.user import get_user_by_username
from app.models.user import User, UserRole, BlacklistedToken
from app.db.session import get_db
from sqlalchemy.future import select


async def get_refresh_token_from_cookie(request: Request) -> str:
    """
    Extract 'refresh_token' from cookies.
    If missing or empty, raise 401.
    """
    token_cookie = request.cookies.get("refresh_token")
    if not token_cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated (no 'refresh_token' cookie)",
        )
    return token_cookie

async def get_access_token_from_cookie(request: Request) -> str:
    """
    Extract 'access_token' from cookies.
    Then remove any surrounding quotes and the 'Bearer ' prefix if present.
    If missing or empty, raise 401.
    """
    token_cookie = request.cookies.get("access_token")
    if not token_cookie:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated (no 'access_token' cookie)",
        )
    # Some frameworks quote the cookie value, so remove quotes if any
    token_cookie = token_cookie.strip('"')
    # If we used 'Bearer <actual_jwt>', remove 'Bearer '
    if token_cookie.startswith("Bearer "):
        token_cookie = token_cookie[len("Bearer "):]
    return token_cookie

async def get_current_user(
    token: str = Depends(get_access_token_from_cookie),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Decode the JWT from the 'access_token' cookie, look up the user in the database.
    Raise 401 if invalid token or user not found.
    """
    try:
        # check if token is blacklisted
        blacklisted = await db.execute(select(BlacklistedToken).filter(BlacklistedToken.token == token))
        if blacklisted.scalars().first():
            raise HTTPException(status_code=401, detail="Token blacklisted.")
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload (missing 'sub').")
        user = await get_user_by_username(db, username)
        if not user:
            raise HTTPException(status_code=401, detail="User not found or token invalid.")
        print(f'USER: {user.__dict__}')
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token signature or format.")

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Ensure the user is active; raise 400 if not.
    """
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user.")
    return current_user

async def get_current_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Ensure the user has the admin role; raise 403 if not.
    """
    # Some apps store role as str (e.g. "admin"), others use an Enum (UserRole.admin).
    # If your user model uses an Enum, adapt check below if needed.
    if current_user.role not in (UserRole.admin, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not have admin privileges."
        )
    return current_user
