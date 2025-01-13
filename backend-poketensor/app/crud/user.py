from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.user import User, UserRole, BlacklistedToken
from app.schemas.user import UserCreate, UserUpdate
from datetime import datetime, timedelta, timezone
from app.core.security import get_password_hash


async def get_user_by_username(db: AsyncSession, username: str):
    result = await db.execute(select(User).filter(User.username == username))
    return result.scalars().first()

async def get_user_by_id(db: AsyncSession, user_id: int):
    """
    Retrieve a user by their ID.
    """
    result = await db.execute(select(User).filter(User.id == user_id))
    return result.scalars().first()

async def create_user(db: AsyncSession, user: UserCreate):
    db_user = User(
        username=user.username,
        hashed_password=user.password,
        role=user.role  # Assign the role during creation
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

async def update_user_crud(db: AsyncSession, user_id: int, user_update: UserUpdate):
    db_user = await get_user_by_id(db, user_id)
    if not db_user:
        return None

    update_data = user_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if key == 'password':
            key = 'hashed_password'
            value = get_password_hash(value)
        print(key, value)
        setattr(db_user, key, value)
        await db.commit()
        await db.refresh(db_user)
    return db_user

async def delete_user_crud(db: AsyncSession, user_id: int):
    db_user = await get_user_by_id(db, user_id)
    if not db_user:
        return None

    await db.delete(db_user)
    await db.commit()

async def blacklist_token(db: AsyncSession, token: str, expires_in: timedelta):
    expires_at = datetime.now(timezone.utc) + expires_in
    db_token = BlacklistedToken(token=token, expires_at=expires_at)
    db.add(db_token)
    await db.commit()