import asyncio
from app.db.session import async_session
from app.models.user import User
from app.core.security import get_password_hash

async def create_first_admin():
    async with async_session() as db:
        existing_admin = await db.execute(
            db.execute.select(User).filter(User.role == "admin")
        )
        if existing_admin.scalars().first():
            print("Admin user already exists.")
            return
        
        admin_user = User(
            username="admin",
            hashed_password=get_password_hash("admin"),
            role="admin"
        )
        db.add(admin_user)
        await db.commit()
        print("Admin user created successfully!")

if __name__ == "__main__":
    asyncio.run(create_first_admin())
