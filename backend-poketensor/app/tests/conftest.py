# tests/conftest.py
import pytest
import pytest_asyncio
import asyncio
from httpx import AsyncClient, ASGITransport
from asgi_lifespan import LifespanManager
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.base import Base  # The SQLAlchemy metadata (Base = declarative_base())
from app.db.session import get_db
from app.models.user import User  # or the relevant user model
from app.core.security import get_password_hash

# 1) Override the DB to use an in-memory SQLite for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# Create an engine for testing
test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

# @pytest_asyncio.fixture(loop_scope="function")
# def event_loop():
#     """
#     Create an event loop for the entire test session (if needed).
#     Some configurations with pytest-anyio might handle this differently.
#     """
#     policy = asyncio.get_event_loop_policy()
#     loop = policy.new_event_loop()
#     yield loop
#     loop.close()

@pytest_asyncio.fixture(loop_scope="function", autouse=True)
async def prepare_database():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

# 2) Override the `get_db` dependency to use our in-memory DB session
async def override_get_db():
    async with TestSessionLocal() as session:
        yield session

@pytest_asyncio.fixture(scope="function", autouse=True)
def override_dependency():
    """
    For every test, override the get_db with our in-memory session.
    """
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()

# 3) Provide an httpx.AsyncClient that runs against the FastAPI app in-memory
@pytest_asyncio.fixture
async def async_client():
    """Use an ASGI transport so no real network calls happen, purely in-memory."""
    async with LifespanManager(app):  # triggers FastAPI startup/shutdown events
        # Provide the ASGITransport:
        transport = ASGITransport(app=app, raise_app_exceptions=True)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client

# 4) A fixture to create a test admin user in the in-memory DB
@pytest_asyncio.fixture
async def create_test_admin():
    """
    Creates a first admin user in the test DB.
    Adjust fields to match your actual model.
    """
    async with TestSessionLocal() as session:
        hashed_pw = get_password_hash("secret_admin_pass")
        admin_user = User(
            username="admin",
            hashed_password=hashed_pw,
            is_active=True,
            role="admin"
        )
        session.add(admin_user)
        await session.commit()
        await session.refresh(admin_user)
        return admin_user

# 5) A fixture to create a test normal user in the in-memory DB
@pytest_asyncio.fixture
async def create_test_user():
    """
    Creates a first normal user in the test DB.
    Adjust fields to match your actual model.
    """
    async with TestSessionLocal() as session:
        hashed_pw = get_password_hash("secret_user_pass")
        user = User(
            username="normal_user",
            hashed_password=hashed_pw,
            is_active=True,
            role="user"
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user