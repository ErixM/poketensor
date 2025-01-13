from pydantic_settings import BaseSettings
from pydantic import ConfigDict

class Settings(BaseSettings):
    model_config = ConfigDict(extra="allow", env_file='.env', env_file_encoding='utf-8')
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SECRET_KEY: str = "your-secret-key"
    ALGORITHM: str = "HS256"
    DATABASE_URL: str = "sqlite+aiosqlite:///./test.db"

settings = Settings()