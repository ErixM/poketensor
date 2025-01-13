from pydantic import BaseModel
from enum import Enum
from pydantic import ConfigDict
from typing import Optional

class UserRole(str, Enum):
    admin = "admin"
    user = "user"

class UserBase(BaseModel):
    username: str
    role: UserRole = UserRole.user  # Default role is "user"

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    is_active: bool

    model_config = ConfigDict(from_attributes=True)

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    role: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)