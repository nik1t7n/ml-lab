import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class RoleEnum(str, enum.Enum):
    USER = 'user'
    ADMIN = 'admin'
    INSTRUCTOR = 'instructor'


class UserBase(BaseModel):
    name: str
    surname: str
    login: str
    role: RoleEnum = RoleEnum.USER


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    name: Optional[str] = None
    surname: Optional[str] = None
    login: Optional[str] = None
    hashed_password: Optional[str] = None
    role: Optional[RoleEnum] = RoleEnum.USER


class UserInDb(UserBase):
    id: int
    hashed_password: str

    class Config:
        orm_mode = True


class TokenPayload(BaseModel):
    id: int
    role: RoleEnum
    exp: datetime


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    login: str
    role: RoleEnum


class RefreshTokenRequest(BaseModel):
    refresh_token: str

