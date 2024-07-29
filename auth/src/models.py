import enum

from sqlalchemy.orm import relationship

from src.schemas import RoleEnum
from db.database import Base

from sqlalchemy import Column, Integer, String, Enum as AlchemyEnum, DateTime, Boolean, ForeignKey


class User(Base):
    __tablename__ = 'users'
    __table_args__ = {'schema': 'auth'}

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    surname = Column(String(100), nullable=False)
    login = Column(String(200), unique=True, nullable=False, index=True)
    hashed_password = Column(String(200), nullable=False)
    role = Column(AlchemyEnum(RoleEnum), default=RoleEnum.USER, nullable=False)

    refresh_tokens = relationship('RefreshToken', back_populates='user', cascade='all, delete-orphan')


class RefreshToken(Base):
    __tablename__ = 'refresh_tokens'
    __table_args__ = {'schema': 'auth'}

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('auth.users.id', ondelete="CASCADE"))

    user = relationship('User', back_populates='refresh_tokens')
