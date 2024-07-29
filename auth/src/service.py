from typing import Union

from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from secrets import token_urlsafe
from sqlalchemy.orm import Session

from src.logs.logger_service import LoggerService

from src.schemas import UserInDb, UserUpdate, UserCreate, TokenResponse, TokenPayload, RoleEnum

from src.models import RefreshToken

from src.models import User
from config import (
    algorithm,
    refresh_token_expire_days,
    secret_key,
)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

log_service = LoggerService("logs/auth_service")
success_logger, error_logger = log_service.configure_loggers("auth_service_success", "auth_service_error")


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.pwd_context = pwd_context
        self.SECRET_KEY = secret_key
        self.ALGORITHM = algorithm
        self.ALLOWED = "allowed"
        self.DENIED = "denied"


    def get_all_users(self):
        try:
            users = self.db.query(User).all()
            success_logger.info(f"All users fetched successfully")
            return users
        except Exception as e:
            error_logger.error(f"Error fetching all users: {str(e)}")
            raise e

    def get_user_by_login(self, login: str):
        try:
            user = self.db.query(User).filter(User.login == login).first()
            if user is None:
                error_logger.warning(f"User not found for login: {login}")
                raise HTTPException(status_code=404, detail=f"User with login {login} not found")

            success_logger.info(f"User {login} fetched successfully")
            return user
        except Exception as e:
            error_logger.error(f"Error fetching user {login}: {str(e)}")
            raise e

    def get_user_by_id(self, user_id: int):
        try:
            user = self.db.query(User).filter(User.id == user_id).first()
            if user is None:
                error_logger.warning(f"User not found for ID: {user_id}")
                raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found")

            success_logger.info(f"User ID {user_id} fetched successfully")
            return user
        except Exception as e:
            error_logger.error(f"Error fetching user ID {user_id}: {str(e)}")
            raise e

    def create_user(self, user: UserCreate):
        try:
            hashed_password = self.pwd_context.hash(user.password)
            db_user = User(
                name=user.name,
                surname=user.surname,
                login=user.login,
                hashed_password=hashed_password,  # функция хеширования пароля
                role=user.role
            )
            self.db.add(db_user)
            self.db.commit()
            self.db.refresh(db_user)
            success_logger.info(f"User {db_user.login} created successfully")
            return db_user
        except Exception as e:
            error_logger.error(f"Error creating user {user.login}: {str(e)}")
            raise e

    def update_user(self, user_id: int, user: UserUpdate):
        try:
            db_user = self.get_user_by_id(user_id)
            for key, value in user.dict().items():
                setattr(db_user, key, value)
            self.db.commit()
            success_logger.info(f"User ID {user_id} updated successfully")
            return db_user
        except Exception as e:
            error_logger.error(f"Error updating user ID {user_id}: {str(e)}")
            raise e

    def delete_user(self, user_id: int):
        try:
            user = self.get_user_by_id(user_id)
            self.db.delete(user)
            self.db.commit()
            success_logger.info(f"User ID {user_id} deleted successfully")
            return user
        except Exception as e:
            error_logger.error(f"Error deleting user ID {user_id}: {str(e)}")
            raise e

    def authenticate_user(self, login: str, password: str):
        try:
            user = self.get_user_by_login(login)
            if not user or not self.pwd_context.verify(password, user.hashed_password):
                success_logger.info(f"Failed login attempt for user: {login}")
                return None
            success_logger.info(f"User {login} authenticated successfully")
            return user
        except Exception as e:
            error_logger.error(f"Error during authentication for user {login}: {str(e)}")
            raise e

    def create_access_token(self, data: dict, expires_delta: Union[timedelta, None] = None):
        try:
            to_encode = data.copy()
            if expires_delta:
                expire = datetime.utcnow() + expires_delta
            else:
                expire = datetime.utcnow() + timedelta(minutes=15)

            to_encode.update({"exp": expire})
            encoded_jwt = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
            success_logger.info(f"Access token created for data: {data}")
            return encoded_jwt
        except Exception as e:
            error_logger.error(f"Error creating access token: {str(e)}")
            raise e

    def create_refresh_token(self, user_id: int):
        try:
            expires_at = datetime.utcnow() + timedelta(days=refresh_token_expire_days)
            token = token_urlsafe(32)
            refresh_token = RefreshToken(
                token=token,
                expires_at=expires_at,
                user_id=user_id
            )
            self.db.add(refresh_token)
            self.db.commit()
            success_logger.info(f"Refresh token created for user ID: {user_id}")
            return token
        except Exception as e:
            error_logger.error(f"Error creating refresh token for user ID {user_id}: {str(e)}")
            raise e

    def login(self, login: str, password: str):
        try:
            user = self.authenticate_user(login, password)
            if not user:
                success_logger.info(f"Login failed for user: {login}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect login or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            access_token = self.create_access_token(data={"id": user.id, "role": user.role})
            refresh_token = self.create_refresh_token(user.id)
            success_logger.info(f"User {login} logged in successfully")
            return TokenResponse(
                login=login,
                role=user.role,
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer")
        except Exception as e:
            error_logger.error(f"Error during login for user {login}: {str(e)}")
            raise e

    def refresh_tokens(self, refresh_token: str) -> TokenResponse:
        try:
            db_token = self.db.query(RefreshToken).filter(RefreshToken.token == refresh_token, RefreshToken.revoked == False).first()

            if not db_token or db_token.expires_at < datetime.utcnow():
                error_logger.warning(
                    f"Invalid or expired refresh token: {refresh_token}")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid or expired token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            user = db_token.user
            new_access_token = self.create_access_token(data={"id": user.id, "role": user.role})
            new_refresh_token = self.create_refresh_token(user.id)

            db_token.revoked = True
            self.db.commit()
            success_logger.info(f"Refresh token refreshed for user ID: {user.id}")
            return TokenResponse(access_token=new_access_token, refresh_token=new_refresh_token, token_type="bearer")
        except Exception as e:
            error_logger.error(f"Error refreshing token: {str(e)}")
            raise e

    def revoke_token(self, refresh_token: str):
        try:
            db_token = self.db.query(RefreshToken).filter(RefreshToken.token == refresh_token).first()
            if not db_token:
                error_logger.warning(f"Invalid token: {refresh_token}")
                raise HTTPException(
                    status_code=400,
                    detail="Invalid token",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            db_token.revoked = True
            self.db.commit()
            success_logger.info(f"Refresh token revoked: {refresh_token}")
            return True
        except Exception as e:
            error_logger.error(f"Error revoking token: {str(e)}")
            raise e

    def verify_token(self, token: str):
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            success_logger.info(f"Token verified successfully: {token}")
            return TokenPayload(**payload)
        except JWTError:
            error_logger.error(f"Invalid token: {token}")
            raise HTTPException(
                status_code=401,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def get_current_user(self, token: str = Depends(OAuth2PasswordBearer(tokenUrl="token"))):
        try:
            payload = self.verify_token(token)
            user = self.db.query(User).filter(User.id == payload.id).first()
            if user is None:
                error_logger.warning(f"User not found for token: {token}")
                raise HTTPException(status_code=404, detail="User not found")
            success_logger.info(f"Current user fetched successfully: {user.id}")
            return user
        except Exception as e:
            error_logger.error(f"Error fetching current user: {str(e)}")
            raise e

    def check_if_admin(self, user_id: int):
        try:
            role = self.get_user_by_id(user_id).role
            success_logger.info(f"Checked if user ID {user_id} is admin")
            return role == RoleEnum.ADMIN
        except Exception as e:
            error_logger.error(f"Error checking if user ID {user_id} is admin: {str(e)}")
            raise e

    def check_if_instructor(self, user_id: int):
        try:
            role = self.get_user_by_id(user_id).role
            success_logger.info(f"Checked if user ID {user_id} is instructor")
            return role == RoleEnum.INSTRUCTOR
        except Exception as e:
            error_logger.error(f"Error checking if user ID {user_id} is instructor: {str(e)}")
            raise e

    def get_user_permission(self, current_user: User = Depends(get_current_user)):
        try:
            role = self.get_user_by_id(current_user.id).role
            if role in [RoleEnum.USER, RoleEnum.ADMIN, RoleEnum.INSTRUCTOR]:
                success_logger.info(f"Permission granted for user ID {current_user.id}")
                return self.ALLOWED
            success_logger.info(f"Permission denied for user ID {current_user.id}")
            return self.DENIED
        except Exception as e:
            error_logger.error(f"Error getting permission for user ID {current_user.id}: {str(e)}")
            raise e

    def get_admin_permission(self, current_user: User = Depends(get_current_user)):
        try:
            if self.check_if_admin(current_user.id):
                success_logger.info(f"Admin permission granted for user ID {current_user.id}")
                return self.ALLOWED
            success_logger.info(f"Admin permission denied for user ID {current_user.id}")
            return self.DENIED
        except Exception as e:
            error_logger.error(f"Error getting admin permission for user ID {current_user.id}: {str(e)}")
            raise e

    def get_admin_or_instructor_permission(self, current_user: User = Depends(get_current_user)):
        try:
            if self.check_if_admin(current_user.id) or self.check_if_instructor(current_user.id):
                success_logger.info(f"Admin or instructor permission granted for user ID {current_user.id}")
                return self.ALLOWED
            success_logger.info(f"Admin or instructor permission denied for user ID {current_user.id}")
            return self.DENIED
        except Exception as e:
            error_logger.error(f"Error getting admin or instructor permission for user ID {current_user.id}: {str(e)}")
            raise e