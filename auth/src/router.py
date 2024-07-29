from datetime import timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.schemas import TokenResponse, RefreshTokenRequest, UserCreate, UserUpdate, UserInDb
from src.service import AuthService

from src.check_permissions import check_permissions, is_user_role, is_admin_role, is_admin_or_instructor_role

from config import access_token_expire_minutes
from db.database import get_db

router = APIRouter(tags=["Auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
ACCESS_TOKEN_EXPIRE_MINUTES = access_token_expire_minutes


def get_auth_service(db: Session = Depends(get_db)):
    return AuthService(db=db)


@router.post("/token", response_model=TokenResponse)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),
                           auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.login(form_data.username, form_data.password)


@router.get("/verify-token/{token}")
async def verify_user_token(token: str, auth_service: AuthService = Depends(get_auth_service)):
    try:
        current_user = auth_service.get_current_user(token=token)
        return {"message": "Token is valid", "login": current_user.login, "role": current_user.role}
    except Exception as e:
        raise e


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(refresh_data: RefreshTokenRequest, auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.refresh_tokens(refresh_data.refresh_token)


@router.post("/revoke")
def revoke_token(refresh_data: RefreshTokenRequest, auth_service: AuthService = Depends(get_auth_service)):
    auth_service.revoke_token(refresh_data.refresh_token)
    return {"message": "Token revoked successfully"}


@router.get("/users/all", response_model=List[UserInDb])
def get_all_users(auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.get_all_users()


@router.get("/users/{id}", response_model=UserInDb)
def get_user_by_id(id: int, auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.get_user_by_id(id)


@router.get("/users/{login}", response_model=UserInDb)
def get_user_by_login(login: str, auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.get_user_by_login(login)


@router.post("/users/create", response_model=UserCreate)
def create_user(user: UserCreate, auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.create_user(user)


@router.put("/users/update/{id}", response_model=UserUpdate)
def update_user(id: int, user: UserUpdate, auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.update_user(id, user)


@router.delete("/users/delete/{id}")
def delete_user(id: int, auth_service: AuthService = Depends(get_auth_service)):
    return auth_service.delete_user(id)


@router.get("/test-user")
@check_permissions(is_user_role)
def test_user(token: str = Depends(oauth2_scheme),
              auth_service: AuthService = Depends(get_auth_service)):
    return {"message": "User role is valid"}


@router.get("/test-admin")
@check_permissions(is_admin_role)
def test_admin(token: str = Depends(oauth2_scheme),
               auth_service: AuthService = Depends(get_auth_service)):
    return {"message": "Admin role is valid"}


@router.get("/test-instructor")
@check_permissions(is_admin_or_instructor_role)
def test_instructor(token: str = Depends(oauth2_scheme),
                    auth_service: AuthService = Depends(get_auth_service)):
    return {"message": "Instructor role is valid"}
