from fastapi import HTTPException, status
from functools import wraps


def check_permissions(permission_check):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            auth_service = kwargs.get('auth_service')
            token = kwargs.get('token')
            current_user = auth_service.get_current_user(token=token)

            permission = permission_check(auth_service, current_user)
            if permission.lower() != "allowed":
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")

            return func(*args, **kwargs)

        return wrapper

    return decorator


def is_admin_role(auth_service, current_user):
    return auth_service.get_admin_permission(current_user)


def is_admin_or_instructor_role(auth_service, current_user):
    return auth_service.get_admin_or_instructor_permission(current_user)


def is_user_role(auth_service, current_user):
    return auth_service.get_user_permission(current_user)

