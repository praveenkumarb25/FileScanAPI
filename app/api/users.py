from fastapi import APIRouter, Depends, HTTPException, status
from app.core.security import get_current_user, require_role
from app.models import User

router = APIRouter()

@router.get("/me", response_model=User)
async def read_users_me(user: User = Depends(get_current_user)):
    return user

@router.get("/admin-data", response_model=dict)
async def read_admin_data(user: User = Depends(require_role("admin"))):
    return {"message": "This is admin data."}

@router.get("/user-data", response_model=dict)
async def read_user_data(user: User = Depends(require_role("user"))):
    return {"message": "This is user data."}
