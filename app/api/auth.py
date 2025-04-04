from fastapi import APIRouter, HTTPException, Depends, status
from app.core.security import create_access_token, verify_password
from app.models import Login, Token
from app.core.config import fake_users_db
from datetime import timedelta

router = APIRouter()
ACCESS_TOKEN_EXPIRE_MINUTES = 10

@router.post("/token", response_model=Token)
async def login(login: Login):
    user = fake_users_db.get(login.username)
    if user is None or not verify_password(login.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    user_roles = user.get("roles", [])
    access_token, expires_in_minutes = create_access_token(
        data={"sub": login.username, "roles": user_roles}, expires_delta=access_token_expires
    )
    return {"token_type": "bearer", "access_token": access_token, "expires_in_minutes": expires_in_minutes}
