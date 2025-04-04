from fastapi import APIRouter, HTTPException, Depends, status
from app.core.security import create_access_token, verify_password
from app.models import Login, Token, TokenResponse
from app.core.config import fake_users_db
from datetime import timedelta
from pydantic import ValidationError

router = APIRouter()
ACCESS_TOKEN_EXPIRE_MINUTES = 10


@router.post("/token", response_model=TokenResponse)
async def login(login_data: dict):
    try:
        # Validate the request body manually using Pydantic
        login = Login(**login_data)
    except ValidationError as e:
        # Extract only relevant error messages
        print(f"Validation error: {e}")
        error_messages = [err["msg"] for err in e.errors()]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=", ".join(error_messages)  # Show only clean errors
        )

    # Authenticate user
    user = fake_users_db.get(login.username)
    if user is None or not verify_password(login.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    user_roles = user.get("roles", [])

    # Generate token using provided duration
    access_token, expires_in_minutes = create_access_token(
        data={"sub": login.username, "roles": user_roles}, 
        duration=login.duration
    )

    return {
        "token_type": "bearer",
        "access_token": access_token,
        "expires_in_minutes": expires_in_minutes
    }
