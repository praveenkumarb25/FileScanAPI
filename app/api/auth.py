from fastapi import APIRouter, HTTPException, status
from app.core.security import create_access_token, verify_password
from app.models import Login, TokenResponse
from pydantic import ValidationError
from app.core.config import get_user_from_db  # ← Add this

router = APIRouter()
ACCESS_TOKEN_EXPIRE_MINUTES = 10

@router.post("/token", response_model=TokenResponse)
async def login(login_data: dict):
    try:
        login = Login(**login_data)
    except ValidationError as e:
        error_messages = [err["msg"] for err in e.errors()]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=", ".join(error_messages)
        )

    # 🔄 Replace fake DB with actual DB lookup
    user = get_user_from_db(login.username)
    if user is None or not verify_password(login.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    user_roles = user.get("roles", [])

    # 🪪 Generate access token
    access_token, expires_in_minutes = create_access_token(
        data={"sub": login.username, "roles": user_roles},
        duration=login.duration
    )

    return {
        "token_type": "bearer",
        "access_token": access_token,
        "expires_in_minutes": expires_in_minutes
    }
