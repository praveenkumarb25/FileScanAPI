from fastapi import APIRouter, HTTPException, status
from app.core.security import create_access_token, verify_password
from app.models import Login, TokenResponse
from pydantic import ValidationError
from app.core.config import get_user_from_db, update_token_metadata  # ✅ Add update function
from datetime import datetime, timedelta
from app.core.utils import limiter
from fastapi import Request 

router = APIRouter()
ACCESS_TOKEN_EXPIRE_MINUTES = 10

@router.post("/token", response_model=TokenResponse)
@limiter.limit("5/minute")  # Rate limiting
async def login(login_data: dict, request: Request) -> TokenResponse:
    try:
        login = Login(**login_data)
    except ValidationError as e:
        error_messages = [err["msg"] for err in e.errors()]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=", ".join(error_messages)
        )

    # 🔄 Actual DB lookup
    user = get_user_from_db(login.username)
    if user is None or not verify_password(login.password, user["password"]):
        update_token_metadata(login.username, success=False)  # ⛔ On failure
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    user_roles = user.get("roles", [])

    # ✅ Generate access token
    access_token, expires_in_minutes = create_access_token(
        data={"sub": login.username, "roles": user_roles},
        duration=login.duration
    )

    # 🕒 Calculate token expiration time
    expire_time = (datetime.utcnow() + timedelta(minutes=expires_in_minutes)).isoformat()

    # ✅ Update token metadata in DynamoDB
    update_token_metadata(login.username, success=True, expire_time=expire_time)

    return {
        "token_type": "bearer",
        "access_token": access_token,
        "expires_in_minutes": expires_in_minutes
    }
