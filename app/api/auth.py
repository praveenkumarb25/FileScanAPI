from fastapi import APIRouter, HTTPException, status
from app.core.security import create_access_token, verify_password
from app.models import Login, TokenResponse
from pydantic import ValidationError
from app.core.config import get_user_from_db, update_token_metadata, get_user_by_email  # ✅ Add update function
from datetime import datetime, timedelta
from app.core.utils import limiter
from fastapi import Request 
import logging

router = APIRouter()
ACCESS_TOKEN_EXPIRE_MINUTES = 10
@router.post("/token", response_model=TokenResponse)
@limiter.limit("5/minute")  # Rate limiting
async def login(login_data: dict, request: Request) -> TokenResponse:
    required_fields = Login.schema()["required"]
    missing_fields = [field for field in required_fields if field not in login_data]

    if missing_fields:
        logging.error(f"Missing required fields: {', '.join(missing_fields)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required fields: {', '.join(missing_fields)}"
        )
    try:
        login = Login(**login_data)
    except ValidationError as e:
        error_messages = [err["msg"] for err in e.errors()]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=", ".join(error_messages)
        )
    email = login_data.get("email")
    username = login_data.get("target_user")

    if not email:
        raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Email must be provided"
    )

    if not username:
        raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Username must be provided"
    )

    # 🔄 Lookup user by email
    user = get_user_by_email(email)
    if user is None:
        raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"User with email '{email}' not found"
    )

    # 🔄 Verify that the email is associated with the username
    if user["username"] != username:
        raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"The email '{email}' is not associated with the username '{username}'"
    ) 

    # 🔄 Actual DB lookup for the requesting user (admin)
    admin_user = get_user_from_db(login.username)
    if admin_user is None or not verify_password(login.password, admin_user["password"]):
        update_token_metadata(login.username, success=False)  # ⛔ On failure
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    admin_roles = admin_user.get("roles", [])

    # 🔒 Ensure only admins can generate tokens
    if "admin" not in admin_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins are allowed to generate tokens"
        )

    # 🔄 Lookup the target user (specified by the admin)
    target_user = login_data.get("target_user")
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target user must be specified"
        )

    target_user_data = get_user_from_db(target_user)
    if target_user_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target user '{target_user}' not found"
        )

    # ✅ Generate access token for the target user
    access_token, expires_in_minutes = create_access_token(
        data={"sub": target_user, "roles": target_user_data.get("roles", []), "email": email},
        duration=login.duration
    )

    # 🕒 Calculate token expiration time
    expire_time = (datetime.utcnow() + timedelta(minutes=expires_in_minutes)).isoformat()

    # ✅ Update token metadata in DynamoDB
    update_token_metadata(target_user, success=True, expire_time=expire_time)

    return {
        "token_type": "bearer",
        "access_token": access_token,
        "expires_in_minutes": expires_in_minutes
    }
