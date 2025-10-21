from fastapi import APIRouter, Depends, HTTPException, status
from app.core.security import get_current_user, require_role, hash_password
from app.models import User, RegisteredUserResponse
from app.core.config import get_user_from_db
import boto3
from dotenv import load_dotenv
import os
import uuid

# Load AWS credentials
load_dotenv(dotenv_path="app/.env")

# AWS setup
dynamodb = boto3.resource(
    'dynamodb',
    region_name=os.getenv("AWS_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)
users = os.getenv("DYNAMODB_USERS_TABLE")
table = dynamodb.Table(users)

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


# ✅ Register route restricted to admin users only
@router.post("/register", response_model=RegisteredUserResponse, status_code=201)
async def register(
    user: dict,
    current_user: User = Depends(require_role("admin"))  # <-- ✅ Admin protection
):
    username = user.get("username")
    password = user.get("password")

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required."
        )

    existing_user = get_user_from_db(username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists."
        )

    user_id = str(uuid.uuid4())
    hashed_pw = hash_password(password)

    new_user = {
        "id": user_id,
        "username": username,
        "password": hashed_pw,
        "roles": ["user"],
        "token_created": "",
        "token_expiration": "",
        "token_failed": 0,
        "token_last_used": ""
    }

    table.put_item(Item=new_user)

    return {
        "id": new_user["id"],
        "username": new_user["username"],
        "roles": new_user["roles"],
        "token_created": new_user["token_created"],
        "token_expiration": new_user["token_expiration"],
        "token_failed": new_user["token_failed"],
        "token_last_used": new_user["token_last_used"]
    }
