from fastapi import Depends, HTTPException, status
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from typing import List
from app.models import TokenData, User, UserInDB
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.core.config import SECRET_KEY, ALGORITHM
from app.core.config import get_user_from_db  # 👉 Import the real DB fetch

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# 🔄 Replaced fake db access with a real DB call
def get_user(username: str):
    user_dict = get_user_from_db(username)
    print(user_dict)
    if user_dict:
        return UserInDB(**user_dict)
    return None

def create_access_token(data: dict, duration: str):
    duration_mapping = {
        "1d": timedelta(days=1),
        "1w": timedelta(weeks=1),
        "1m": timedelta(days=30),  # Approximate a month
        "1y": timedelta(days=365),
    }
    
    if duration not in duration_mapping:
        raise ValueError("Invalid duration. Choose from '1d', '1w', '1m', or '1y'.")

    expires_delta = duration_mapping[duration]
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    remaining_time = int((expire - datetime.utcnow()).total_seconds() / 60)  # Convert to minutes
    
    return encoded_jwt, remaining_time

def get_current_user(token: str = Depends(OAuth2PasswordBearer(tokenUrl="token"))):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        roles: List[str] = payload.get("roles", [])
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, roles=roles)
    except JWTError:
        raise credentials_exception

    # ✅ Now fetch from real DB
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

def require_role(required_role: str):
    def role_dependency(user: User = Depends(get_current_user)):
        roles = user.roles
        if required_role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user
    return role_dependency
