import os
from base64 import urlsafe_b64encode
from passlib.context import CryptContext

SECRET_KEY = urlsafe_b64encode(os.urandom(32)).decode('utf-8')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": pwd_context.hash("password123"),
        "disabled": False,
        "roles": ["user"]
    },
    "admin": {
        "username": "admin",
        "full_name": "Admin User",
        "email": "admin@example.com",
        "hashed_password": pwd_context.hash("adminpass"),
        "disabled": False,
        "roles": ["user", "admin"]
    }
}
