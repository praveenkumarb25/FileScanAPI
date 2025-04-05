from pydantic import BaseModel
from typing import Optional, List


# Token response model sent to the client after successful login
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in_minutes: int


# Token payload (used internally when extracting token data)
class TokenData(BaseModel):
    username: str
    roles: List[str]


# Public user model (used in responses)
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = False
    roles: Optional[List[str]] = []


# Model representing how user is stored in the DB (includes hashed_password)
class UserInDB(User):
    id: str
    password: str
    token_created: Optional[str] = None
    token_expiration: Optional[str] = None
    token_failed: Optional[int] = 0
    token_last_used: Optional[str] = None


# Model for login request
class Login(BaseModel):
    username: str
    password: str
    duration: str  # e.g., '30m' or '1h'


# Model used to represent a scan record
class Scan(BaseModel):
    time: str  # You may want to convert this to datetime
    is_infected: bool
    infected_by: Optional[str] = None


# Token response used by the API
class TokenResponse(BaseModel):
    token_type: str
    access_token: str
    expires_in_minutes: int

class RegisteredUserResponse(BaseModel):
    id: str
    username: str
    roles: List[str]
    token_created: Optional[str]
    token_expiration: Optional[str]
    token_failed: int
    token_last_used: Optional[str]