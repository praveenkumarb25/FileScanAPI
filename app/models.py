from pydantic import BaseModel
from typing import Optional, List

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in_minutes: int

class TokenData(BaseModel):
    username: str
    roles: List[str]

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None
    roles: Optional[List[str]] = []

class UserInDB(User):
    hashed_password: str

class Login(BaseModel):
    username: str
    password: str

class Scan(BaseModel):
    time: str
    #username: Optional[str] = None
    is_infected : bool
    infected_by : Optional[str] = None