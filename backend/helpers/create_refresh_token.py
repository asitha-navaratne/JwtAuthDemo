import os
from datetime import datetime, timedelta, timezone
from jose import jwt
from dotenv import load_dotenv


load_dotenv()

ALGORITHM = os.getenv("ALGORITHM")
REFRESH_TOKEN_SECRET_KEY = os.getenv("REFRESH_TOKEN_SECRET_KEY")
REFRESH_TOKEN_EXPIRE_MINUTES = os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES")

def create_refresh_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta is not None:
        expires_delta = datetime.now(timezone.utc) + expires_delta
    else:
        expires_delta = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expires_delta})
    encoded_jwt = jwt.encode(to_encode, REFRESH_TOKEN_SECRET_KEY, ALGORITHM)
    
    return encoded_jwt