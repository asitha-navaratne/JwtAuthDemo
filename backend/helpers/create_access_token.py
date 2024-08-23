import os
from datetime import datetime, timedelta, timezone
from jose import jwt
from dotenv import load_dotenv


load_dotenv()

ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_SECRET_KEY = os.getenv("ACCESS_TOKEN_SECRET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta is not None:
        expires_delta = datetime.now(timezone.utc) + expires_delta
    else:
        expires_delta = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expires_delta})
    encoded_jwt = jwt.encode(to_encode, ACCESS_TOKEN_SECRET_KEY, ALGORITHM)

    return encoded_jwt