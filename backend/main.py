import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from typing import Annotated
from pydantic import BaseModel
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from dotenv import load_dotenv

import database.models as models
from database.models import Users
from database.config import engine, SessionLocal


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

origins = [
    "https://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    email: str
    first_name: str
    last_name: str
    password: str

def get_user_by_email(email: str, db: db_dependency):
    return db.query(Users).filter(Users.email == email).first()

def create_user(user: UserCreate, db: db_dependency):
    hashed_password = pwd_context.hash(user.password)
    db_user = Users(email=user.email, first_name=user.first_name, last_name=user.last_name, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()

    return "complete"

@app.post('/register')
def register(user: UserCreate, db: db_dependency):
    db_user = get_user_by_email(email=user.email, db=db)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    return create_user(user=user, db=db)

def authenticate_user(email: str, password: str, db: db_dependency):
    user = db.query(Users).filter(Users.email == email).first()
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt

@app.post('/token')
def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")

        if email is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")
    
@app.get('/verify-token/{token}')
async def verify_user_token(token: str):
    verify_token(token=token)

    return {"message": "Token is valid"}