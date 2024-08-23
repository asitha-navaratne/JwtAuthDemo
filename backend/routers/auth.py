import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Annotated
from pydantic import BaseModel
from datetime import timedelta
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from dotenv import load_dotenv

from database.models import Users
from database.config import SessionLocal

from helpers.create_access_token import create_access_token
from helpers.verify_token import verify_token


load_dotenv()

ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_SECRET_KEY = os.getenv("ACCESS_TOKEN_SECRET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

router = APIRouter(
    prefix='/auth',
    tags=['Auth']
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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

def authenticate_user(email: str, password: str, db: db_dependency):
    user = db.query(Users).filter(Users.email == email).first()
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    
    return user

@router.post('/token')
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

@router.post('/register')
def register(user: UserCreate, db: db_dependency):
    db_user = get_user_by_email(email=user.email, db=db)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    return create_user(user=user, db=db)

@router.get('/verify-token/{token}')
async def verify_user_token(token: str):
    verify_token(token=token)

    return {"message": "Token is valid"}