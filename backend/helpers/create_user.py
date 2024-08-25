from sqlalchemy.orm import Session
from passlib.context import CryptContext

from database.models import Users
from models.CreateUserModel import CreateUserModel


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_user(user: CreateUserModel, db: Session) -> int:
    hashed_password = pwd_context.hash(user.password)
    db_user = Users(email=user.email, first_name=user.first_name, last_name=user.last_name, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()

    return 201
