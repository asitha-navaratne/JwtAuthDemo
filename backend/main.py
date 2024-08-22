from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from typing import Annotated

import database.models as models
from database.config import engine, SessionLocal

app = FastAPI()

models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

@app.post('/users')
async def get_all_users(db: db_dependency):
    user = db.query(models.Users).all()

    return user