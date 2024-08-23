from pydantic import BaseModel

class CreateUserModel(BaseModel):
    email: str
    first_name: str
    last_name: str
    password: str