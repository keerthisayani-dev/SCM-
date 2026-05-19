from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1)
    email: EmailStr
    password: str = Field(..., min_length=8)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned_value = value.strip()
        if not cleaned_value:
            raise ValueError("Name mu st contain at least one non-space character.")
        return cleaned_value


class UserOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    email: EmailStr
    created_at: datetime


class UserInDB(UserOut):
    hashed_password: str
