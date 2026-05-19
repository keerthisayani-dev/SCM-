from enum import Enum

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


PASSWORD_RULE_MESSAGE = (
    "Password must be at least 8 characters long and include at least one "
    "lowercase letter, one uppercase letter, and one special character."
)


def validate_password_rule(password: str) -> str:
    has_min_length = len(password) >= 8
    has_lowercase = any(character.islower() for character in password)
    has_uppercase = any(character.isupper() for character in password)
    has_special_character = any(not character.isalnum() for character in password)

    if not (has_min_length and has_lowercase and has_uppercase and has_special_character):
        raise ValueError(PASSWORD_RULE_MESSAGE)
    return password


class UserSignupRequest(BaseModel):
    username: str = Field(..., min_length=1)
    email: EmailStr
    phone_number: str = Field(..., min_length=10, max_length=10)
    password: str
    confirm_password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Username must contain at least one non-space character.")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_rule(value)

    @field_validator("phone_number")
    @classmethod
    def validate_phone_number(cls, value: str) -> str:
        if not value.isdigit():
            raise ValueError("Phone number must contain digits only.")
        if len(value) != 10:
            raise ValueError("Phone number must be exactly 10 digits.")
        return value

    @model_validator(mode="after")
    def validate_password_confirmation(self) -> "UserSignupRequest":
        if self.password != self.confirm_password:
            raise ValueError("Password and confirm password must match.")
        return self


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class RoleEnum(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class UserProfileResponse(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: RoleEnum


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return validate_password_rule(value)

    @model_validator(mode="after")
    def validate_password_confirmation(self) -> "PasswordChangeRequest":
        if self.new_password != self.confirm_password:
            raise ValueError("New password and confirm password must match.")
        return self


class PasswordCheckRequest(BaseModel):
    password: str


class PasswordCheckResponse(BaseModel):
    valid: bool
    message: str


class AdminUserSummary(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: RoleEnum
    is_active: bool = True


class UserRoleUpdateRequest(BaseModel):
    role: RoleEnum
