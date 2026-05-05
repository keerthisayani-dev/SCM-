from pydantic import BaseModel, Field


class AuthToken(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AuthUserSummary(BaseModel):
    id: str
    username: str
    email: str


class AuthResponse(BaseModel):
    message: str
    token_type: str = "bearer"
    access_token: str
    user: AuthUserSummary


class UserSignupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=6)


class UserLoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=6)


class UserProfileResponse(BaseModel):
    id: str
    username: str
    email: str


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., min_length=6)
    new_password: str = Field(..., min_length=6)


class PasswordCheckRequest(BaseModel):
    password: str = Field(..., min_length=6)


class PasswordCheckResponse(BaseModel):
    valid: bool
    message: str
