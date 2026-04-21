import re

import dns.exception
import dns.resolver
from pydantic import BaseModel, ValidationInfo, field_validator


def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    return password


def validate_email_domain_has_mx(email: str) -> str:
    normalized_email = email.strip().lower()
    domain = normalized_email.rsplit("@", 1)[-1]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    try:
        answers = resolver.resolve(domain, "MX")
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        dns.exception.DNSException,
    ) as exc:
        raise ValueError("Email domain does not have valid mail DNS records") from exc

    if not answers:
        raise ValueError("Email domain does not have valid mail DNS records")

    return normalized_email


class UserSignup(BaseModel):
    name: str
    email: str
    phone: str
    password: str
    confirm_password: str

    @field_validator("email")
    @classmethod
    def email_must_be_valid(cls, value: str) -> str:
        value = value.strip().lower()
        pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
        if not re.match(pattern, value):
            raise ValueError("Invalid email address")
        return validate_email_domain_has_mx(value)

    @field_validator("phone")
    @classmethod
    def phone_must_be_valid(cls, value: str) -> str:
        if not value.isdigit() or len(value) != 10:
            raise ValueError("Phone number must be 10 digits")
        return value

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, value: str, info: ValidationInfo) -> str:
        if "password" in info.data and value != info.data["password"]:
            raise ValueError("Passwords do not match")
        return value

    @field_validator("password")
    @classmethod
    def password_is_strong(cls, value: str) -> str:
        return validate_password_strength(value)


class UserLogin(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
        if not re.match(pattern, normalized):
            raise ValueError("Invalid email address")
        return normalized


class UserData(BaseModel):
    name: str
    email: str
    phone: str


class TokenResponse(BaseModel):
    message: str
    access_token: str
    token_type: str = "bearer"
    user: UserData


class PasswordVerifyRequest(BaseModel):
    password: str


class PasswordVerifyResponse(BaseModel):
    message: str
    is_valid: bool


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_new_password: str

    @field_validator("new_password")
    @classmethod
    def new_password_is_strong(cls, value: str) -> str:
        return validate_password_strength(value)

    @field_validator("confirm_new_password")
    @classmethod
    def new_passwords_match(cls, value: str, info: ValidationInfo) -> str:
        if "new_password" in info.data and value != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return value
