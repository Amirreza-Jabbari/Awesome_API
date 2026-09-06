"""Disposable email checker schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import InvalidEmailError
from app.utils.email import split_email


class DisposableEmailRequest(BaseModel):
    email: str = Field(description="The email address to check.", min_length=3, max_length=320)

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: str) -> str:
        try:
            split_email(v)
        except InvalidEmailError as exc:
            raise ValueError(exc.message) from exc
        return v


class DisposableEmailResponse(BaseModel):
    email: str = Field(description="The email address (as supplied).")
    domain: str = Field(description="The normalized domain.")
    is_disposable: bool = Field(description="True if the domain is a known disposable host.")
