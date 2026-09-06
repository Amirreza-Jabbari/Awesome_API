"""Email validation schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import InvalidEmailError
from app.utils.email import split_email


class EmailValidateRequest(BaseModel):
    email: str = Field(description="The email address to validate.", min_length=3, max_length=320)

    @field_validator("email")
    @classmethod
    def _syntax_check(cls, v: str) -> str:
        try:
            split_email(v)
        except InvalidEmailError as exc:
            raise ValueError(exc.message) from exc
        return v


class EmailValidateResponse(BaseModel):
    email: str
    domain: str
    local_part: str
    is_valid: bool = Field(description="Syntax-level validity (not mailbox existence).")
    is_disposable: bool | None = None
    is_public: bool | None = None
    mx_exists: bool | None = None
    main_category: str | None = None
    sub_category: str | None = None
    reason: str | None = Field(
        default=None,
        description="Human explanation when invalid, if any.",
    )
