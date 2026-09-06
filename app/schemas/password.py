"""Password generator schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class PasswordGenerateRequest(BaseModel):
    length: int = Field(default=16, ge=4, le=256, description="Password length (4-256).")
    exclude_numbers: bool = Field(default=False, description="Exclude digit characters.")
    exclude_special_chars: bool = Field(default=False, description="Exclude special characters.")
    min_upper: int = Field(default=1, ge=0, le=8, description="Minimum uppercase letters.")
    min_lower: int = Field(default=1, ge=0, le=8, description="Minimum lowercase letters.")
    min_numbers: int = Field(default=1, ge=0, le=8, description="Minimum digits.")
    min_specials: int = Field(default=1, ge=0, le=8, description="Minimum special characters.")

    @model_validator(mode="after")
    def _validate_feasibility(self) -> PasswordGenerateRequest:
        categories = [self.min_upper, self.min_lower]
        if not self.exclude_numbers:
            categories.append(self.min_numbers)
        if not self.exclude_special_chars:
            categories.append(self.min_specials)
        required = sum(categories)
        if required > self.length:
            raise ValueError(
                f"Minimum per-category requirements ({required}) exceed "
                f"requested length ({self.length})."
            )
        if (
            self.exclude_numbers
            and self.exclude_special_chars
            and (self.min_numbers > 0 or self.min_specials > 0)
        ):
            raise ValueError("Cannot require numbers/specials when those categories are excluded.")
        return self


class PasswordGenerateResponse(BaseModel):
    random_password: str = Field(description="A cryptographically secure random password.")
