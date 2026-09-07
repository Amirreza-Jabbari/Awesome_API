"""Domain-specific exceptions and their mapping to clean HTTP responses.

Internal services raise these exceptions; exception handlers translate them
into the documented JSON error envelope:

    {
        "error": {
            "code": "INVALID_DOMAIN",
            "message": "The supplied domain is invalid."
        }
    }

Internal implementation details (tracebacks, paths, provider internals) must
never leak into these responses. Details are only logged server-side.
"""

from __future__ import annotations

from typing import Any, ClassVar


class AwesomeAPIError(Exception):
    """Base class for all application/domain errors."""

    code: ClassVar[str] = "API_ERROR"
    status_code: ClassVar[int] = 500
    default_message: ClassVar[str] = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        detail: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        resolved_message = (
            message.strip()
            if isinstance(message, str) and message.strip()
            else self.default_message
        )

        self.message = resolved_message
        self.detail = detail.strip() if isinstance(detail, str) and detail.strip() else None
        self.details = details if isinstance(details, dict) else None

        super().__init__(self.message)

    def to_response(self) -> dict[str, Any]:
        """Return the public, sanitized API error envelope."""
        error: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.details is not None:
            error["details"] = self.details
        return {"error": error}


class ValidationError(AwesomeAPIError):
    """Base class for invalid user-supplied input."""

    code = "VALIDATION_ERROR"
    status_code = 422
    default_message = "The supplied input is invalid."


class InvalidEmailError(ValidationError):
    code = "INVALID_EMAIL"
    default_message = "The supplied email address is invalid."


class InvalidDomainError(ValidationError):
    code = "INVALID_DOMAIN"
    default_message = "The supplied domain is invalid."


class InvalidIPAddressError(ValidationError):
    code = "INVALID_IP"
    default_message = "The supplied IP address is invalid."


class InvalidURLError(ValidationError):
    code = "INVALID_URL"
    default_message = "The supplied URL is invalid."


class InvalidPhoneError(ValidationError):
    code = "INVALID_PHONE"
    default_message = "The supplied phone number is invalid."


class InvalidUserAgentError(ValidationError):
    code = "INVALID_USER_AGENT"
    default_message = "The supplied user agent is invalid."


class SSRFBlockedError(AwesomeAPIError):
    code = "SSRF_BLOCKED"
    status_code = 422
    default_message = "The supplied URL resolves to a disallowed address."


class ResolutionBlockedError(AwesomeAPIError):
    code = "RESOLUTION_BLOCKED"
    status_code = 422
    default_message = "The supplied target resolves to a disallowed address."


class DNSLookupError(AwesomeAPIError):
    """Base class for DNS resolution failures."""

    code = "DNS_ERROR"
    status_code = 502
    default_message = "DNS lookup failed."


class DNSNXDomainError(DNSLookupError):
    """The queried DNS name does not exist."""

    code = "DNS_NXDOMAIN"
    status_code = 404
    default_message = "The domain could not be resolved (NXDOMAIN)."


class DNSTimeoutError(DNSLookupError):
    """The DNS resolver exceeded its configured timeout."""

    code = "DNS_TIMEOUT"
    status_code = 504
    default_message = "DNS lookup timed out."


class DNSNoDataError(DNSLookupError):
    """The domain exists but has no requested record type."""

    code = "DNS_NODATA"
    status_code = 404
    default_message = "No DNS data found for the requested record type."


class ProviderTimeoutError(AwesomeAPIError):
    code = "PROVIDER_TIMEOUT"
    status_code = 504
    default_message = "An external provider request timed out."


class ProviderUnavailableError(AwesomeAPIError):
    code = "PROVIDER_UNAVAILABLE"
    status_code = 502
    default_message = "An external provider is currently unavailable."


class ProviderConfigurationError(AwesomeAPIError):
    code = "PROVIDER_CONFIG_ERROR"
    status_code = 503
    default_message = "An external provider is not configured."


class WHOISUnavailableError(ProviderUnavailableError):
    code = "WHOIS_UNAVAILABLE"
    default_message = "WHOIS/RDAP data is not available for this domain."


class RateLimitExceededError(AwesomeAPIError):
    code = "RATE_LIMITED"
    status_code = 429
    default_message = "Too many requests. Please try again later."


class ParserError(AwesomeAPIError):
    code = "PARSER_ERROR"
    status_code = 422
    default_message = "The supplied data could not be safely parsed."


class InternalError(AwesomeAPIError):
    code = "INTERNAL_ERROR"
    status_code = 500
    default_message = "An internal error occurred."


class BrowserCapacityError(AwesomeAPIError):
    code = "BROWSER_CAPACITY"
    status_code = 503
    default_message = "The design-system browser capacity is currently exhausted."


class AuthenticationRequiredError(AwesomeAPIError):
    code = "AUTHENTICATION_REQUIRED"
    status_code = 401
    default_message = (
        "The target website requires authentication; public extraction is not supported."
    )


class InvalidSelectorError(ValidationError):
    code = "INVALID_SELECTOR"
    default_message = "The supplied CSS selector is invalid."


class ElementNotFoundError(ValidationError):
    code = "ELEMENT_NOT_FOUND"
    default_message = "The requested page element was not found."


class MultipleElementsError(ValidationError):
    code = "MULTIPLE_ELEMENTS"
    default_message = "The selector matched more than one element."


class ResourceLimitError(AwesomeAPIError):
    code = "RESOURCE_LIMIT"
    status_code = 413
    default_message = "The requested resource exceeds the allowed limit."


class ImageProcessingError(AwesomeAPIError):
    """Base class for local image-processing failures."""

    code = "IMAGE_PROCESSING_ERROR"
    status_code = 422
    default_message = "The supplied image could not be processed."


class ImageFormatUnsupportedError(ImageProcessingError):
    code = "IMAGE_FORMAT_UNSUPPORTED"
    default_message = "The supplied image format is not supported."


class ImageFeatureDisabledError(ImageProcessingError):
    code = "IMAGE_FEATURE_DISABLED"
    default_message = "The requested image feature is not enabled on this deployment."


class ImageTimeoutError(ImageProcessingError):
    code = "IMAGE_TIMEOUT"
    status_code = 504
    default_message = "Image processing timed out."
