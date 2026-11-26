class DomainError(Exception):
    """An expected failure that maps to an HTTP status and a safe public message."""

    status_code = 400

    def __init__(self, detail: str, *, headers: dict[str, str] | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        self.headers = headers or {}


class Unauthorized(DomainError):
    status_code = 401


class Forbidden(DomainError):
    status_code = 403


class NotFound(DomainError):
    status_code = 404


class Conflict(DomainError):
    status_code = 409


class Gone(DomainError):
    status_code = 410


class Invalid(DomainError):
    status_code = 422


class QuotaExceeded(DomainError):
    status_code = 413


class TooManyAttempts(DomainError):
    status_code = 429


class StorageUnavailable(DomainError):
    status_code = 502
