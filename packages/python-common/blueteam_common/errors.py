from __future__ import annotations


class BlueTeamError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class NotFoundError(BlueTeamError):
    def __init__(self, message: str = "Resource not found") -> None:
        super().__init__("NOT_FOUND", message, 404)


class PermissionDeniedError(BlueTeamError):
    def __init__(self, message: str = "Permission denied") -> None:
        super().__init__("PERMISSION_DENIED", message, 403)


class TenantIsolationError(BlueTeamError):
    def __init__(self, message: str = "Cross-tenant access denied") -> None:
        super().__init__("TENANT_ISOLATION", message, 403)


class ConflictError(BlueTeamError):
    def __init__(self, message: str = "Conflict") -> None:
        super().__init__("CONFLICT", message, 409)


class UnauthorizedError(BlueTeamError):
    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__("UNAUTHORIZED", message, 401)
