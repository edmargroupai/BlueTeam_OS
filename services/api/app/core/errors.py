from __future__ import annotations

from blueteam_common.errors import BlueTeamError
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


def request_id_of(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


async def blueteam_error_handler(request: Request, exc: BlueTeamError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.code,
                "message": exc.message,
                "request_id": request_id_of(request),
            }
        },
    )


async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = "HTTP_ERROR"
    if exc.status_code == 401:
        code = "UNAUTHORIZED"
    elif exc.status_code == 403:
        code = "PERMISSION_DENIED"
    elif exc.status_code == 404:
        code = "NOT_FOUND"
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": code,
                "message": str(exc.detail),
                "request_id": request_id_of(request),
            }
        },
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "request_id": request_id_of(request),
            }
        },
    )
