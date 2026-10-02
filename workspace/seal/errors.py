"""统一异常与原因码。"""
from __future__ import annotations


class SealError(Exception):
    """业务错误。code 为稳定原因码，http_status 供 REST 层使用。"""

    def __init__(self, code: str, message: str, http_status: int = 409,
                 detail: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.detail = detail or {}


class NotFound(SealError):
    def __init__(self, code: str, message: str, detail=None):
        super().__init__(code, message, 404, detail)


class BadRequest(SealError):
    def __init__(self, code: str, message: str, detail=None):
        super().__init__(code, message, 400, detail)


class Conflict(SealError):
    def __init__(self, code: str, message: str, detail=None):
        super().__init__(code, message, 409, detail)


class Forbidden(SealError):
    def __init__(self, code: str, message: str, detail=None):
        super().__init__(code, message, 403, detail)


class VerifyFailed(Exception):
    """离线/在线验真失败（可能同时包含多条问题）。"""

    def __init__(self, reasons: list[dict]):
        super().__init__("; ".join(r["code"] for r in reasons))
        self.reasons = reasons
