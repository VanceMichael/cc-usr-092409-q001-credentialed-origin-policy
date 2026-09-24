"""统一策略的 CORS 中间件。

预检（OPTIONS + Access-Control-Request-Method）与实际响应使用同一份
CorsPolicy：
- 只有命中允许清单（规范化后精确匹配，含端口）的来源才会得到放行头，
  且凭据模式下回显具体来源，绝不通配；
- 未获信任的来源拿不到任何 Access-Control-Allow-* 头；预检拒绝统一
  返回 403，与路径、方法是否存在无关，实际请求则按无 Origin 处理，
  避免借错误差异探测受保护资源；
- 所有响应合并 Vary: Origin，预检额外声明
  Access-Control-Request-Method / Access-Control-Request-Headers，
  保证缓存键正确。
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

from starlette.responses import PlainTextResponse

from .cors_policy import SAFELISTED_REQUEST_HEADERS, normalize_origin

_PREFLIGHT_VARY = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
_FORBIDDEN_BODY = "Forbidden"


def _merge_vary(
    headers: List[Tuple[bytes, bytes]], additions: Iterable[str]
) -> List[Tuple[bytes, bytes]]:
    """把 additions 合并进已有 Vary（不区分大小写、去重）。"""
    result: List[Tuple[bytes, bytes]] = []
    tokens: List[str] = []
    for key, value in headers:
        if key.lower() == b"vary":
            tokens.extend(
                t.strip() for t in value.decode("latin-1").split(",") if t.strip()
            )
        else:
            result.append((key, value))
    lowered = {t.lower() for t in tokens}
    if "*" not in lowered:
        for item in additions:
            if item.lower() not in lowered:
                tokens.append(item)
                lowered.add(item.lower())
    if tokens:
        result.append((b"vary", ", ".join(tokens).encode("latin-1")))
    return result


class CorsPolicyMiddleware:
    """纯 ASGI 中间件，每个请求从 store 取当前策略（换版即时生效）。"""

    def __init__(self, app, store):
        self.app = app
        self.store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        policy = self.store.current
        request_headers = {}
        for key, value in scope.get("headers", []):
            request_headers.setdefault(
                key.decode("latin-1").lower(), value.decode("latin-1")
            )
        origin = request_headers.get("origin")

        if policy is None or origin is None:
            # 无 Origin：服务端到服务端调用，正常处理，仅补 Vary 防缓存串味
            await self._forward(scope, receive, send, cors_headers=None)
            return

        normalized = normalize_origin(origin)
        allowed = normalized is not None and policy.allows(normalized)

        if (
            scope["method"] == "OPTIONS"
            and "access-control-request-method" in request_headers
        ):
            response = self._preflight(
                policy, request_headers, normalized if allowed else None
            )
            await response(scope, receive, send)
            return

        cors_headers = None
        if allowed:
            cors_headers = [("access-control-allow-origin", normalized)]
            if policy.allow_credentials:
                cors_headers.append(("access-control-allow-credentials", "true"))
        await self._forward(scope, receive, send, cors_headers=cors_headers)

    def _preflight(
        self, policy, request_headers, normalized_origin: Optional[str]
    ) -> PlainTextResponse:
        def forbidden() -> PlainTextResponse:
            # 统一的 403：不随路径/方法/头是否存在而变化，避免探测差异
            return PlainTextResponse(
                _FORBIDDEN_BODY, status_code=403, headers={"Vary": _PREFLIGHT_VARY}
            )

        if normalized_origin is None:
            return forbidden()
        requested_method = (
            request_headers.get("access-control-request-method", "").strip().upper()
        )
        if requested_method not in policy.allow_methods:
            return forbidden()
        requested_headers = request_headers.get("access-control-request-headers", "")
        for header in requested_headers.split(","):
            header = header.strip().lower()
            if not header or header in SAFELISTED_REQUEST_HEADERS:
                continue
            if header not in policy.allow_headers:
                return forbidden()
        headers = {
            "Access-Control-Allow-Origin": normalized_origin,
            "Access-Control-Allow-Methods": ", ".join(policy.allow_methods),
            "Access-Control-Allow-Headers": ", ".join(policy.allow_headers),
            "Access-Control-Max-Age": str(policy.max_age),
            "Vary": _PREFLIGHT_VARY,
        }
        if policy.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        return PlainTextResponse("", status_code=200, headers=headers)

    async def _forward(self, scope, receive, send, cors_headers):
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers = _merge_vary(headers, ["Origin"])
                if cors_headers:
                    existing = {key.lower() for key, _ in headers}
                    for key, value in cors_headers:
                        encoded = key.encode("latin-1")
                        if encoded not in existing:
                            headers.append(
                                (encoded, value.encode("latin-1"))
                            )
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)
