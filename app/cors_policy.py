"""跨域来源策略：规范化、校验、原子生效与审计。

安全目标：
- 生产环境只接受规范化后的 HTTPS 来源清单；
- 开发环境的本机（loopback）来源必须显式开启；
- 通配符、null 来源、带用户信息的地址以及易混淆主机写法
  （整数/十六进制 IP、非四段点分 IPv4、结尾句点 FQDN 等）一律拒绝，
  凭据模式下更是绝不共存；
- 配置换版先完整校验再原子生效；启动或重载失败时继续使用最后一份
  有效策略（内存或快照），并留下不含密钥的审计摘要。
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional, Sequence
from urllib.parse import urlsplit

logger = logging.getLogger("app.cors")
if not logger.handlers:
    # 审计记录必须默认可见；部署方可用自己的日志配置接管该 logger
    _audit_handler = logging.StreamHandler()
    _audit_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    logger.addHandler(_audit_handler)
logger.setLevel(logging.INFO)
logger.propagate = False

ENVIRONMENT_PRODUCTION = "production"
ENVIRONMENT_DEVELOPMENT = "development"
_ENVIRONMENTS = (ENVIRONMENT_PRODUCTION, ENVIRONMENT_DEVELOPMENT)

DEFAULT_ALLOW_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
DEFAULT_ALLOW_HEADERS = ("authorization", "content-type")
DEFAULT_MAX_AGE = 600
MAX_MAX_AGE = 86400
DEFAULT_STATE_FILE = "./data/cors_policy_state.json"

_METHOD_RE = re.compile(r"^[A-Z]+$")
# RFC 9110 token（小写后校验）
_HEADER_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-z]+$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

# CORS 安全列表请求头：预检子集校验时豁免（浏览器可自行携带）
SAFELISTED_REQUEST_HEADERS = frozenset(
    {"accept", "accept-language", "content-language", "content-type"}
)


class PolicyValidationError(ValueError):
    """配置完整校验失败。"""


class StartupGateError(RuntimeError):
    """启动门禁：配置无效且没有可回退的最后有效策略。"""


def _normalize_host(host: str) -> Optional[str]:
    """规范化主机名；易混淆写法返回 None。

    拒绝：结尾句点 FQDN、整数/十六进制 IP、非严格四段点分 IPv4
    （含前导零）、非法 DNS 标签、非法 IP 字面量。
    """
    host = host.strip().lower()
    if not host or len(host) > 253:
        return None
    if host.endswith("."):
        return None
    if ":" in host:  # IPv6 字面量（urlsplit 已去掉方括号）
        try:
            return "[{}]".format(ipaddress.IPv6Address(host).compressed)
        except ValueError:
            return None
    try:  # 国际化域名统一为 punycode 再按 DNS 校验
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    if all(c in "0123456789." for c in host):
        # 纯数字与点：必须是严格四段 IPv4，拒绝 127.1 / 2130706433 / 0177.0.0.1
        try:
            return str(ipaddress.IPv4Address(host))
        except ValueError:
            return None
    if host.startswith("0x"):
        return None  # 十六进制 IP 写法
    labels = host.split(".")
    for label in labels:
        if not 1 <= len(label) <= 63:
            return None
        if not _DNS_LABEL_RE.match(label):
            return None
    return host


def normalize_origin(raw: object) -> Optional[str]:
    """把来源规范化为 scheme://host[:port]；不合法或不允许则返回 None。

    拒绝：通配符、null、用户信息、路径/查询/片段、非 http(s) 方案、
    易混淆主机写法。默认端口（http:80 / https:443）会被归一化掉，
    非默认端口保留并参与匹配。
    """
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw or len(raw) > 2048:
        return None
    if raw in ("*", "null"):
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    netloc = parts.netloc
    if "@" in netloc or parts.username is not None or parts.password is not None:
        return None  # 带用户信息的地址
    if parts.path or parts.query or parts.fragment:
        return None  # 来源不允许携带路径/查询/片段
    host = parts.hostname
    if not host:
        return None
    normalized_host = _normalize_host(host)
    if normalized_host is None:
        return None
    if netloc.rsplit("@", 1)[-1].endswith(":"):
        return None  # 空端口写法
    try:
        port = parts.port
    except ValueError:
        return None
    default_port = 443 if scheme == "https" else 80
    if port is not None:
        if not 1 <= port <= 65535:
            return None
        if port == default_port:
            port = None
    origin = "{}://{}".format(scheme, normalized_host)
    if port is not None:
        origin = "{}:{}".format(origin, port)
    return origin


def _is_loopback_host(host: str) -> bool:
    """host 为已规范化主机（可能带 IPv6 方括号）。"""
    bare = host.strip("[]")
    if bare == "localhost" or bare.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(bare).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class CorsPolicy:
    """不可变的有效策略快照；替换即整体替换（原子生效）。"""

    environment: str
    allowed_origins: frozenset
    allow_credentials: bool
    allow_localhost: bool
    allow_methods: tuple
    allow_headers: tuple
    max_age: int

    def allows(self, normalized_origin: str) -> bool:
        return normalized_origin in self.allowed_origins

    def summary(self) -> dict:
        """审计摘要内容：只含策略本身，不含任何密钥。"""
        return {
            "environment": self.environment,
            "allowed_origins": sorted(self.allowed_origins),
            "allow_credentials": self.allow_credentials,
            "allow_localhost": self.allow_localhost,
            "allow_methods": list(self.allow_methods),
            "allow_headers": list(self.allow_headers),
            "max_age": self.max_age,
        }

    @property
    def digest(self) -> str:
        canonical = json.dumps(self.summary(), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_policy(
    *,
    environment: str,
    origins: Sequence[str],
    allow_credentials: bool,
    allow_localhost: bool,
    allow_methods: Sequence[str],
    allow_headers: Sequence[str],
    max_age: int,
) -> CorsPolicy:
    """完整校验并构造策略；任何一项不合法都整体拒绝。"""
    if environment not in _ENVIRONMENTS:
        raise PolicyValidationError("APP_ENV 非法: {!r}".format(environment))

    normalized = []
    seen = set()
    for raw in origins:
        item = normalize_origin(raw)
        if item is None:
            raise PolicyValidationError(
                "来源不合法或不允许（通配/null/用户信息/混淆主机/非 http(s)）: {!r}".format(raw)
            )
        if item not in seen:
            seen.add(item)
            normalized.append(item)

    for origin in normalized:
        parts = urlsplit(origin)
        host = parts.hostname or ""
        loopback = _is_loopback_host(host)
        if environment == ENVIRONMENT_PRODUCTION:
            if parts.scheme != "https":
                raise PolicyValidationError("生产环境仅接受 HTTPS 来源: {}".format(origin))
            if loopback:
                raise PolicyValidationError("生产环境不接受本机来源: {}".format(origin))
        else:
            if loopback and not allow_localhost:
                raise PolicyValidationError(
                    "本机来源需显式开启 CORS_ALLOW_LOCALHOST: {}".format(origin)
                )
            if parts.scheme == "http" and not loopback:
                raise PolicyValidationError(
                    "开发环境仅本机来源可使用 HTTP: {}".format(origin)
                )

    methods = tuple(m.strip().upper() for m in allow_methods if m.strip())
    if not methods:
        raise PolicyValidationError("允许的方法列表不能为空")
    for method in methods:
        if not _METHOD_RE.match(method):
            raise PolicyValidationError("非法的允许方法: {!r}".format(method))

    headers = tuple(h.strip().lower() for h in allow_headers if h.strip())
    if not headers:
        raise PolicyValidationError("允许的请求头列表不能为空")
    for header in headers:
        if header == "*":
            raise PolicyValidationError("不允许通配请求头")
        if not _HEADER_TOKEN_RE.match(header):
            raise PolicyValidationError("非法的允许请求头: {!r}".format(header))

    if not isinstance(max_age, int) or not 0 <= max_age <= MAX_MAX_AGE:
        raise PolicyValidationError("CORS_MAX_AGE 超出范围: {!r}".format(max_age))

    if allow_credentials:
        # normalize_origin 已拒绝通配/null/用户信息/混淆主机，此处为不变量兜底
        for origin in normalized:
            if origin in ("*", "null") or "@" in origin:
                raise PolicyValidationError(
                    "凭据模式不得与通配/null/用户信息来源共存: {}".format(origin)
                )

    return CorsPolicy(
        environment=environment,
        allowed_origins=frozenset(normalized),
        allow_credentials=allow_credentials,
        allow_localhost=allow_localhost,
        allow_methods=methods,
        allow_headers=headers,
        max_age=max_age,
    )


def _parse_bool(raw: str, name: str) -> bool:
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise PolicyValidationError("{} 不是合法布尔值: {!r}".format(name, raw))


def load_policy_from_env(env: Mapping[str, str]) -> CorsPolicy:
    """从环境变量完整加载并校验策略（不产生任何副作用）。"""
    environment = env.get("APP_ENV", ENVIRONMENT_PRODUCTION).strip().lower()
    if not environment:
        environment = ENVIRONMENT_PRODUCTION
    raw_origins = [
        item.strip()
        for item in env.get("CORS_ALLOWED_ORIGINS", "").split(",")
        if item.strip()
    ]
    allow_credentials = _parse_bool(
        env.get("CORS_ALLOW_CREDENTIALS", "true"), "CORS_ALLOW_CREDENTIALS"
    )
    allow_localhost = _parse_bool(
        env.get("CORS_ALLOW_LOCALHOST", "false"), "CORS_ALLOW_LOCALHOST"
    )
    methods = [
        m.strip() for m in env.get("CORS_ALLOW_METHODS", "").split(",") if m.strip()
    ] or list(DEFAULT_ALLOW_METHODS)
    headers = [
        h.strip() for h in env.get("CORS_ALLOW_HEADERS", "").split(",") if h.strip()
    ] or list(DEFAULT_ALLOW_HEADERS)
    raw_max_age = env.get("CORS_MAX_AGE", str(DEFAULT_MAX_AGE)).strip()
    try:
        max_age = int(raw_max_age)
    except ValueError:
        raise PolicyValidationError("CORS_MAX_AGE 不是整数: {!r}".format(raw_max_age))
    return build_policy(
        environment=environment,
        origins=raw_origins,
        allow_credentials=allow_credentials,
        allow_localhost=allow_localhost,
        allow_methods=methods,
        allow_headers=headers,
        max_age=max_age,
    )


def _audit(result: str, policy: Optional[CorsPolicy], **extra) -> None:
    """输出不含密钥的审计摘要（JSON 单行日志）。"""
    record = {
        "event": "cors_policy",
        "result": result,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    if policy is not None:
        record["policy_hash"] = policy.digest
        record["summary"] = policy.summary()
    record.update(extra)
    logger.info(json.dumps(record, ensure_ascii=False, sort_keys=True))


@dataclass(frozen=True)
class ReloadResult:
    applied: bool
    reason: str
    active_policy: Optional[CorsPolicy]

    @property
    def active_hash(self) -> Optional[str]:
        return self.active_policy.digest if self.active_policy else None


class CorsPolicyStore:
    """进程内当前有效策略。

    - 替换为整体引用交换，配合线程锁保证原子生效；
    - 每次成功应用都会把策略快照原子写入状态文件；
    - 启动时环境配置无效则回退到快照，快照也没有就触发启动门禁；
    - 运行期重载失败保留最后一份有效策略。
    """

    def __init__(self, state_file: Optional[os.PathLike] = None):
        self._lock = threading.Lock()
        self._policy: Optional[CorsPolicy] = None
        self._state_file = Path(state_file) if state_file else None

    @property
    def current(self) -> Optional[CorsPolicy]:
        return self._policy

    @classmethod
    def from_environment(
        cls,
        env: Optional[Mapping[str, str]] = None,
        state_file: Optional[os.PathLike] = None,
    ) -> "CorsPolicyStore":
        env = os.environ if env is None else env
        if state_file is None:
            state_file = env.get("CORS_POLICY_STATE_FILE") or DEFAULT_STATE_FILE
        store = cls(state_file)
        try:
            policy = load_policy_from_env(env)
        except PolicyValidationError as exc:
            fallback = store._load_snapshot(env)
            if fallback is not None:
                store._policy = fallback
                _audit("fallback_to_snapshot", fallback, reason=str(exc))
                return store
            _audit("startup_rejected", None, reason=str(exc))
            raise StartupGateError(
                "跨域策略启动门禁拒绝启动: {}".format(exc)
            ) from exc
        store._policy = policy
        store._persist(policy)
        _audit("applied", policy, source="environment")
        return store

    def reload_from_environment(
        self, env: Optional[Mapping[str, str]] = None
    ) -> ReloadResult:
        """运行期换版：先完整校验，通过才原子替换；失败保留旧策略。"""
        env = os.environ if env is None else env
        try:
            policy = load_policy_from_env(env)
        except PolicyValidationError as exc:
            _audit("reload_rejected", self._policy, reason=str(exc))
            return ReloadResult(False, str(exc), self._policy)
        with self._lock:
            self._policy = policy
        self._persist(policy)
        _audit("applied", policy, source="reload")
        return ReloadResult(True, "", policy)

    # ---- 快照持久化 ----

    def _persist(self, policy: CorsPolicy) -> None:
        if self._state_file is None:
            return
        payload = json.dumps(policy.summary(), sort_keys=True, ensure_ascii=False)
        snapshot = {
            "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "policy": policy.summary(),
        }
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_file.with_suffix(self._state_file.suffix + ".tmp")
            tmp.write_text(
                json.dumps(snapshot, ensure_ascii=False, sort_keys=True),
                encoding="utf-8",
            )
            os.replace(tmp, self._state_file)  # 原子生效
        except OSError as exc:
            logger.warning("cors_policy snapshot persist failed: %s", exc)

    def _load_snapshot(self, env: Mapping[str, str]) -> Optional[CorsPolicy]:
        if self._state_file is None or not self._state_file.is_file():
            return None
        try:
            snapshot = json.loads(self._state_file.read_text(encoding="utf-8"))
            summary = snapshot["policy"]
            payload = json.dumps(summary, sort_keys=True, ensure_ascii=False)
            if snapshot.get("sha256") != hashlib.sha256(
                payload.encode("utf-8")
            ).hexdigest():
                logger.warning("cors_policy snapshot checksum mismatch")
                return None
            policy = build_policy(
                environment=summary["environment"],
                origins=summary["allowed_origins"],
                allow_credentials=bool(summary["allow_credentials"]),
                allow_localhost=bool(summary["allow_localhost"]),
                allow_methods=summary["allow_methods"],
                allow_headers=summary["allow_headers"],
                max_age=int(summary["max_age"]),
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning("cors_policy snapshot invalid: %s", exc)
            return None
        current_env = env.get("APP_ENV", ENVIRONMENT_PRODUCTION).strip().lower()
        if policy.environment != current_env:
            logger.warning(
                "cors_policy snapshot environment %r != current %r",
                policy.environment,
                current_env,
            )
            return None
        return policy
