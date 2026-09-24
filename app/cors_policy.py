"""跨域凭据策略：来源规范化、严格校验、原子换版与统一中间件。

设计目标：
- 生产环境只接受规范化的 HTTPS 来源；开发环境的本机（loopback）来源必须显式开启。
- 通配符、``null``、用户信息（userinfo）、非规范/混淆主机写法一律拒绝。
- 预检与实际请求共用同一份不可变策略；未信任来源得不到任何放行头，
  预检一律返回相同的无放行头响应，避免借状态码差异探测受保护资源。
- 配置必须先完整校验，再原子替换生效；热装载失败、多进程重载失败时
  继续使用最后一份有效策略（LKG），并写入不含密钥的审计摘要。
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import Response

logger = logging.getLogger("aquaculture.cors")

SAFE_SCHEMES = ("http", "https")
DEFAULT_ALLOW_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
DEFAULT_ALLOW_HEADERS = ("Authorization", "Content-Type", "Accept")
DEFAULT_MAX_AGE = 600

# Fetch 标准中始终可用的简单头；预检即使未显式配置也应放行。
_SAFELISTED_REQUEST_HEADERS = frozenset(
    {"accept", "accept-language", "content-language"}
)

SNAPSHOT_FILENAME = "cors-policy.snapshot.json"
AUDIT_FILENAME = "cors-audit.log"
_POLICY_FILE_KEYS = {
    "allowed_origins",
    "allow_localhost",
    "localhost_ports",
    "allow_methods",
    "allow_headers",
    "max_age",
}


class PolicyValidationError(ValueError):
    """策略配置无法通过校验。消息只包含键名/来源等非密信息。"""


@dataclass(frozen=True)
class CorsPolicy:
    """不可变的跨域策略快照。"""

    allowed_origins: frozenset[str]
    allow_methods: tuple[str, ...]
    allow_headers: frozenset[str]
    max_age: int = DEFAULT_MAX_AGE
    allow_localhost: bool = False
    env: str = "production"
    source: str = "unknown"

    def fingerprint(self) -> str:
        material = json.dumps(
            {
                "origins": sorted(self.allowed_origins),
                "methods": list(self.allow_methods),
                "headers": sorted(self.allow_headers),
                "max_age": self.max_age,
                "allow_localhost": self.allow_localhost,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:16]

    def audit_summary(self) -> dict:
        """供日志/审计使用的摘要：只含计数与指纹，绝不含凭据。"""
        return {
            "env": self.env,
            "source": self.source,
            "origins_count": len(self.allowed_origins),
            "origins": sorted(self.allowed_origins),
            "methods": list(self.allow_methods),
            "headers_count": len(self.allow_headers),
            "headers": sorted(self.allow_headers),
            "max_age": self.max_age,
            "allow_localhost": self.allow_localhost,
            "fingerprint": self.fingerprint(),
        }

    def matches_origin(self, origin: str | None) -> bool:
        return bool(origin) and origin in self.allowed_origins

    def allows_method(self, method: str) -> bool:
        return method.upper() in self.allow_methods

    def check_request_headers(self, requested: Iterable[str]) -> list[str] | None:
        """校验 Access-Control-Request-Headers。

        全部允许时返回规范化（去空格、小写比较、保留原写法）的列表；
        任一不允许则返回 None。
        """
        accepted: list[str] = []
        for raw in requested:
            name = raw.strip()
            if not name:
                continue
            folded = name.lower()
            if folded in _SAFELISTED_REQUEST_HEADERS:
                continue
            if folded not in self.allow_headers:
                return None
            accepted.append(name)
        return accepted


# ---------------------------------------------------------------------------
# 来源规范化与校验
# ---------------------------------------------------------------------------

def _host_is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_HOST_LABEL_RE = re.compile(
    r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _looks_like_noncanonical_ip(raw_host: str, parts: list[str]) -> bool:
    """识别需要拒绝的非规范/混淆 IP 写法（127.1、0x7f.1、0177.0.0.1、整数）。"""
    if raw_host.isdigit():
        return True
    for part in parts:
        if not part:
            continue
        # 十六进制段、带前导零的数字段、纯 hex 字符与数字混合的段。
        if part[:2].lower() == "0x" and any(ch.isdigit() for ch in part[2:]):
            return True
        if len(part) > 1 and part.isdigit() and part.startswith("0"):
            return True
        lowered = part.lower()
        if (
            any(ch.isdigit() for ch in lowered)
            and any(ch.isalpha() for ch in lowered)
            and all(ch in "0123456789abcdefx" for ch in lowered)
        ):
            return True
    # 1-3 段的纯数字点分形式（如 127.1）。
    if 1 < len(parts) < 4 and all(p.isdigit() for p in parts if p):
        return True
    return False


def _canonicalize_host(raw_host: str) -> str:
    """把主机部分规范化为字面量；任何非规范/混淆写法都抛错。"""
    if not raw_host:
        raise PolicyValidationError("来源缺少主机名")
    if raw_host.endswith("."):
        raise PolicyValidationError(f"主机名不允许尾随点: {raw_host!r}")

    # IPv6：必须带方括号传入。
    if raw_host.startswith("["):
        if not raw_host.endswith("]"):
            raise PolicyValidationError(f"IPv6 主机括号不闭合: {raw_host!r}")
        literal = raw_host[1:-1]
        try:
            ip = ipaddress.IPv6Address(literal)
        except ValueError:
            raise PolicyValidationError(f"非法或非规范 IPv6 字面量: {raw_host!r}")
        canonical_ip = str(ip)
        if literal.lower() != canonical_ip:
            raise PolicyValidationError(
                f"IPv6 必须使用压缩规范写法 [{canonical_ip}]: {raw_host!r}"
            )
        return canonical_ip

    parts = raw_host.split(".")
    # IPv4：只接受点分四段纯数字的规范写法，拒绝 127.1 / 0x7f.1 / 整数等混淆形式。
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            ip = ipaddress.IPv4Address(raw_host)
        except ValueError:
            raise PolicyValidationError(f"非法 IPv4 字面量: {raw_host!r}")
        canonical_ip = str(ip)
        if raw_host != canonical_ip:
            raise PolicyValidationError(
                f"IPv4 不允许前导零等非规范写法，应为 {canonical_ip}: {raw_host!r}"
            )
        return canonical_ip
    if _looks_like_noncanonical_ip(raw_host, parts):
        raise PolicyValidationError(
            f"疑似非规范 IP 字面量（只接受点分四段）: {raw_host!r}"
        )

    # 域名：先小写化并做 IDNA，再逐标签严格校验。
    try:
        encoded = raw_host.lower().encode("idna").decode("ascii")
    except UnicodeError:
        raise PolicyValidationError(f"主机名无法进行 IDNA 规范化: {raw_host!r}")
    for label in encoded.split("."):
        if not _HOST_LABEL_RE.match(label):
            raise PolicyValidationError(
                f"主机名标签非法（空标签、非法字符或连字符位置）: {raw_host!r}"
            )
    return encoded


def normalize_origin(raw: object, *, env: str = "production") -> str:
    """把单条来源配置规范化为 ``scheme://host[:port]``。

    生产环境只允许 https；开发环境仅对 loopback 主机放行 http（需另外显式开启）。
    """
    if not isinstance(raw, str):
        raise PolicyValidationError("来源必须是字符串")
    value = raw.strip()
    if not value:
        raise PolicyValidationError("来源为空")
    if value == "*" or value.lower() == "null":
        raise PolicyValidationError("不允许通配符 * 或 null 来源")

    parts = urlsplit(value)
    if parts.scheme not in SAFE_SCHEMES:
        raise PolicyValidationError(f"来源协议必须是 http/https: {raw!r}")
    if not parts.hostname:
        raise PolicyValidationError(f"来源缺少主机名: {raw!r}")
    # 用户信息（含 https://good.com@evil.com 这类混淆）直接拒绝。
    if "@" in parts.netloc or parts.username is not None:
        raise PolicyValidationError(f"来源不允许携带用户信息: {raw!r}")
    if parts.path or parts.query or parts.fragment:
        raise PolicyValidationError(f"来源不允许包含路径/查询/片段: {raw!r}")
    if parts.netloc != parts.netloc.strip():
        raise PolicyValidationError(f"来源含有空白字符: {raw!r}")

    # 拆解原始主机与端口（urlsplit 会宽容 :0443，需自己做最小形式校验）。
    netloc = parts.netloc
    if netloc.startswith("["):
        end = netloc.find("]")
        if end < 0:
            raise PolicyValidationError(f"IPv6 主机括号不闭合: {raw!r}")
        raw_host = netloc[: end + 1]
        rest = netloc[end + 1 :]
        raw_port = rest[1:] if rest.startswith(":") else ""
        if rest and not rest.startswith(":"):
            raise PolicyValidationError(f"来源主机写法非法: {raw!r}")
    else:
        if netloc.count(":") > 1:
            raise PolicyValidationError(f"来源主机写法非法: {raw!r}")
        raw_host, sep, raw_port = netloc.rpartition(":")
        if not sep:
            raw_host, raw_port = netloc, ""

    if raw_port:
        if not raw_port.isdigit():
            raise PolicyValidationError(f"端口必须是纯数字: {raw!r}")
        if len(raw_port) > 1 and raw_port.startswith("0"):
            raise PolicyValidationError(f"端口不允许前导零: {raw!r}")
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise PolicyValidationError(f"端口超出 1-65535 范围: {raw!r}")
    else:
        port = None

    canonical_host = _canonicalize_host(raw_host)

    # 默认端口必须省略：浏览器 Origin 头从不带 :443/:80。
    if port is not None and (
        (parts.scheme == "https" and port == 443)
        or (parts.scheme == "http" and port == 80)
    ):
        raise PolicyValidationError(f"来源必须省略默认端口: {raw!r}")

    host_part = f"[{canonical_host}]" if raw_host.startswith("[") else canonical_host
    canonical = f"{parts.scheme}://{host_part}"
    if port is not None:
        canonical = f"{canonical}:{port}"

    if env == "production" and _host_is_loopback(canonical_host):
        raise PolicyValidationError(
            f"生产环境来源清单不允许包含本机（loopback）主机: {raw!r}"
        )
    if parts.scheme != "https":
        if env != "development" or not _host_is_loopback(canonical_host):
            raise PolicyValidationError(
                f"仅开发环境的 loopback 主机可使用 http 来源: {raw!r}"
            )
    return canonical


def _clean_methods(methods: object) -> tuple[str, ...]:
    if not isinstance(methods, list) or not methods:
        raise PolicyValidationError("allow_methods 必须是非空数组")
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in methods:
        if not isinstance(item, str) or not item.strip():
            raise PolicyValidationError("allow_methods 中的方法必须是非空字符串")
        method = item.strip().upper()
        for ch in method:
            if not (ch.isalpha() or ch == "-"):
                raise PolicyValidationError(f"非法 HTTP 方法: {item!r}")
        if method not in seen:
            seen.add(method)
            cleaned.append(method)
    return tuple(cleaned)


def _clean_headers(headers: object) -> frozenset[str]:
    if not isinstance(headers, list) or not headers:
        raise PolicyValidationError("allow_headers 必须是非空数组")
    cleaned: set[str] = set()
    for item in headers:
        if not isinstance(item, str) or not item.strip():
            raise PolicyValidationError("allow_headers 中的头名必须是非空字符串")
        name = item.strip().lower()
        # token 字符粗检，杜绝空白/冒号等注入。
        if any(ch in name for ch in ' \t\r\n:,/<>?;[]{}'):
            raise PolicyValidationError(f"非法请求头名称: {item!r}")
        cleaned.add(name)
    return frozenset(cleaned)


def _clean_ports(ports: object) -> list[int]:
    if not isinstance(ports, list):
        raise PolicyValidationError("localhost_ports 必须是数组")
    result: list[int] = []
    for item in ports:
        if isinstance(item, bool) or not isinstance(item, int):
            raise PolicyValidationError("localhost_ports 必须是整数")
        if not 1 <= item <= 65535:
            raise PolicyValidationError(f"localhost 端口超出范围: {item}")
        if item not in result:
            result.append(item)
    return result


def _loopback_origins(ports: Iterable[int]) -> list[str]:
    origins = [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
    ]
    for port in ports:
        origins.extend(
            [
                f"http://localhost:{port}",
                f"http://127.0.0.1:{port}",
                f"http://[::1]:{port}",
            ]
        )
    return origins


def build_policy(
    *,
    env: str,
    origins: Iterable[str],
    allow_methods: Iterable[str] = DEFAULT_ALLOW_METHODS,
    allow_headers: Iterable[str] = DEFAULT_ALLOW_HEADERS,
    max_age: int = DEFAULT_MAX_AGE,
    allow_localhost: bool = False,
    localhost_ports: Iterable[int] = (),
    source: str = "config",
) -> CorsPolicy:
    """完整校验全部输入后，一次性构造不可变策略（任何一项非法都不生效）。"""
    if env not in ("production", "development"):
        raise PolicyValidationError(f"未知运行环境: {env!r}")
    if isinstance(max_age, bool) or not isinstance(max_age, int):
        raise PolicyValidationError("max_age 必须是非负整数")
    if max_age < 0 or max_age > 86400:
        raise PolicyValidationError("max_age 必须在 0-86400 之间")

    normalized: set[str] = set()
    for raw in origins:
        origin = normalize_origin(raw, env=env)
        if origin in normalized:
            raise PolicyValidationError(f"来源清单存在重复项（规范化后）: {raw!r}")
        normalized.add(origin)

    if allow_localhost:
        if env != "development":
            raise PolicyValidationError("allow_localhost 只能在开发环境开启")
        ports = _clean_ports(list(localhost_ports))
        for origin in _loopback_origins(ports):
            normalized.add(normalize_origin(origin, env=env))

    if env == "production" and not normalized:
        raise PolicyValidationError("生产环境必须配置至少一个可信来源")

    return CorsPolicy(
        allowed_origins=frozenset(normalized),
        allow_methods=_clean_methods(list(allow_methods)),
        allow_headers=_clean_headers(list(allow_headers)),
        max_age=max_age,
        allow_localhost=allow_localhost,
        env=env,
        source=source,
    )


def parse_policy_document(
    document: object, *, env: str, source: str, extra_origins: Iterable[str] = ()
) -> CorsPolicy:
    """解析并校验 JSON 策略文档。未知键直接报错（防止夹带/拼写错误被静默忽略）。"""
    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise PolicyValidationError("策略文件顶层必须是 JSON 对象")
    unknown = set(document) - _POLICY_FILE_KEYS
    if unknown:
        raise PolicyValidationError(
            f"策略文件包含未知字段（只列键名）: {sorted(unknown)}"
        )

    origins = document.get("allowed_origins", [])
    if not isinstance(origins, list):
        raise PolicyValidationError("allowed_origins 必须是数组")

    merged = [*extra_origins, *origins]
    return build_policy(
        env=env,
        origins=merged,
        allow_methods=document.get("allow_methods", DEFAULT_ALLOW_METHODS),
        allow_headers=document.get("allow_headers", DEFAULT_ALLOW_HEADERS),
        max_age=document.get("max_age", DEFAULT_MAX_AGE),
        allow_localhost=bool(document.get("allow_localhost", False)),
        localhost_ports=document.get("localhost_ports", []),
        source=source,
    )


# ---------------------------------------------------------------------------
# 持久化（LKG 快照与审计摘要）
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, data: bytes, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def snapshot_path(state_dir: Path) -> Path:
    return Path(state_dir) / SNAPSHOT_FILENAME


def save_snapshot(policy: CorsPolicy, state_dir: Path) -> Path:
    payload = {
        "version": 1,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "allowed_origins": sorted(policy.allowed_origins),
            "allow_methods": list(policy.allow_methods),
            "allow_headers": sorted(policy.allow_headers),
            "max_age": policy.max_age,
            "allow_localhost": policy.allow_localhost,
            "env": policy.env,
        },
    }
    target = snapshot_path(state_dir)
    _atomic_write(
        target,
        (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        mode=0o600,
    )
    return target


def load_snapshot(state_dir: Path, *, env: str) -> CorsPolicy | None:
    target = snapshot_path(state_dir)
    if not target.is_file():
        return None
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
        policy_body = document["policy"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    try:
        return build_policy(
            env=env,
            origins=policy_body.get("allowed_origins", []),
            allow_methods=policy_body.get("allow_methods", DEFAULT_ALLOW_METHODS),
            allow_headers=policy_body.get("allow_headers", DEFAULT_ALLOW_HEADERS),
            max_age=policy_body.get("max_age", DEFAULT_MAX_AGE),
            allow_localhost=bool(policy_body.get("allow_localhost", False))
            and env == "development",
            source=f"snapshot:{target}",
        )
    except PolicyValidationError:
        return None


def append_audit(state_dir: Path, event: str, **fields) -> None:
    """追加一条不含密钥的审计摘要。审计写入失败只告警，不影响服务。"""
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "pid": os.getpid(),
            "event": event,
            **fields,
        }
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
        target = state_dir / AUDIT_FILENAME
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        logger.info("cors-audit %s", line.strip())
    except OSError as exc:
        logger.warning("审计摘要写入失败（事件 %s）: %s", event, exc)


# ---------------------------------------------------------------------------
# 策略持有者与装载流程
# ---------------------------------------------------------------------------

class PolicyHolder:
    """持有当前有效策略；替换是原子的，读侧永远拿到完整对象。"""

    def __init__(self, policy: CorsPolicy | None = None) -> None:
        self._policy = policy
        self._lock = asyncio.Lock()

    def get(self) -> CorsPolicy | None:
        return self._policy

    def replace(self, policy: CorsPolicy) -> None:
        self._policy = policy


def _env_bool(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in ("1", "true", "yes", "on")


def _env_origins() -> list[str]:
    raw = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
    return [item.strip() for item in raw.split(",") if item.strip()] if raw else []


def load_policy_from_sources(
    *, env: str, policy_file: Path | None, state_dir: Path
) -> tuple[CorsPolicy, str]:
    """按 环境变量 → 策略文件 的顺序装载并完整校验。

    成功时返回 (策略, 来源描述)；失败抛出 PolicyValidationError，由调用方决定
    回退到最后一份有效策略或拒绝启动。
    """
    extra_origins = _env_origins()
    if policy_file is not None:
        try:
            document = json.loads(policy_file.read_text(encoding="utf-8"))
        except OSError as exc:
            raise PolicyValidationError(f"策略文件无法读取: {exc.strerror or exc}")
        except ValueError:
            raise PolicyValidationError("策略文件不是合法 JSON")
        policy = parse_policy_document(
            document,
            env=env,
            source=f"file:{policy_file}",
            extra_origins=extra_origins,
        )
    else:
        policy = build_policy(
            env=env,
            origins=extra_origins,
            allow_localhost=_env_bool("CORS_ALLOW_LOCALHOST"),
            localhost_ports=_env_ports(),
            source="env",
        )
    return policy, policy.source


def _env_ports() -> list[int]:
    raw = os.getenv("CORS_LOCALHOST_PORTS", "").strip()
    if not raw:
        return []
    ports: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item.isdigit():
            raise PolicyValidationError(f"CORS_LOCALHOST_PORTS 含非法端口: {item!r}")
        ports.append(int(item))
    return ports


def bootstrap_policy(
    *, env: str, policy_file: Path | None, state_dir: Path
) -> CorsPolicy:
    """启动门禁：成功返回新策略并刷新快照；失败则回退快照；再失败则拒绝启动。"""
    try:
        policy, _ = load_policy_from_sources(
            env=env, policy_file=policy_file, state_dir=state_dir
        )
    except PolicyValidationError as exc:
        snapshot = load_snapshot(state_dir, env=env)
        if snapshot is not None:
            append_audit(
                state_dir,
                "startup_fallback",
                reason=str(exc),
                **{f"active_{k}": v for k, v in _safe_summary(snapshot).items()},
            )
            return snapshot
        append_audit(state_dir, "startup_rejected", reason=str(exc))
        raise
    save_snapshot(policy, state_dir)
    append_audit(
        state_dir,
        "startup_loaded",
        **{f"active_{k}": v for k, v in _safe_summary(policy).items()},
    )
    return policy


def _safe_summary(policy: CorsPolicy) -> dict:
    summary = policy.audit_summary()
    summary.pop("source", None)
    return summary


async def watch_policy_file(
    holder: PolicyHolder,
    *,
    env: str,
    policy_file: Path,
    state_dir: Path,
    interval: float,
) -> None:
    """轮询策略文件：校验通过才原子换版；失败保留最后一份有效策略。"""
    last_mtime: float | None = None
    last_size: int | None = None
    try:
        stat = policy_file.stat()
        last_mtime, last_size = stat.st_mtime, stat.st_size
    except OSError:
        pass

    while True:
        await asyncio.sleep(max(0.2, interval))
        try:
            stat = policy_file.stat()
        except OSError as exc:
            if last_mtime is not None:
                append_audit(
                    state_dir,
                    "reload_rejected",
                    reason=f"策略文件无法读取: {exc.strerror or exc}",
                    **{f"active_{k}": v for k, v in _safe_summary(holder.get()).items()},
                )
                last_mtime = last_size = None
            continue
        if (stat.st_mtime, stat.st_size) == (last_mtime, last_size):
            continue
        try:
            policy, _ = load_policy_from_sources(
                env=env, policy_file=policy_file, state_dir=state_dir
            )
        except PolicyValidationError as exc:
            current = holder.get()
            append_audit(
                state_dir,
                "reload_rejected",
                reason=str(exc),
                **(
                    {f"active_{k}": v for k, v in _safe_summary(current).items()}
                    if current is not None
                    else {}
                ),
            )
            # 保留旧的 mtime 观察值也无妨：以内容为准，下轮再试。
            last_mtime, last_size = stat.st_mtime, stat.st_size
            continue
        try:
            # 先持久化（原子 rename），再切换内存引用：保证生效策略与快照一致。
            save_snapshot(policy, state_dir)
        except OSError as exc:
            current = holder.get()
            append_audit(
                state_dir,
                "reload_rejected",
                reason=f"快照无法写入: {exc.strerror or exc}",
                **(
                    {f"active_{k}": v for k, v in _safe_summary(current).items()}
                    if current is not None
                    else {}
                ),
            )
            last_mtime, last_size = stat.st_mtime, stat.st_size
            continue
        holder.replace(policy)
        append_audit(
            state_dir,
            "reload_loaded",
            **{f"active_{k}": v for k, v in _safe_summary(policy).items()},
        )
        last_mtime, last_size = stat.st_mtime, stat.st_size


# ---------------------------------------------------------------------------
# ASGI 中间件：预检与实际响应共用同一份策略
# ---------------------------------------------------------------------------

class CorsMiddleware:
    """凭据型 CORS 中间件。

    - 预检（OPTIONS + Access-Control-Request-Method）从不进入业务应用：
      无论路径是否存在、来源是否可信，统一返回 204，杜绝路径探测差异；
      只有来源/方法/头全部命中策略时才附带放行头。
    - 实际请求正常进入应用；仅当来源命中策略时在响应（含错误响应）上加放行头。
    """

    def __init__(self, app, holder: PolicyHolder) -> None:
        self.app = app
        self.holder = holder

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        policy = self.holder.get()
        headers = Headers(scope=scope)
        origin = headers.get("origin")
        requested_method = headers.get("access-control-request-method")

        if scope["method"] == "OPTIONS" and requested_method:
            await self._preflight(
                scope, send, policy=policy, origin=origin,
                requested_method=requested_method, headers=headers,
            )
            return

        await self._pass_through(scope, receive, send, policy=policy, origin=origin)

    async def _preflight(
        self, scope, send, *, policy, origin, requested_method, headers: Headers
    ) -> None:
        vary = b"origin, access-control-request-method, access-control-request-headers"
        cors_headers: list[tuple[bytes, bytes]] = [(b"vary", vary)]
        allowed = False
        if policy is not None and origin and policy.matches_origin(origin):
            if policy.allows_method(requested_method):
                requested_headers = headers.getlist("access-control-request-headers")
                names: list[str] = []
                ok = True
                for field_value in requested_headers:
                    for token in field_value.split(","):
                        token = token.strip()
                        if token:
                            names.append(token)
                checked = policy.check_request_headers(names)
                if checked is None:
                    ok = False
                if ok:
                    echo = ", ".join(
                        name.strip()
                        for name in names
                        if name.strip().lower()
                        not in _SAFELISTED_REQUEST_HEADERS
                    )
                    cors_headers = [
                        (b"vary", vary),
                        (b"access-control-allow-origin", origin.encode("latin-1")),
                        (b"access-control-allow-credentials", b"true"),
                        (
                            b"access-control-allow-methods",
                            ", ".join(policy.allow_methods).encode("latin-1"),
                        ),
                        (
                            b"access-control-allow-headers",
                            (echo or ", ".join(sorted(policy.allow_headers))).encode(
                                "latin-1"
                            ),
                        ),
                        (
                            b"access-control-max-age",
                            str(policy.max_age).encode("latin-1"),
                        ),
                    ]
                    allowed = True

        # 无论是否放行，预检一律 204、同一套基础头，不调用业务应用。
        await self._send_simple(send, 204, cors_headers)
        logger.debug(
            "preflight origin=%r method=%r allowed=%s path=%s",
            origin, requested_method, allowed, scope.get("path"),
        )

    async def _pass_through(self, scope, receive, send, *, policy, origin) -> None:
        trusted = bool(
            policy is not None and origin and policy.matches_origin(origin)
        )
        extra: list[tuple[bytes, bytes]] = []
        if trusted:
            extra = [
                (b"access-control-allow-origin", origin.encode("latin-1")),
                (b"access-control-allow-credentials", b"true"),
            ]

        async def sender(message):
            if message["type"] == "http.response.start":
                raw = list(message.get("headers", []))
                raw = _merge_vary(raw)
                raw.extend(extra)
                message = dict(message)
                message["headers"] = raw
            await send(message)

        await self.app(scope, receive, sender)

    @staticmethod
    async def _send_simple(send, status: int, headers: list[tuple[bytes, bytes]]) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": b""})


def _merge_vary(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """保证任何响应都带 Vary: Origin，并与已有的 Vary 合并。"""
    existing_vary: list[str] = []
    kept: list[tuple[bytes, bytes]] = []
    for name, value in headers:
        if name == b"vary":
            existing_vary.append(value.decode("latin-1"))
        else:
            kept.append((name, value))
    tokens = ["origin"]
    for value in existing_vary:
        for token in value.split(","):
            token = token.strip()
            if token and token.lower() not in {t.lower() for t in tokens}:
                tokens.append(token)
    kept.append((b"vary", ", ".join(tokens).encode("latin-1")))
    return kept
