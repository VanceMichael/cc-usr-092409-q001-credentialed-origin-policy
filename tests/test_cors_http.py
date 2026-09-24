"""HTTP 回归测试：用真实 uvicorn 子进程验证跨域策略端到端行为。

覆盖：允许来源、拒绝来源、无 Origin 的服务调用、SQLite 业务接口、
预检（方法/请求头/Max-Age/Vary）、错误响应无差异、热换版回退、
重启后快照回退一致、多 worker 启动回退、生产坏配置启动门禁。
"""

import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOOD_ORIGIN = "https://ops.example.com"
OTHER_ORIGIN = "https://console.example.com"
EVIL_ORIGIN = "https://evil.example"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def atomic_write_json(path: Path, document) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def raw_request(port, method, path, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    result = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, data)
    conn.close()
    return result


class Server:
    def __init__(self, base_dir: Path, policy_file, *, env="production",
                 workers=1, reload_interval="0.3"):
        self.base_dir = base_dir
        self.state_dir = base_dir / "cors-state"
        self.port = free_port()
        self.log_path = base_dir / "server.log"
        self.proc = None

        env_vars = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(ROOT),
            "APP_ENV": env,
            "DATABASE_URL": f"sqlite:///{base_dir / 'business.sqlite3'}",
            "CORS_STATE_DIR": str(self.state_dir),
            "CORS_RELOAD_INTERVAL": reload_interval,
            "LOG_LEVEL": "INFO",
        }
        if policy_file is not None:
            env_vars["CORS_POLICY_FILE"] = str(policy_file)

        cmd = [
            sys.executable, "-m", "uvicorn", "app.main:app",
            "--host", "127.0.0.1", "--port", str(self.port),
        ]
        if workers > 1:
            cmd += ["--workers", str(workers)]
        self.cmd = cmd
        self.env_vars = env_vars

    def start(self, timeout=20):
        self.log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            self.cmd,
            env=self.env_vars,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.log.close()
                raise AssertionError(
                    f"server exited early ({self.proc.returncode}); log:\n"
                    + self.log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                )
            try:
                status, _, _ = raw_request(self.port, "GET", "/health")
                if status == 200:
                    return self
            except OSError:
                time.sleep(0.15)
        self.stop()
        raise AssertionError("server did not become ready")

    def stop(self):
        if self.proc is None:
            return
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait(timeout=5)
        if not self.log.closed:
            self.log.close()

    def request(self, *args, **kwargs):
        return raw_request(self.port, *args, **kwargs)

    def audit_entries(self):
        log = self.state_dir / "cors-audit.log"
        if not log.is_file():
            return []
        return [
            json.loads(line)
            for line in log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def wait_for_event(self, event, timeout=8, *, since=0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            entries = self.audit_entries()
            matches = [e for e in entries[since:] if e.get("event") == event]
            if matches:
                return entries
            time.sleep(0.2)
        raise AssertionError(f"audit event {event!r} 未出现: {self.audit_entries()}")

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def good_policy(**overrides):
    doc = {
        "allowed_origins": [GOOD_ORIGIN],
        "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type", "Accept"],
        "max_age": 300,
    }
    doc.update(overrides)
    return doc


class CorsHttpTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="cors-http-")
        self.dir = Path(self._tmp.name)
        self.policy_file = self.dir / "cors.json"
        atomic_write_json(self.policy_file, good_policy())

    def tearDown(self):
        self._tmp.cleanup()

    # -- 基础放行/拒绝 -----------------------------------------------------

    def test_trusted_origin_actual_request_allowed(self):
        with Server(self.dir, self.policy_file) as server:
            status, headers, _ = server.request(
                "GET", "/api/ponds/", {"Origin": GOOD_ORIGIN}
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers.get("access-control-allow-origin"), GOOD_ORIGIN)
            self.assertEqual(headers.get("access-control-allow-credentials"), "true")
            self.assertIn("origin", headers.get("vary", "").lower())
            # 凭据模式禁止回显通配符
            self.assertNotEqual(headers.get("access-control-allow-origin"), "*")

    def test_untrusted_origin_gets_no_cors_headers(self):
        with Server(self.dir, self.policy_file) as server:
            status, headers, body = server.request(
                "GET", "/api/ponds/", {"Origin": EVIL_ORIGIN}
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, b"[]")
            self.assertNotIn("access-control-allow-origin", headers)
            self.assertNotIn("access-control-allow-credentials", headers)
            self.assertIn("origin", headers.get("vary", "").lower())

    def test_no_origin_server_to_server_call(self):
        with Server(self.dir, self.policy_file) as server:
            status, headers, body = server.request("GET", "/health")
            self.assertEqual(status, 200)
            self.assertIn(b"healthy", body)
            self.assertNotIn("access-control-allow-origin", headers)
            self.assertNotIn("access-control-allow-credentials", headers)

    def test_confusable_origins_never_match(self):
        with Server(self.dir, self.policy_file) as server:
            for origin in (
                "https://ops.example.com.evil.example",
                "https://ops.example.com:443",
                "https://OPS.EXAMPLE.COM:443",
                "https://ops.example.com/",
                "null",
                "https://ops.example.com@evil.example",
            ):
                with self.subTest(origin=origin):
                    _, headers, _ = server.request(
                        "OPTIONS", "/api/ponds/",
                        {
                            "Origin": origin,
                            "Access-Control-Request-Method": "POST",
                        },
                    )
                    self.assertNotIn("access-control-allow-origin", headers, origin)

    # -- 预检 --------------------------------------------------------------

    def test_preflight_allowed_full_headers(self):
        with Server(self.dir, self.policy_file) as server:
            status, headers, body = server.request(
                "OPTIONS", "/api/ponds/",
                {
                    "Origin": GOOD_ORIGIN,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "authorization, content-type",
                },
            )
            self.assertEqual(status, 204)
            self.assertEqual(body, b"")
            self.assertEqual(headers.get("access-control-allow-origin"), GOOD_ORIGIN)
            self.assertEqual(headers.get("access-control-allow-credentials"), "true")
            self.assertIn("POST", headers.get("access-control-allow-methods", ""))
            allowed_headers = headers.get("access-control-allow-headers", "").lower()
            self.assertIn("authorization", allowed_headers)
            self.assertIn("content-type", allowed_headers)
            self.assertEqual(headers.get("access-control-max-age"), "300")
            self.assertIn("origin", headers.get("vary", "").lower())

    def test_preflight_cache_is_stable_across_requests(self):
        with Server(self.dir, self.policy_file) as server:
            seen = []
            for _ in range(2):
                _, headers, body = server.request(
                    "OPTIONS", "/api/ponds/",
                    {
                        "Origin": GOOD_ORIGIN,
                        "Access-Control-Request-Method": "GET",
                    },
                )
                seen.append((
                    body,
                    headers.get("access-control-max-age"),
                    headers.get("access-control-allow-origin"),
                    headers.get("access-control-allow-methods"),
                ))
            self.assertEqual(seen[0], seen[1])
            self.assertEqual(seen[0][1], "300")

    def test_preflight_untrusted_or_bad_method_header_uniform(self):
        with Server(self.dir, self.policy_file) as server:
            def preflight(path, origin, method="POST", req_headers=None):
                hdrs = {"Origin": origin, "Access-Control-Request-Method": method}
                if req_headers:
                    hdrs["Access-Control-Request-Headers"] = req_headers
                return server.request("OPTIONS", path, hdrs)

            cases = {
                "untrusted-existing-path": preflight(
                    "/api/ponds/", EVIL_ORIGIN
                ),
                "untrusted-missing-path": preflight(
                    "/api/does-not-exist/", EVIL_ORIGIN
                ),
                "bad-method": preflight(
                    "/api/ponds/", GOOD_ORIGIN, method="PROPFIND"
                ),
                "bad-header": preflight(
                    "/api/ponds/", GOOD_ORIGIN, req_headers="x-evil-header"
                ),
            }
            baselines = []
            for name, (status, headers, body) in cases.items():
                self.assertEqual(status, 204, name)
                self.assertEqual(body, b"", name)
                self.assertNotIn("access-control-allow-origin", headers, name)
                self.assertNotIn("access-control-allow-methods", headers, name)
                self.assertNotIn("access-control-allow-headers", headers, name)
                self.assertNotIn("access-control-allow-credentials", headers, name)
                baselines.append((status, body))
            # 任意路径、任意拒绝原因：预检响应无差异，无法据此探测受保护资源
            self.assertEqual(len(set(baselines)), 1)

    def test_actual_request_error_responses_have_no_oracle(self):
        with Server(self.dir, self.policy_file) as server:
            trusted = server.request(
                "GET", "/api/ponds/999999/", {"Origin": GOOD_ORIGIN}
            )
            untrusted = server.request(
                "GET", "/api/ponds/999999/", {"Origin": EVIL_ORIGIN}
            )
            no_origin = server.request("GET", "/api/ponds/999999/")
            # 状态码与响应体完全一致，差异仅限 CORS 放行头
            self.assertEqual(trusted[0], untrusted[0], 404)
            self.assertEqual(untrusted[0], no_origin[0])
            self.assertEqual(untrusted[2], no_origin[2])
            self.assertNotIn("access-control-allow-origin", untrusted[1])
            self.assertEqual(
                trusted[1].get("access-control-allow-origin"), GOOD_ORIGIN
            )

    # -- SQLite 业务接口 ---------------------------------------------------

    def test_sqlite_business_api_still_works(self):
        with Server(self.dir, self.policy_file) as server:
            payload = json.dumps(
                {"name": "一号塘", "area": 12.5, "water_depth": 1.8,
                 "species": "草鱼"}
            )
            status, headers, body = server.request(
                "POST", "/api/ponds/",
                {"Content-Type": "application/json", "Origin": GOOD_ORIGIN},
                body=payload.encode("utf-8"),
            )
            self.assertEqual(status, 200, body)
            pond_id = json.loads(body)["id"]

            status, _, body = server.request(
                "GET", f"/api/ponds/{pond_id}/", {"Origin": GOOD_ORIGIN}
            )
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["name"], "一号塘")

            status, _, body = server.request("GET", "/api/ponds/")
            self.assertEqual(status, 200)
            self.assertEqual(len(json.loads(body)), 1)

            status, _, _ = server.request(
                "DELETE", f"/api/ponds/{pond_id}/", {"Origin": GOOD_ORIGIN}
            )
            self.assertEqual(status, 200)
            self.assertTrue((self.dir / "business.sqlite3").is_file())

    # -- 热换版：失败保留最后一份有效策略 ----------------------------------

    def test_reload_invalid_config_keeps_last_good_then_applies_valid(self):
        with Server(self.dir, self.policy_file) as server:
            # 1) 换成非法 JSON：旧策略继续生效
            self.policy_file.write_text("{ not json", encoding="utf-8")
            entries = server.wait_for_event("reload_rejected")
            self.assertTrue(
                any(e.get("active_fingerprint") for e in entries
                    if e["event"] == "reload_rejected")
            )
            events_seen = len(entries)
            status, headers, _ = server.request(
                "GET", "/api/ponds/", {"Origin": GOOD_ORIGIN}
            )
            self.assertEqual(status, 200)
            self.assertEqual(
                headers.get("access-control-allow-origin"), GOOD_ORIGIN
            )

            # 2) 换成内容非法（生产环境混入 http 本机来源）：仍旧策略
            atomic_write_json(self.policy_file, good_policy(
                allowed_origins=[GOOD_ORIGIN, "http://127.0.0.1:5173"]
            ))
            server.wait_for_event(
                "reload_rejected", timeout=6, since=events_seen
            )
            _, headers, _ = server.request(
                "GET", "/api/ponds/", {"Origin": OTHER_ORIGIN}
            )
            self.assertNotIn("access-control-allow-origin", headers)

            # 3) 换成合法新策略（新增来源、调整 max-age）：原子生效
            atomic_write_json(self.policy_file, good_policy(
                allowed_origins=[GOOD_ORIGIN, OTHER_ORIGIN], max_age=120
            ))
            server.wait_for_event("reload_loaded")
            _, headers, _ = server.request(
                "GET", "/api/ponds/", {"Origin": OTHER_ORIGIN}
            )
            self.assertEqual(
                headers.get("access-control-allow-origin"), OTHER_ORIGIN
            )
            _, headers, _ = server.request(
                "OPTIONS", "/api/ponds/",
                {"Origin": OTHER_ORIGIN, "Access-Control-Request-Method": "GET"},
            )
            self.assertEqual(headers.get("access-control-max-age"), "120")

            # 审计摘要不得包含任何密钥类字段
            raw_audit = (self.dir / "cors-state" / "cors-audit.log").read_text()
            self.assertNotIn("cookie", raw_audit.lower())

    # -- 重启后快照回退，结果与重启前一致 ----------------------------------

    def test_restart_with_bad_config_falls_back_consistently(self):
        def collect(server):
            results = {}
            results["good_actual"] = server.request(
                "GET", "/api/ponds/", {"Origin": GOOD_ORIGIN}
            )[:2]
            results["evil_actual"] = server.request(
                "GET", "/api/ponds/", {"Origin": EVIL_ORIGIN}
            )[:2]
            results["no_origin"] = server.request("GET", "/health")[:2]
            results["good_preflight"] = server.request(
                "OPTIONS", "/api/ponds/",
                {"Origin": GOOD_ORIGIN,
                 "Access-Control-Request-Method": "POST"},
            )[:2]
            results["evil_preflight"] = server.request(
                "OPTIONS", "/api/ponds/",
                {"Origin": EVIL_ORIGIN,
                 "Access-Control-Request-Method": "POST"},
            )[:2]
            return results

        def comparable(snapshot):
            return [
                (
                    status,
                    {k: v for k, v in headers.items()
                     if k not in ("date", "server")},
                )
                for status, headers in snapshot.values()
            ]

        with Server(self.dir, self.policy_file) as server:
            before = collect(server)

        # 配置换版为非法内容后重启：必须回退快照并与重启前完全一致
        self.policy_file.write_text("{ broken", encoding="utf-8")
        with Server(self.dir, self.policy_file) as server:
            after = collect(server)
            entries = server.audit_entries()
            self.assertTrue(
                any(e["event"] == "startup_fallback" for e in entries)
            )
        self.assertEqual(comparable(before), comparable(after))

    # -- 多进程启动：两个 worker 都回退最后一份有效策略 --------------------

    def test_multiple_workers_startup_fallback(self):
        from app.cors_policy import build_policy, save_snapshot

        state_dir = self.dir / "cors-state"
        # 预置最后一份有效策略快照
        save_snapshot(
            build_policy(env="production", origins=[GOOD_ORIGIN]), state_dir
        )
        # 当前配置非法：两个 worker 都必须回退，而不是各自失败/裸奔
        self.policy_file.write_text("{ broken", encoding="utf-8")

        with Server(self.dir, self.policy_file, workers=2) as server:
            deadline = time.time() + 15
            pids = set()
            while time.time() < deadline:
                fallbacks = [
                    e for e in server.audit_entries()
                    if e["event"] == "startup_fallback"
                ]
                pids = {e["pid"] for e in fallbacks}
                if len(pids) >= 2:
                    break
                time.sleep(0.3)
            self.assertGreaterEqual(
                len(pids), 2, f"两个 worker 都应回退: {server.audit_entries()}"
            )

            # 多次请求（可能命中不同 worker）结果一致
            for _ in range(6):
                status, headers, _ = server.request(
                    "GET", "/api/ponds/", {"Origin": GOOD_ORIGIN}
                )
                self.assertEqual(status, 200)
                self.assertEqual(
                    headers.get("access-control-allow-origin"), GOOD_ORIGIN
                )
                status, headers, _ = server.request(
                    "GET", "/api/ponds/", {"Origin": EVIL_ORIGIN}
                )
                self.assertNotIn("access-control-allow-origin", headers)

    # -- 生产环境无有效配置且无快照：启动门禁失败 --------------------------

    def test_production_invalid_config_without_snapshot_rejects_boot(self):
        bad_dir = self.dir / "fresh"
        bad_dir.mkdir()
        bad_file = bad_dir / "cors.json"
        bad_file.write_text(
            json.dumps({"allowed_origins": ["http://127.0.0.1:5173"]}),
            encoding="utf-8",
        )
        server = Server(bad_dir, bad_file)
        with self.assertRaises(AssertionError):
            server.start(timeout=8)
        log = server.log_path.read_text(encoding="utf-8", errors="replace")
        self.assertIn("CORS", log)
        audit = bad_dir / "cors-state" / "cors-audit.log"
        self.assertTrue(audit.is_file())
        self.assertIn("startup_rejected", audit.read_text(encoding="utf-8"))

    # -- 开发环境：本机来源显式开启 ----------------------------------------

    def test_development_localhost_origins_opt_in(self):
        atomic_write_json(self.policy_file, good_policy(
            allowed_origins=[],
            allow_localhost=True,
            localhost_ports=[5173],
        ))
        with Server(self.dir, self.policy_file, env="development") as server:
            for origin in (
                "http://localhost:5173",
                "http://127.0.0.1:5173",
                "http://[::1]:5173",
            ):
                with self.subTest(origin=origin):
                    _, headers, _ = server.request(
                        "GET", "/api/ponds/", {"Origin": origin}
                    )
                    self.assertEqual(
                        headers.get("access-control-allow-origin"), origin
                    )
            # 未列入端口的本机来源不放行
            _, headers, _ = server.request(
                "GET", "/api/ponds/", {"Origin": "http://localhost:3000"}
            )
            self.assertNotIn("access-control-allow-origin", headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
