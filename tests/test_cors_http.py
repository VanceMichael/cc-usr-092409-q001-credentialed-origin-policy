"""跨域信任边界 HTTP 回归测试。

覆盖：允许来源、拒绝来源、无 Origin 的服务调用、预检缓存、配置回退、
重启/多进程一致性，以及 SQLite 业务接口在修复后仍然可用。
"""
import json
import os
import tempfile
import unittest

# 必须在导入 app 之前固定数据库与快照位置（database.py/main.py 在导入时读取环境）
_TEST_TMP = tempfile.mkdtemp(prefix="cors_http_test_")
os.environ["DATABASE_URL"] = "sqlite:///{}/test.sqlite3".format(_TEST_TMP)
os.environ["CORS_POLICY_STATE_FILE"] = os.path.join(_TEST_TMP, "module_app_state.json")

from fastapi.testclient import TestClient

from app.cors_policy import StartupGateError
from app.main import create_app

ALLOWED_ORIGIN = "https://console.example.com"
ALLOWED_ORIGIN_WITH_PORT = "https://admin.example.com:8443"
EVIL_ORIGIN = "https://evil.example.com"
DECOY_SECRET = "s3cr3t-decoy-token"  # 用于证明审计摘要不泄露环境密钥


def make_env(state_file, **overrides):
    env = {
        "APP_ENV": "production",
        "CORS_ALLOWED_ORIGINS": "{},{}".format(ALLOWED_ORIGIN, ALLOWED_ORIGIN_WITH_PORT),
        "CORS_ALLOW_CREDENTIALS": "true",
        "CORS_ALLOW_METHODS": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
        "CORS_ALLOW_HEADERS": "Authorization,Content-Type",
        "CORS_MAX_AGE": "600",
        "CORS_POLICY_STATE_FILE": state_file,
    }
    env.update(overrides)
    return env


def preflight(client, origin, method="POST", headers="Authorization,Content-Type", path="/api/ponds/"):
    request_headers = {"Access-Control-Request-Method": method}
    if origin is not None:
        request_headers["Origin"] = origin
    if headers is not None:
        request_headers["Access-Control-Request-Headers"] = headers
    return client.options(path, headers=request_headers)


def assert_no_cors_headers(testcase, response):
    for name in response.headers:
        testcase.assertFalse(
            name.lower().startswith("access-control-"),
            "不应出现放行头 {}: {}".format(name, response.headers[name]),
        )


class CorsHttpTestBase(unittest.TestCase):
    """每个用例类共享一份带独立快照文件的有效配置。"""

    @classmethod
    def setUpClass(cls):
        cls.state_file = os.path.join(_TEST_TMP, cls.__name__ + "_state.json")
        cls.env = make_env(cls.state_file)
        cls.app = create_app(cls.env)
        cls.client = TestClient(cls.app)


class AllowedOriginTest(CorsHttpTestBase):
    def test_preflight_allowed_origin(self):
        resp = preflight(self.client, ALLOWED_ORIGIN)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["access-control-allow-origin"], ALLOWED_ORIGIN)
        self.assertEqual(resp.headers["access-control-allow-credentials"], "true")
        methods = {m.strip() for m in resp.headers["access-control-allow-methods"].split(",")}
        self.assertIn("POST", methods)
        self.assertIn("GET", methods)
        allow_headers = {
            h.strip().lower()
            for h in resp.headers["access-control-allow-headers"].split(",")
        }
        self.assertIn("authorization", allow_headers)
        self.assertIn("content-type", allow_headers)

    def test_preflight_allowed_origin_with_explicit_port(self):
        resp = preflight(self.client, ALLOWED_ORIGIN_WITH_PORT)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.headers["access-control-allow-origin"], ALLOWED_ORIGIN_WITH_PORT
        )

    def test_preflight_never_echoes_wildcard_with_credentials(self):
        resp = preflight(self.client, ALLOWED_ORIGIN)
        self.assertNotEqual(resp.headers.get("access-control-allow-origin"), "*")

    def test_actual_request_allowed_origin(self):
        resp = self.client.get("/api/ponds/", headers={"Origin": ALLOWED_ORIGIN})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["access-control-allow-origin"], ALLOWED_ORIGIN)
        self.assertEqual(resp.headers["access-control-allow-credentials"], "true")
        self.assertIn("origin", resp.headers["vary"].lower())

    def test_default_port_spelling_matches(self):
        resp = self.client.get(
            "/api/ponds/", headers={"Origin": "https://console.example.com:443"}
        )
        self.assertEqual(
            resp.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN
        )


class DeniedOriginTest(CorsHttpTestBase):
    def test_preflight_denied_origin(self):
        resp = preflight(self.client, EVIL_ORIGIN)
        self.assertEqual(resp.status_code, 403)
        assert_no_cors_headers(self, resp)

    def test_preflight_denied_wrong_port(self):
        # 同主机不同端口是不同来源
        resp = preflight(self.client, "https://admin.example.com")
        self.assertEqual(resp.status_code, 403)
        assert_no_cors_headers(self, resp)

    def test_preflight_denied_http_downgrade(self):
        resp = preflight(self.client, "http://console.example.com")
        self.assertEqual(resp.status_code, 403)
        assert_no_cors_headers(self, resp)

    def test_null_and_confusing_origins_denied(self):
        for origin in (
            "null",
            "https://user@console.example.com",
            "https://console.example.com.",
            "http://2130706433",
            "http://0x7f000001",
            "https://console.example.com@evil.example.com",
        ):
            with self.subTest(origin=origin):
                resp = preflight(self.client, origin)
                self.assertEqual(resp.status_code, 403)
                assert_no_cors_headers(self, resp)
                resp_actual = self.client.get("/api/ponds/", headers={"Origin": origin})
                assert_no_cors_headers(self, resp_actual)

    def test_preflight_denied_method_not_in_policy(self):
        resp = preflight(self.client, ALLOWED_ORIGIN, method="TRACE")
        self.assertEqual(resp.status_code, 403)
        assert_no_cors_headers(self, resp)

    def test_preflight_denied_header_not_in_policy(self):
        resp = preflight(self.client, ALLOWED_ORIGIN, headers="X-Evil-Header")
        self.assertEqual(resp.status_code, 403)
        assert_no_cors_headers(self, resp)

    def test_denied_preflight_is_uniform_across_paths(self):
        """拒绝响应不随路径是否存在而变化，避免借错误差异探测资源。"""
        existing = preflight(self.client, EVIL_ORIGIN, path="/api/ponds/")
        missing = preflight(self.client, EVIL_ORIGIN, path="/api/nonexistent-secret/")
        self.assertEqual(existing.status_code, missing.status_code)
        self.assertEqual(existing.text, missing.text)
        vary = lambda r: sorted(
            v.strip().lower() for v in r.headers.get("vary", "").split(",")
        )
        self.assertEqual(vary(existing), vary(missing))

    def test_actual_request_denied_origin_behaves_like_no_origin(self):
        """实际请求：未获信任来源与无 Origin 得到一致的业务响应，只是没有放行头。"""
        denied = self.client.get("/api/ponds/", headers={"Origin": EVIL_ORIGIN})
        anonymous = self.client.get("/api/ponds/")
        self.assertEqual(denied.status_code, anonymous.status_code)
        self.assertEqual(denied.json(), anonymous.json())
        assert_no_cors_headers(self, denied)

    def test_actual_request_denied_origin_404_identical(self):
        denied = self.client.get(
            "/api/ponds/999999/", headers={"Origin": EVIL_ORIGIN}
        )
        anonymous = self.client.get("/api/ponds/999999/")
        self.assertEqual(denied.status_code, anonymous.status_code)
        self.assertEqual(denied.json(), anonymous.json())
        assert_no_cors_headers(self, denied)


class NoOriginAndVaryTest(CorsHttpTestBase):
    def test_service_call_without_origin(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        assert_no_cors_headers(self, resp)
        # 响应依赖 Origin 是否存在，必须声明 Vary 防缓存串味
        self.assertIn("origin", resp.headers["vary"].lower())

    def test_preflight_cache_contract(self):
        resp = preflight(self.client, ALLOWED_ORIGIN)
        self.assertEqual(resp.headers["access-control-max-age"], "600")
        vary = {v.strip().lower() for v in resp.headers["vary"].split(",")}
        self.assertIn("origin", vary)
        self.assertIn("access-control-request-method", vary)
        self.assertIn("access-control-request-headers", vary)

    def test_preflight_result_differs_by_origin(self):
        allowed = preflight(self.client, ALLOWED_ORIGIN)
        denied = preflight(self.client, EVIL_ORIGIN)
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(denied.status_code, 403)
        # Vary: Origin 已声明，缓存不会把放行结果错发给其他来源
        self.assertIn("origin", allowed.headers["vary"].lower())


class BusinessApiTest(CorsHttpTestBase):
    def test_sqlite_business_api_still_works(self):
        payload = {"name": "跨域回归塘口", "area": 12.5, "water_depth": 1.8, "species": "草鱼"}
        created = self.client.post(
            "/api/ponds/", json=payload, headers={"Origin": ALLOWED_ORIGIN}
        )
        self.assertEqual(created.status_code, 200, created.text)
        pond_id = created.json()["id"]
        fetched = self.client.get("/api/ponds/{}/".format(pond_id))
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["name"], payload["name"])

    def test_business_data_survives_restart(self):
        payload = {"name": "重启一致性塘口", "area": 8.0, "water_depth": 2.0}
        before = create_app(self.env)
        created = TestClient(before).post("/api/ponds/", json=payload)
        self.assertEqual(created.status_code, 200, created.text)
        # 模拟重启：同一 SQLite 文件，新应用实例
        after = create_app(self.env)
        names = [p["name"] for p in TestClient(after).get("/api/ponds/").json()]
        self.assertIn(payload["name"], names)


class ReloadFallbackTest(unittest.TestCase):
    def test_reload_failure_keeps_last_valid_policy(self):
        state_file = os.path.join(_TEST_TMP, "reload_state.json")
        env = make_env(state_file)
        app = create_app(env)
        client = TestClient(app)
        self.assertEqual(preflight(client, ALLOWED_ORIGIN).status_code, 200)

        store = app.state.cors_policy_store
        bad_env = make_env(
            state_file,
            CORS_ALLOWED_ORIGINS="http://insecure.example.com",  # 生产环境不允许 HTTP
            API_SECRET_KEY=DECOY_SECRET,
        )
        with self.assertLogs("app.cors", level="INFO") as captured:
            result = store.reload_from_environment(bad_env)
        self.assertFalse(result.applied)
        self.assertIn("HTTPS", result.reason)

        # 审计摘要：有结果与策略哈希，没有密钥
        audit = "\n".join(captured.output)
        records = [json.loads(line.split(":", 2)[2]) for line in captured.output]
        rejected = [r for r in records if r["result"] == "reload_rejected"]
        self.assertTrue(rejected)
        self.assertEqual(rejected[0]["policy_hash"], store.current.digest)
        self.assertNotIn(DECOY_SECRET, audit)

        # 行为不变：允许来源仍放行，恶意来源仍拒绝
        self.assertEqual(preflight(client, ALLOWED_ORIGIN).status_code, 200)
        self.assertEqual(preflight(client, EVIL_ORIGIN).status_code, 403)

    def test_reload_success_applies_atomically(self):
        state_file = os.path.join(_TEST_TMP, "reload_ok_state.json")
        env = make_env(state_file)
        app = create_app(env)
        client = TestClient(app)
        store = app.state.cors_policy_store
        new_env = make_env(
            state_file, CORS_ALLOWED_ORIGINS="https://new-console.example.com"
        )
        with self.assertLogs("app.cors", level="INFO"):
            result = store.reload_from_environment(new_env)
        self.assertTrue(result.applied)
        # 换版立即生效：旧来源被拒，新来源放行
        self.assertEqual(preflight(client, ALLOWED_ORIGIN).status_code, 403)
        resp = preflight(client, "https://new-console.example.com")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.headers["access-control-allow-origin"],
            "https://new-console.example.com",
        )


class RestartAndGateTest(unittest.TestCase):
    def test_restart_with_broken_env_falls_back_to_last_valid_snapshot(self):
        state_file = os.path.join(_TEST_TMP, "restart_state.json")
        good_env = make_env(state_file)
        before = TestClient(create_app(good_env))
        self.assertEqual(preflight(before, ALLOWED_ORIGIN).status_code, 200)
        self.assertTrue(os.path.isfile(state_file), "有效策略应已写入快照")

        # 重启时环境被改成非法配置：回退到最后一份有效策略
        broken_env = make_env(
            state_file, CORS_ALLOWED_ORIGINS="*,https://console.example.com"
        )
        with self.assertLogs("app.cors", level="INFO") as captured:
            after = TestClient(create_app(broken_env))
        audit = "\n".join(captured.output)
        self.assertIn("fallback_to_snapshot", audit)

        # 重启前后结果一致
        self.assertEqual(preflight(after, ALLOWED_ORIGIN).status_code, 200)
        self.assertEqual(preflight(after, EVIL_ORIGIN).status_code, 403)
        resp = after.get("/api/ponds/", headers={"Origin": ALLOWED_ORIGIN})
        self.assertEqual(
            resp.headers.get("access-control-allow-origin"), ALLOWED_ORIGIN
        )

    def test_startup_gate_rejects_when_no_valid_policy_exists(self):
        missing_state = os.path.join(_TEST_TMP, "never_existed_state.json")
        bad_env = make_env(
            missing_state, CORS_ALLOWED_ORIGINS="http://insecure.example.com"
        )
        with self.assertRaises(StartupGateError):
            create_app(bad_env)

    def test_startup_gate_rejects_wildcard_with_credentials(self):
        missing_state = os.path.join(_TEST_TMP, "never_existed_state2.json")
        bad_env = make_env(missing_state, CORS_ALLOWED_ORIGINS="*")
        with self.assertRaises(StartupGateError):
            create_app(bad_env)

    def test_multi_process_instances_are_consistent(self):
        # 多进程启动：每个进程独立校验同一份环境，行为一致
        state_a = os.path.join(_TEST_TMP, "worker_a_state.json")
        state_b = os.path.join(_TEST_TMP, "worker_b_state.json")
        worker_a = TestClient(create_app(make_env(state_a)))
        worker_b = TestClient(create_app(make_env(state_b)))
        for origin, expected in ((ALLOWED_ORIGIN, 200), (EVIL_ORIGIN, 403)):
            self.assertEqual(preflight(worker_a, origin).status_code, expected)
            self.assertEqual(preflight(worker_b, origin).status_code, expected)


class DevLocalhostTest(unittest.TestCase):
    def test_dev_localhost_requires_explicit_opt_in(self):
        state_file = os.path.join(_TEST_TMP, "dev_gate_state.json")
        env = make_env(
            state_file,
            APP_ENV="development",
            CORS_ALLOWED_ORIGINS="http://localhost:3000",
        )
        with self.assertRaises(StartupGateError):
            create_app(env)

    def test_dev_localhost_works_when_enabled(self):
        state_file = os.path.join(_TEST_TMP, "dev_ok_state.json")
        env = make_env(
            state_file,
            APP_ENV="development",
            CORS_ALLOWED_ORIGINS="http://localhost:3000",
            CORS_ALLOW_LOCALHOST="true",
        )
        client = TestClient(create_app(env))
        resp = preflight(client, "http://localhost:3000")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.headers["access-control-allow-origin"], "http://localhost:3000"
        )
        # 非本机的 HTTP 来源仍然不行
        self.assertEqual(preflight(client, "http://intranet.example.com").status_code, 403)


if __name__ == "__main__":
    unittest.main()
