import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.cors_policy import (
    CorsPolicy,
    PolicyValidationError,
    bootstrap_policy,
    build_policy,
    load_snapshot,
    normalize_origin,
    parse_policy_document,
    save_snapshot,
)

PROD = "production"
DEV = "development"


class NormalizeOriginTest(unittest.TestCase):
    def assertRejected(self, raw, env=PROD):
        with self.assertRaises(PolicyValidationError):
            normalize_origin(raw, env=env)

    def test_production_accepts_canonical_https(self):
        self.assertEqual(
            normalize_origin("https://ops.example.com"), "https://ops.example.com"
        )
        # 大写协议/主机名规范化为小写
        self.assertEqual(
            normalize_origin("HTTPS://Ops.Example.COM"), "https://ops.example.com"
        )
        # 显式非默认端口保留
        self.assertEqual(
            normalize_origin("https://ops.example.com:8443"),
            "https://ops.example.com:8443",
        )
        # IDNA 域名规范化为 punycode
        self.assertEqual(normalize_origin("https://例え.jp"), "https://xn--r8jz45g.jp")

    def test_wildcard_null_userinfo_rejected(self):
        self.assertRejected("*")
        self.assertRejected("null")
        self.assertRejected("NULL")
        self.assertRejected("https://user:pass@ops.example.com")
        self.assertRejected("https://good.com@evil.com")
        self.assertRejected("https://ops.example.com@evil.com")

    def test_noncanonical_hosts_rejected(self):
        self.assertRejected("https://ops.example.com.")     # 尾随点
        self.assertRejected("https://127.1")                # 非点分四段
        self.assertRejected("https://0177.0.0.1")           # 前导零
        self.assertRejected("https://0x7f.0.0.1")           # 十六进制
        self.assertRejected("https://2130706433")           # 整数形式
        self.assertRejected("https://[0:0:0:0:0:0:0:1]")    # 非压缩 IPv6
        self.assertRejected("https://ops..example.com")     # 空标签
        self.assertRejected("https://-bad.example.com")     # 连字符开头
        self.assertRejected("https://bad-.example.com")
        self.assertRejected("https://256.256.256.256")

    def test_ports_strict(self):
        self.assertRejected("https://ops.example.com:443")    # 默认端口必须省略
        self.assertRejected("http://ops.example.com:80")
        self.assertRejected("https://ops.example.com:0443")   # 前导零
        self.assertRejected("https://ops.example.com:https")  # 命名端口
        self.assertRejected("https://ops.example.com:65536")
        self.assertRejected("https://ops.example.com:0")

    def test_path_query_fragment_rejected(self):
        self.assertRejected("https://ops.example.com/")
        self.assertRejected("https://ops.example.com/ui")
        self.assertRejected("https://ops.example.com?q=1")
        self.assertRejected("https://ops.example.com#frag")

    def test_scheme_and_environment(self):
        # 生产环境不允许 http，也不允许任何 loopback 主机（即使是 https）
        self.assertRejected("http://ops.example.com")
        self.assertRejected("https://localhost")
        self.assertRejected("https://127.0.0.1")
        self.assertRejected("https://[::1]")
        self.assertRejected("ftp://ops.example.com")
        self.assertRejected("not-a-url")
        # 开发环境：只有显式启用本机来源时才接受 loopback http
        self.assertRejected("http://localhost:5173", env=PROD)
        self.assertEqual(
            normalize_origin("http://127.0.0.1:5173", env=DEV),
            "http://127.0.0.1:5173",
        )
        self.assertEqual(
            normalize_origin("http://[::1]:5173", env=DEV), "http://[::1]:5173"
        )
        # 开发环境也不允许任意主机走 http
        self.assertRejected("http://dev.example.com", env=DEV)

    def test_domains_with_digits_are_not_ip_confused(self):
        # 含数字的正常域名不能被误判为 IP
        self.assertEqual(
            normalize_origin("https://site2.example.com"),
            "https://site2.example.com",
        )
        self.assertEqual(
            normalize_origin("https://v6.example.com"), "https://v6.example.com"
        )


class BuildPolicyTest(unittest.TestCase):
    def test_production_requires_origins(self):
        with self.assertRaises(PolicyValidationError):
            build_policy(env=PROD, origins=[])

    def test_development_allows_empty_but_localhost_is_opt_in(self):
        policy = build_policy(env=DEV, origins=[])
        self.assertFalse(policy.matches_origin("http://localhost:5173"))
        policy = build_policy(
            env=DEV, origins=[], allow_localhost=True, localhost_ports=[5173, 4173]
        )
        for origin in (
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://[::1]:4173",
        ):
            self.assertTrue(policy.matches_origin(origin), origin)

    def test_localhost_opt_in_forbidden_in_production(self):
        with self.assertRaises(PolicyValidationError):
            build_policy(
                env=PROD,
                origins=["https://ops.example.com"],
                allow_localhost=True,
            )

    def test_duplicate_origins_after_normalization_rejected(self):
        with self.assertRaises(PolicyValidationError):
            build_policy(
                env=PROD,
                origins=["https://ops.example.com", "HTTPS://OPS.EXAMPLE.COM"],
            )

    def test_methods_and_headers_validated(self):
        with self.assertRaises(PolicyValidationError):
            build_policy(env=PROD, origins=["https://a.com"], allow_methods=[])
        with self.assertRaises(PolicyValidationError):
            build_policy(
                env=PROD, origins=["https://a.com"], allow_methods=["GET\r\nX: y"]
            )
        with self.assertRaises(PolicyValidationError):
            build_policy(env=PROD, origins=["https://a.com"], allow_headers=["bad name"])
        policy = build_policy(
            env=PROD,
            origins=["https://a.com"],
            allow_headers=["X-Token", "x-token", "Content-Type"],
        )
        # 头名小写去重
        self.assertEqual(policy.allow_headers, frozenset({"x-token", "content-type"}))

    def test_header_check_respects_safelist(self):
        policy = build_policy(env=PROD, origins=["https://a.com"])
        self.assertIsNotNone(policy.check_request_headers(["Accept-Language"]))
        self.assertIsNone(policy.check_request_headers(["X-Evil"]))
        accepted = policy.check_request_headers(["Authorization", "Content-Type"])
        self.assertEqual(accepted, ["Authorization", "Content-Type"])

    def test_immutable(self):
        policy = build_policy(env=PROD, origins=["https://a.com"])
        with self.assertRaises(Exception):
            policy.max_age = 10  # type: ignore[misc]


class DocumentAndSnapshotTest(unittest.TestCase):
    def test_unknown_keys_rejected(self):
        with self.assertRaises(PolicyValidationError):
            parse_policy_document(
                {"allowed_origins": ["https://a.com"], "extra": 1},
                env=PROD,
                source="test",
            )

    def test_non_object_document_rejected(self):
        with self.assertRaises(PolicyValidationError):
            parse_policy_document(["https://a.com"], env=PROD, source="test")

    def test_env_origins_merge_with_file(self):
        policy = parse_policy_document(
            {"allowed_origins": ["https://file.example.com"]},
            env=PROD,
            source="test",
            extra_origins=["https://env.example.com"],
        )
        self.assertIn("https://file.example.com", policy.allowed_origins)
        self.assertIn("https://env.example.com", policy.allowed_origins)

    def test_full_validation_is_all_or_nothing(self):
        # 一项非法 => 整个文档不生效（不会部分采用）
        with self.assertRaises(PolicyValidationError):
            parse_policy_document(
                {
                    "allowed_origins": [
                        "https://good.example.com",
                        "http://127.0.0.1:5173",  # 生产非法
                    ]
                },
                env=PROD,
                source="test",
            )

    def test_snapshot_roundtrip(self):
        with TemporaryDirectory() as tmp:
            state = Path(tmp)
            policy = build_policy(
                env=PROD, origins=["https://ops.example.com"], source="file:x"
            )
            save_snapshot(policy, state)
            loaded = load_snapshot(state, env=PROD)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.allowed_origins, policy.allowed_origins)
            self.assertTrue(str(loaded.source).startswith("snapshot:"))

    def test_bootstrap_falls_back_to_snapshot(self):
        with TemporaryDirectory() as tmp:
            state = Path(tmp)
            good = build_policy(env=PROD, origins=["https://keep.example.com"])
            save_snapshot(good, state)

            # 新配置非法且无策略文件可装载：走环境变量路径必然报错 -> 回退快照
            import os

            os.environ.pop("CORS_ALLOWED_ORIGINS", None)
            policy = bootstrap_policy(env=PROD, policy_file=None, state_dir=state)
            self.assertIn("https://keep.example.com", policy.allowed_origins)
            audit = (state / "cors-audit.log").read_text(encoding="utf-8")
            self.assertIn("startup_fallback", audit)
            # 审计摘要不得包含 Cookie/Authorization 等凭据字段
            self.assertNotIn("authorization-header-value", audit)

    def test_bootstrap_rejects_without_snapshot(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(PolicyValidationError):
                bootstrap_policy(
                    env=PROD, policy_file=None, state_dir=Path(tmp) / "missing"
                )


if __name__ == "__main__":
    unittest.main()
