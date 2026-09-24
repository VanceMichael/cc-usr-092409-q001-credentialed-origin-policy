import unittest

from app.cors_policy import (
    DEFAULT_ALLOW_HEADERS,
    DEFAULT_ALLOW_METHODS,
    PolicyValidationError,
    build_policy,
    load_policy_from_env,
    normalize_origin,
)


class NormalizeOriginTest(unittest.TestCase):
    def test_basic_https_origin(self):
        self.assertEqual(
            normalize_origin("https://console.example.com"),
            "https://console.example.com",
        )

    def test_case_and_default_port_are_normalized(self):
        self.assertEqual(
            normalize_origin("HTTPS://Console.Example.COM:443"),
            "https://console.example.com",
        )
        self.assertEqual(
            normalize_origin("http://localhost:80"), "http://localhost"
        )

    def test_non_default_port_is_kept(self):
        self.assertEqual(
            normalize_origin("https://admin.example.com:8443"),
            "https://admin.example.com:8443",
        )
        self.assertEqual(
            normalize_origin("http://localhost:3000"), "http://localhost:3000"
        )

    def test_ipv6_origin(self):
        self.assertEqual(
            normalize_origin("http://[::1]:8000"), "http://[::1]:8000"
        )

    def test_wildcard_and_null_rejected(self):
        self.assertIsNone(normalize_origin("*"))
        self.assertIsNone(normalize_origin("null"))

    def test_userinfo_rejected(self):
        self.assertIsNone(normalize_origin("https://user@example.com"))
        self.assertIsNone(normalize_origin("https://user:pass@example.com"))
        self.assertIsNone(normalize_origin("https://example.com@evil.com"))

    def test_confusing_hosts_rejected(self):
        self.assertIsNone(normalize_origin("https://example.com."))  # 结尾句点
        self.assertIsNone(normalize_origin("http://2130706433"))  # 整数 IP
        self.assertIsNone(normalize_origin("http://0x7f000001"))  # 十六进制 IP
        self.assertIsNone(normalize_origin("http://127.1"))  # 非四段写法
        self.assertIsNone(normalize_origin("http://0177.0.0.1"))  # 前导零
        self.assertIsNone(normalize_origin("https://exa mple.com"))
        self.assertIsNone(normalize_origin("https://-badlabel.com"))

    def test_path_query_fragment_rejected(self):
        self.assertIsNone(normalize_origin("https://example.com/"))
        self.assertIsNone(normalize_origin("https://example.com/path"))
        self.assertIsNone(normalize_origin("https://example.com?q=1"))
        self.assertIsNone(normalize_origin("https://example.com#frag"))

    def test_non_http_schemes_rejected(self):
        self.assertIsNone(normalize_origin("ftp://example.com"))
        self.assertIsNone(normalize_origin("file:///etc/passwd"))
        self.assertIsNone(normalize_origin("example.com"))
        self.assertIsNone(normalize_origin(""))

    def test_strict_ipv4_accepted(self):
        self.assertEqual(
            normalize_origin("https://192.168.1.10:8443"),
            "https://192.168.1.10:8443",
        )


def _build(environment="production", origins=("https://console.example.com",), **kw):
    params = dict(
        environment=environment,
        origins=origins,
        allow_credentials=True,
        allow_localhost=False,
        allow_methods=DEFAULT_ALLOW_METHODS,
        allow_headers=DEFAULT_ALLOW_HEADERS,
        max_age=600,
    )
    params.update(kw)
    return build_policy(**params)


class BuildPolicyTest(unittest.TestCase):
    def test_production_accepts_https_list(self):
        policy = _build()
        self.assertIn("https://console.example.com", policy.allowed_origins)

    def test_production_rejects_http_origin(self):
        with self.assertRaises(PolicyValidationError):
            _build(origins=("http://console.example.com",))

    def test_production_rejects_loopback(self):
        with self.assertRaises(PolicyValidationError):
            _build(origins=("https://localhost",))
        with self.assertRaises(PolicyValidationError):
            _build(origins=("https://127.0.0.1",))

    def test_wildcard_null_userinfo_never_coexist_with_credentials(self):
        for bad in ("*", "null", "https://user@example.com"):
            with self.assertRaises(PolicyValidationError):
                _build(origins=(bad,))

    def test_dev_localhost_requires_explicit_flag(self):
        with self.assertRaises(PolicyValidationError):
            _build(environment="development", origins=("http://localhost:3000",))
        policy = _build(
            environment="development",
            origins=("http://localhost:3000",),
            allow_localhost=True,
        )
        self.assertIn("http://localhost:3000", policy.allowed_origins)

    def test_dev_http_only_for_loopback(self):
        with self.assertRaises(PolicyValidationError):
            _build(
                environment="development",
                origins=("http://intranet.example.com",),
                allow_localhost=True,
            )

    def test_dev_https_non_loopback_allowed(self):
        policy = _build(
            environment="development",
            origins=("https://staging.example.com",),
        )
        self.assertIn("https://staging.example.com", policy.allowed_origins)

    def test_duplicate_origins_deduped(self):
        policy = _build(
            origins=(
                "https://console.example.com",
                "https://console.example.com:443",
                "HTTPS://CONSOLE.EXAMPLE.COM",
            )
        )
        self.assertEqual(policy.allowed_origins, {"https://console.example.com"})

    def test_wildcard_header_rejected(self):
        with self.assertRaises(PolicyValidationError):
            _build(allow_headers=("*",))

    def test_invalid_method_rejected(self):
        with self.assertRaises(PolicyValidationError):
            _build(allow_methods=("GET", "not a method"))

    def test_max_age_bounds(self):
        with self.assertRaises(PolicyValidationError):
            _build(max_age=-1)
        with self.assertRaises(PolicyValidationError):
            _build(max_age=86401)

    def test_empty_origin_list_is_valid_and_denies_all(self):
        policy = _build(origins=())
        self.assertFalse(policy.allows("https://console.example.com"))


class LoadPolicyFromEnvTest(unittest.TestCase):
    def test_full_env(self):
        policy = load_policy_from_env(
            {
                "APP_ENV": "production",
                "CORS_ALLOWED_ORIGINS": "https://a.example.com, https://b.example.com:8443",
                "CORS_ALLOW_CREDENTIALS": "true",
                "CORS_ALLOW_METHODS": "GET,POST",
                "CORS_ALLOW_HEADERS": "Authorization,Content-Type",
                "CORS_MAX_AGE": "1200",
            }
        )
        self.assertEqual(
            policy.allowed_origins,
            {"https://a.example.com", "https://b.example.com:8443"},
        )
        self.assertEqual(policy.allow_methods, ("GET", "POST"))
        self.assertEqual(policy.allow_headers, ("authorization", "content-type"))
        self.assertEqual(policy.max_age, 1200)

    def test_defaults_are_safe(self):
        policy = load_policy_from_env({})
        self.assertEqual(policy.environment, "production")
        self.assertEqual(policy.allowed_origins, frozenset())
        self.assertTrue(policy.allow_credentials)
        self.assertFalse(policy.allow_localhost)

    def test_invalid_bool_rejected(self):
        with self.assertRaises(PolicyValidationError):
            load_policy_from_env({"CORS_ALLOW_LOCALHOST": "maybe"})

    def test_invalid_max_age_rejected(self):
        with self.assertRaises(PolicyValidationError):
            load_policy_from_env({"CORS_MAX_AGE": "soon"})

    def test_invalid_app_env_rejected(self):
        with self.assertRaises(PolicyValidationError):
            load_policy_from_env({"APP_ENV": "staging"})


if __name__ == "__main__":
    unittest.main()
