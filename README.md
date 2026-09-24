# 水产养殖管理后端

该服务提供塘口、养殖批次、投苗、投喂、水质、用药、成本、出塘和周期分析的 HTTP API，数据保存在 SQLite。运行时不依赖浏览器或外部服务。

## 跨域（CORS）信任边界

服务默认**不放行任何跨域来源**。预检与实际响应使用同一份策略，只有命中允许清单（规范化后精确匹配，含端口）的来源才会得到 `Access-Control-Allow-*` 头；凭据模式下回显具体来源，绝不通配。未获信任的来源拿不到放行头，预检统一返回 403（与路径是否存在无关），实际请求按无 Origin 处理，无法借错误差异探测受保护资源。所有响应带 `Vary: Origin`，预检另带 `Vary: Access-Control-Request-Method, Access-Control-Request-Headers`。

环境变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `APP_ENV` | `production` | `production` 只接受 HTTPS 来源且拒绝本机来源；`development` 允许本机 HTTP 来源（需显式开启） |
| `CORS_ALLOWED_ORIGINS` | 空 | 逗号分隔的来源清单，如 `https://console.example.com,https://admin.example.com:8443` |
| `CORS_ALLOW_CREDENTIALS` | `true` | 是否允许携带 Cookie / 授权头 |
| `CORS_ALLOW_LOCALHOST` | `false` | 开发环境下本机（loopback）来源的显式开关 |
| `CORS_ALLOW_METHODS` | `GET,POST,PUT,PATCH,DELETE,OPTIONS` | 预检放行的方法 |
| `CORS_ALLOW_HEADERS` | `Authorization,Content-Type` | 预检放行的请求头 |
| `CORS_MAX_AGE` | `600` | 预检缓存秒数（0–86400） |
| `CORS_POLICY_STATE_FILE` | `./data/cors_policy_state.json` | 最后一份有效策略的快照位置 |

规则：

- 通配符 `*`、`null` 来源、带用户信息的地址（`https://user@host`）以及易混淆主机写法（整数/十六进制 IP、非四段点分 IPv4、结尾句点 FQDN 等）一律拒绝，绝不与凭据模式共存。
- 配置换版先完整校验再原子生效；运行期重载失败保留最后一份有效策略，并输出不含密钥的审计摘要（JSON 日志，含策略哈希）。
- 启动门禁：环境配置无效时回退到快照中的最后有效策略；快照也不存在则拒绝启动。多进程（多 worker）各自独立校验同一份环境，行为一致。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 编译检查

```bash
python3 -m compileall -q app
```

## 启动

```bash
DATABASE_URL=sqlite:///./data/aquaculture.sqlite3 \
APP_ENV=production \
CORS_ALLOWED_ORIGINS=https://console.example.com \
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
