# 水产养殖管理后端

该服务提供塘口、养殖批次、投苗、投喂、水质、用药、成本、出塘和周期分析的 HTTP API，数据保存在 SQLite。运行时不依赖浏览器或外部服务。

## 跨域（CORS）信任边界

浏览器接入接口默认允许携带凭据（Cookie、`Authorization` 头），因此后端**只回显经过显式登记并规范化的来源**，不使用通配符：

- 生产环境（`APP_ENV=production`，默认）只接受 `https://` 来源，且至少配置一个；
- 开发环境（`APP_ENV=development`）的本机来源（`localhost` / `127.0.0.1` / `[::1]`，仅限 `http`）必须通过 `allow_localhost` **显式开启**；
- `*`、`null`、带用户信息（`https://user@host`）、非默认端口显式写出（`:443`/`:80`）、前导零端口、尾随点域名、非规范 IP（`127.1`、`0x7f.0.0.1`、`0177.0.0.1`、十进制整数、非压缩 IPv6）等混淆写法一律拒绝；
- 预检与实际请求共用同一份不可变策略。预检（`OPTIONS` + `Access-Control-Request-Method`）一律返回 `204` 且不进入业务应用——无论路径是否存在、来源是否可信，响应无状态码/响应体差异，未信任来源只缺少放行头，无法借差异探测受保护资源；
- 所有响应带 `Vary: Origin`（预检另含 `Access-Control-Request-Method`、`Access-Control-Request-Headers`），`Access-Control-Max-Age` 由策略控制。

### 配置来源（按优先级合并）

1. 环境变量 `CORS_ALLOWED_ORIGINS`：逗号分隔的来源（与策略文件清单合并）；
2. 策略文件 `CORS_POLICY_FILE`：JSON 文档，字段见 [`config/cors.example.json`](config/cors.example.json)，出现未知字段会被拒绝。

```bash
# 生产：环境变量方式
APP_ENV=production \
CORS_ALLOWED_ORIGINS="https://ops.example.com,https://console.example.com:8443" \
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 生产：策略文件方式（支持轮询热换版）
APP_ENV=production CORS_POLICY_FILE=./config/cors.json \
uvicorn app.main:app --host 0.0.0.0 --port 8000

# 开发：显式开启本机前端来源
APP_ENV=development CORS_ALLOW_LOCALHOST=true CORS_LOCALHOST_PORTS=5173,4173 \
uvicorn app.main:app --reload
```

相关环境变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `APP_ENV` | `production` | `production` 仅允许登记的 HTTPS 来源；`development` 才允许 http loopback |
| `CORS_POLICY_FILE` | 无 | JSON 策略文件路径；设置后轮询其变化 |
| `CORS_ALLOWED_ORIGINS` | 无 | 逗号分隔的额外可信来源 |
| `CORS_ALLOW_LOCALHOST` | `false` | 仅开发环境有效；自动放行 localhost/127.0.0.1/[::1] |
| `CORS_LOCALHOST_PORTS` | 无 | 开发环境放行的本机端口（逗号分隔） |
| `CORS_STATE_DIR` | `data/cors-state` | 有效策略快照与审计日志目录（权限 0600） |
| `CORS_RELOAD_INTERVAL` | `2` | 策略文件轮询秒数；`CORS_RELOAD_ENABLED=false` 可关闭 |

### 换版、回退与审计

- 新配置必须**完整校验通过后才原子生效**（先落快照再切换引用），任何一项非法都保留当前策略；
- 进程启动时若配置非法，会自动回退到 `CORS_STATE_DIR` 下最后一份有效策略快照（LKG）；多 worker 启动时各自独立回退；既无合法配置又无快照时，生产环境**拒绝启动**；
- 每次装载、回退、拒绝换版、关停都会在 `$CORS_STATE_DIR/cors-audit.log` 追加一行 JSON 摘要（时间、PID、事件、来源清单、方法、头计数、指纹、拒绝原因），**不含任何 Cookie、令牌或密钥**。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

`tests/test_cors_policy.py` 为策略规范化/校验/快照的单元测试；`tests/test_cors_http.py` 会启动真实 uvicorn 子进程（含双 worker），验证允许/拒绝来源、无 Origin 调用、预检缓存、热换版回退、重启前后一致性及 SQLite 业务接口。

## 编译检查

```bash
python3 -m compileall -q app
```

## 启动

```bash
DATABASE_URL=sqlite:///./data/aquaculture.sqlite3 \
APP_ENV=production CORS_ALLOWED_ORIGINS="https://ops.example.com" \
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
