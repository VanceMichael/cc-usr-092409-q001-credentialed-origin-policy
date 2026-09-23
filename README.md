# 水产养殖管理后端

该服务提供塘口、养殖批次、投苗、投喂、水质、用药、成本、出塘和周期分析的 HTTP API，数据保存在 SQLite。运行时不依赖浏览器或外部服务。

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
DATABASE_URL=sqlite:///./data/aquaculture.sqlite3 uvicorn app.main:app --host 0.0.0.0 --port 8000
```
