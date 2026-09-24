import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager, suppress
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy.exc import OperationalError

from .cors_policy import (
    CorsMiddleware,
    PolicyHolder,
    PolicyValidationError,
    append_audit,
    bootstrap_policy,
    watch_policy_file,
)
from .database import engine, Base
from .routers import ponds, batches, stocking, feeding, water_quality, medication, costs, harvest, analysis

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("aquaculture")

APP_ENV = os.getenv("APP_ENV", "production").strip().lower()
POLICY_FILE_ENV = os.getenv("CORS_POLICY_FILE", "").strip()
POLICY_FILE = Path(POLICY_FILE_ENV) if POLICY_FILE_ENV else None
STATE_DIR = Path(os.getenv("CORS_STATE_DIR", "data/cors-state"))
RELOAD_INTERVAL = float(os.getenv("CORS_RELOAD_INTERVAL", "2"))
RELOAD_ENABLED = os.getenv("CORS_RELOAD_ENABLED", "true").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)

# 中间件在导入期挂载，但策略由启动门禁填入；读侧始终拿到完整的不可变快照。
cors_holder = PolicyHolder()


def init_db(retries: int = 6, delay: float = 0.25) -> None:
    """建表放在启动期；多 worker 同时对同一 SQLite 建表会竞争，
    失败后以 checkfirst 方式重试（竞争结束后即为 no-op）。"""
    for attempt in range(retries):
        try:
            Base.metadata.create_all(bind=engine)
            return
        except OperationalError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    # 启动门禁：配置先完整校验；失败时回退最后一份有效策略；再失败则拒绝启动。
    try:
        policy = bootstrap_policy(
            env=APP_ENV, policy_file=POLICY_FILE, state_dir=STATE_DIR
        )
    except PolicyValidationError as exc:
        logger.error("CORS 启动门禁失败，且没有可回退的有效策略: %s", exc)
        raise
    cors_holder.replace(policy)
    logger.info("CORS 策略已生效: %s", policy.fingerprint())

    reload_task: asyncio.Task | None = None
    if POLICY_FILE is not None and RELOAD_ENABLED:
        reload_task = asyncio.create_task(
            watch_policy_file(
                cors_holder,
                env=APP_ENV,
                policy_file=POLICY_FILE,
                state_dir=STATE_DIR,
                interval=RELOAD_INTERVAL,
            ),
            name="cors-policy-watcher",
        )
    try:
        yield
    finally:
        if reload_task is not None:
            reload_task.cancel()
            with suppress(asyncio.CancelledError):
                await reload_task
        append_audit(STATE_DIR, "shutdown")


app = FastAPI(
    title="水产养殖管理系统",
    description="一个完整的水产养殖管理系统，支持塘口管理、投苗记录、日常管理、成本核算、出塘销售和养殖周期分析",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(CorsMiddleware, holder=cors_holder)

app.include_router(ponds.router)
app.include_router(batches.router)
app.include_router(stocking.router)
app.include_router(feeding.router)
app.include_router(water_quality.router)
app.include_router(medication.router)
app.include_router(costs.router)
app.include_router(harvest.router)
app.include_router(analysis.router)

@app.get("/")
def root():
    return {
        "message": "欢迎使用水产养殖管理系统API",
        "docs": "/docs",
        "version": "1.0.0"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}
