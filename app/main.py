from fastapi import FastAPI

from .cors_middleware import CorsPolicyMiddleware
from .cors_policy import CorsPolicyStore
from .database import Base, engine
from .routers import (
    analysis,
    batches,
    costs,
    feeding,
    harvest,
    medication,
    ponds,
    stocking,
    water_quality,
)


def create_app(env=None) -> FastAPI:
    """构建应用实例。

    启动门禁：跨域策略先完整校验再原子生效；环境配置无效时回退到最后
    一份有效快照，快照也不存在则抛出 StartupGateError 拒绝启动。
    env 缺省读取进程环境；传入映射可用于多进程一致性验证与测试。
    """
    Base.metadata.create_all(bind=engine)

    store = CorsPolicyStore.from_environment(env)

    app = FastAPI(
        title="水产养殖管理系统",
        description="一个完整的水产养殖管理系统，支持塘口管理、投苗记录、日常管理、成本核算、出塘销售和养殖周期分析",
        version="1.0.0",
    )
    app.state.cors_policy_store = store
    app.add_middleware(CorsPolicyMiddleware, store=store)

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
            "version": "1.0.0",
        }

    @app.get("/health")
    def health_check():
        return {"status": "healthy"}

    return app


app = create_app()
