import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from prahari import config
from prahari.api.routes import router
from prahari.live.state import pipeline


async def _ticker() -> None:
    # backstop: flip warmup→monitoring on time even if traffic stops after the window
    while True:
        await asyncio.sleep(2)
        try:
            await pipeline.tick()
        except Exception:
            pass


async def _feed_refresher() -> None:
    # keep blocklist feeds fresh; skip entirely when no feeds are configured
    if not config.THREATINTEL_FEEDS:
        return
    from prahari.live import feeds
    while True:
        try:
            await asyncio.to_thread(feeds.refresh)
        except Exception:
            pass
        await asyncio.sleep(max(0.1, config.THREATINTEL_REFRESH_HOURS) * 3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    tasks = [asyncio.create_task(_ticker()), asyncio.create_task(_feed_refresher())]
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()


app = FastAPI(title="Prahari", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "prahari"}
