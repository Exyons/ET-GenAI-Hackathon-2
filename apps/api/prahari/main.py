import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_ticker())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Prahari", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "prahari"}
