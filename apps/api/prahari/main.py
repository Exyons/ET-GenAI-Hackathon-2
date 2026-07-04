from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from prahari.api.routes import router

app = FastAPI(title="Prahari", version="0.1.0")

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
