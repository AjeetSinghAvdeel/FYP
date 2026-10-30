from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.assessments import router as assessments_router
from app.api.routes.auth import router as auth_router
from app.api.routes.reports import router as reports_router
from app.api.routes.targets import router as targets_router
from app.api.routes.evaluations import router as evaluations_router
from app.api.routes.admin import router as admin_router
from app.core.database import init_db

app = FastAPI(title="Risk-Guided Adaptive Pentest Platform", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(targets_router)
app.include_router(assessments_router)
app.include_router(reports_router)
app.include_router(evaluations_router)
app.include_router(admin_router)


@app.get("/health")
@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.on_event("startup")
def startup() -> None:
    init_db()
