from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from vrf.inference import build_backend, run_generation
from vrf.schemas import SecureCodeSample


class InferenceRequest(BaseModel):
    task_type: str = "weakness_identification"
    language: str = "python"
    prompt: str
    code: str | None = None
    diff: str | None = None
    sample_id: str = "adhoc"


def create_app(config: dict[str, Any]) -> FastAPI:
    backend = build_backend(config["backend"])
    app = FastAPI(title="VeriSec Forge")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "model_version": backend.model_version}

    @app.post("/infer")
    def infer(request: InferenceRequest) -> dict[str, Any]:
        sample = SecureCodeSample(
            id=request.sample_id,
            task_type=request.task_type,
            language=request.language,
            prompt=request.prompt,
            code=request.code,
            diff=request.diff,
            split="adhoc",
            difficulty="unknown",
            source="api",
        )
        return run_generation(backend, sample).to_dict()

    return app
