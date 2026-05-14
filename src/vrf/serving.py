from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from vrf.inference import build_backend, run_generation
from vrf.patch_review_demo import (
    DEFAULT_DATASET_PATH,
    DEFAULT_EVIDENCE_PATH,
    DEFAULT_PREDICTIONS_PATH,
    build_patch_review_demo,
    list_demo_examples,
)
from vrf.schemas import SecureCodeSample


class InferenceRequest(BaseModel):
    task_type: str = "weakness_identification"
    language: str = "python"
    prompt: str
    code: str | None = None
    diff: str | None = None
    sample_id: str = "adhoc"


class PatchReviewRequest(BaseModel):
    sample_id: str | None = None
    pair_key: str | None = None
    evidence_limit: int = 2
    text_limit: int = 700


def create_app(config: dict[str, Any]) -> FastAPI:
    backend = build_backend(config["backend"])
    demo_config = config.get("patch_review_demo", {})
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

    @app.get("/review-pair/examples")
    def review_pair_examples(limit: int = 5) -> list[dict[str, Any]]:
        return list_demo_examples(
            demo_config.get("dataset", DEFAULT_DATASET_PATH),
            limit=limit,
        )

    @app.post("/review-pair")
    def review_pair(request: PatchReviewRequest) -> dict[str, Any]:
        return build_patch_review_demo(
            dataset_path=demo_config.get("dataset", DEFAULT_DATASET_PATH),
            predictions_path=demo_config.get("predictions", DEFAULT_PREDICTIONS_PATH),
            evidence_path=demo_config.get("evidence", DEFAULT_EVIDENCE_PATH),
            sample_id=request.sample_id,
            pair_key=request.pair_key,
            evidence_limit=request.evidence_limit,
            text_limit=request.text_limit,
        )

    return app
