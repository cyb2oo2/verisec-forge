from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
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


PATCH_REVIEW_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>VeriSec Forge Patch Review Demo</title>
  <style>
    :root {
      --ink: #162033;
      --muted: #637083;
      --paper: #fbf7ef;
      --panel: rgba(255, 255, 255, 0.82);
      --line: #dfd5c6;
      --risk: #b23b2e;
      --safe: #1f7a5a;
      --accent: #d98b2b;
      --shadow: 0 24px 70px rgba(45, 32, 18, 0.16);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--ink);
      font-family: Georgia, "Times New Roman", serif;
      background:
        radial-gradient(circle at 12% 8%, rgba(217, 139, 43, 0.24), transparent 28rem),
        radial-gradient(circle at 88% 12%, rgba(31, 122, 90, 0.16), transparent 24rem),
        linear-gradient(135deg, #fffaf0 0%, #f1eadc 52%, #e6dbc7 100%);
      min-height: 100vh;
    }
    main { max-width: 1180px; margin: 0 auto; padding: 42px 22px 64px; }
    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1.2fr) minmax(280px, 0.8fr);
      gap: 22px;
      align-items: stretch;
    }
    .card {
      background: var(--panel);
      border: 1px solid rgba(91, 75, 53, 0.18);
      border-radius: 28px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(12px);
    }
    .intro { padding: 34px; }
    .eyebrow { color: var(--accent); font: 700 13px/1.2 Verdana, sans-serif; letter-spacing: .12em; text-transform: uppercase; }
    h1 { font-size: clamp(38px, 6vw, 76px); line-height: .92; margin: 16px 0; letter-spacing: -0.055em; }
    .lede { color: #455268; font-size: 19px; line-height: 1.55; max-width: 780px; }
    .controls { padding: 24px; display: grid; gap: 14px; }
    label { display: block; color: var(--muted); font: 700 12px/1.2 Verdana, sans-serif; letter-spacing: .08em; text-transform: uppercase; }
    select, input, button {
      width: 100%;
      border-radius: 16px;
      border: 1px solid var(--line);
      padding: 12px 14px;
      font: 15px/1.25 Verdana, sans-serif;
      background: rgba(255, 255, 255, 0.86);
      color: var(--ink);
    }
    button {
      cursor: pointer;
      border: 0;
      color: white;
      background: linear-gradient(135deg, #25324d, #98631e);
      font-weight: 700;
      box-shadow: 0 14px 28px rgba(37, 50, 77, 0.22);
    }
    .status { min-height: 22px; color: var(--muted); font: 13px/1.4 Verdana, sans-serif; }
    .result { margin-top: 22px; display: grid; gap: 18px; }
    .summary { padding: 24px; display: grid; gap: 12px; }
    .pair-title { font: 700 14px/1.4 Verdana, sans-serif; color: var(--muted); overflow-wrap: anywhere; }
    .metric-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .metric { border: 1px solid var(--line); border-radius: 18px; padding: 14px; background: rgba(255,255,255,.64); }
    .metric strong { display: block; font-size: 22px; margin-top: 4px; }
    .sides { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
    .side { padding: 22px; border-left: 7px solid var(--line); }
    .side.risk { border-left-color: var(--risk); }
    .side.safe { border-left-color: var(--safe); }
    .side h2 { margin: 0 0 10px; font-size: 27px; letter-spacing: -0.03em; }
    .pill {
      display: inline-block;
      border-radius: 999px;
      padding: 5px 10px;
      margin: 3px 4px 3px 0;
      font: 700 12px/1 Verdana, sans-serif;
      background: #eee3d2;
      color: #574b3d;
    }
    .pill.risk { background: #f7d8d4; color: var(--risk); }
    .pill.safe { background: #d9efe4; color: var(--safe); }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #172033;
      color: #f8ead8;
      border-radius: 18px;
      padding: 14px;
      font: 13px/1.45 Consolas, "Liberation Mono", monospace;
    }
    .window { border-top: 1px solid var(--line); padding-top: 14px; margin-top: 14px; }
    .caveats { color: var(--muted); font: 13px/1.55 Verdana, sans-serif; }
    @media (max-width: 820px) {
      .hero, .sides, .metric-row { grid-template-columns: 1fr; }
      main { padding-top: 24px; }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="card intro">
        <div class="eyebrow">VeriSec Forge</div>
        <h1>Patch review, without pretending the benchmark is magic.</h1>
        <p class="lede">This artifact-backed demo shows the current paired-diff stack: pair-coupled decision, probability gap, support label, and evidence windows. It is for reviewer orientation, not arbitrary online vulnerability scanning.</p>
      </div>
      <div class="card controls">
        <label for="pairSelect">Demo pair</label>
        <select id="pairSelect"></select>
        <label for="sampleId">Or sample id</label>
        <input id="sampleId" placeholder="225086::pairctx" />
        <button id="loadButton">Review Pair</button>
        <div id="status" class="status">Loading examples...</div>
      </div>
    </section>
    <section id="result" class="result"></section>
  </main>
  <script>
    const pairSelect = document.querySelector("#pairSelect");
    const sampleId = document.querySelector("#sampleId");
    const statusEl = document.querySelector("#status");
    const resultEl = document.querySelector("#result");
    const loadButton = document.querySelector("#loadButton");

    function esc(value) {
      return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
      }[ch]));
    }

    function pct(value) {
      if (value === null || value === undefined || Number.isNaN(Number(value))) return "n/a";
      return (Number(value) * 100).toFixed(1) + "%";
    }

    function renderSide(row, riskierId) {
      const kind = row.id === riskierId ? "risk" : "safe";
      const windows = (row.evidence_windows || []).map(win => `
        <div class="window">
          <span class="pill ${kind}">${esc((win.direction_labels || []).join(", ") || "direction unclear")}</span>
          <span class="pill">risk ${esc(win.risk_support)}</span>
          <span class="pill">safety ${esc(win.safety_support)}</span>
          <p><strong>${esc(win.header)}</strong></p>
          <p>Removed</p><pre>${esc(win.removed || "(none)")}</pre>
          <p>Added</p><pre>${esc(win.added || "(none)")}</pre>
        </div>
      `).join("");
      return `
        <article class="card side ${kind}">
          <h2>${kind === "risk" ? "Riskier side" : "Safer side"}</h2>
          <div class="pill ${kind}">${esc(row.decision)}</div>
          <div class="pill">${esc(row.support_label)}</div>
          <p class="pair-title">${esc(row.id)} · ${esc(row.project)} · ${esc(row.cve)} · ${esc(row.cwe)}</p>
          <div class="metric-row">
            <div class="metric"><span>Probability</span><strong>${pct(row.vulnerability_probability)}</strong></div>
            <div class="metric"><span>Risk support</span><strong>${esc(row.risk_support)}</strong></div>
            <div class="metric"><span>Safety support</span><strong>${esc(row.safety_support)}</strong></div>
            <div class="metric"><span>Benchmark</span><strong>${row.correct_on_benchmark ? "correct" : "wrong"}</strong></div>
          </div>
          ${windows || '<p class="caveats">No evidence windows in artifact.</p>'}
        </article>
      `;
    }

    function render(payload) {
      const decision = payload.pair_decision || {};
      resultEl.innerHTML = `
        <div class="card summary">
          <div class="pair-title">${esc(payload.pair_key)}</div>
          <div class="metric-row">
            <div class="metric"><span>Riskier side</span><strong>${esc(decision.riskier_side_id)}</strong></div>
            <div class="metric"><span>Safer side</span><strong>${esc(decision.safer_side_id)}</strong></div>
            <div class="metric"><span>Probability gap</span><strong>${esc(decision.probability_gap)}</strong></div>
            <div class="metric"><span>Pair-coupled</span><strong>${decision.pair_coupled ? "yes" : "no"}</strong></div>
          </div>
          <div class="caveats">${(payload.caveats || []).map(item => `<p>${esc(item)}</p>`).join("")}</div>
        </div>
        <div class="sides">
          ${(payload.rows || []).map(row => renderSide(row, decision.riskier_side_id)).join("")}
        </div>
      `;
    }

    async function loadExamples() {
      const response = await fetch("/review-pair/examples?limit=8");
      const examples = await response.json();
      pairSelect.innerHTML = examples.map(item => `
        <option value="${esc(item.pair_key)}">${esc(item.project)} · ${esc(item.cve)} · ${esc(item.vulnerability_type)}</option>
      `).join("");
      statusEl.textContent = "Ready.";
      if (examples[0]) await loadReview({ pair_key: examples[0].pair_key });
    }

    async function loadReview(body) {
      statusEl.textContent = "Reviewing...";
      const response = await fetch("/review-pair", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ evidence_limit: 2, text_limit: 600, ...body })
      });
      if (!response.ok) throw new Error(await response.text());
      render(await response.json());
      statusEl.textContent = "Rendered artifact-backed review.";
    }

    loadButton.addEventListener("click", async () => {
      try {
        const id = sampleId.value.trim();
        await loadReview(id ? { sample_id: id } : { pair_key: pairSelect.value });
      } catch (error) {
        statusEl.textContent = "Error: " + error.message;
      }
    });

    loadExamples().catch(error => { statusEl.textContent = "Error: " + error.message; });
  </script>
</body>
</html>
"""


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

    @app.get("/review-pair/ui", response_class=HTMLResponse)
    def review_pair_ui() -> str:
        return PATCH_REVIEW_HTML

    return app
