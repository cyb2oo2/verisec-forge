# Reproducibility Sign-Off Checklist

## Environment
- [ ] Fresh venv, `pip install -e ".[dev]"` (extras only if needed).
- [ ] Python 3.11; resolved dependency versions recorded.

## Smoke path
- [ ] Five focused smoke tests pass (adapter, ci-smoke-contract, paper-artifacts,
      report-index, reproducibility-bundle).
- [ ] `git diff --check` clean (no whitespace errors).

## Manifests
- [ ] Every releasable artifact has a `reproducibility/*.json` manifest.
- [ ] `--check-only` passes for each relevant manifest.
- [ ] No hash mismatch (a mismatch is stop-the-line, not a re-hash).

## Determinism
- [ ] Seeds fixed and recorded.
- [ ] No timestamps / unordered set-iteration / RNG leaking into artifact bytes.
- [ ] Same seed + inputs → same output (within documented tolerance).

## Traceability
- [ ] Number appears in `reports/`, `experiments/registry.json`, and
      `paper/result_anchor_map.md` (if paper-facing), all consistent.
- [ ] Reproduction level tagged honestly (report / manifest / ci-smoke / protocol).

## Boundary
- [ ] No attempt to reproduce a GPU/training result inside CI.
- [ ] No smoke/pilot mislabeled as manifest-backed model quality.
