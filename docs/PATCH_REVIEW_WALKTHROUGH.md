# Patch Review External-Validation Walkthrough

This walkthrough shows how a reviewer can inspect one restored artifact-backed paired-diff example without running a model checkpoint. It connects the public PrimeVul reproduction bundle to the patch-review demo contract: paired diff identity, vulnerability probability, pair-coupled decision, support label, evidence window, and claim boundary.

## Restore And Run

```powershell
.\.venv\Scripts\python.exe scripts\download_reproducibility_bundle.py --restore
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py
.\.venv\Scripts\python.exe -m vrf.cli patch-demo --pair-key "tensorflow|c2b31ff2d3151acb230edc3f5b1832d2c713a9e0|CVE-2022-23565"
```

## Selected Pair

- Pair key: `tensorflow|c2b31ff2d3151acb230edc3f5b1832d2c713a9e0|CVE-2022-23565`
- Riskier side: `195389::pairctx`
- Safer side: `225086::pairctx`
- Probability gap: `0.8530`
- Pair-coupled decoding applied: `true`

## Side Summary

| Side | ID | Decision | Gold label | Probability | Support | Risk / safety support | Benchmark correctness |
| --- | --- | --- | --- | ---: | --- | --- | --- |
| Riskier | `195389::pairctx` | `vulnerable` | `vulnerable` | `0.9118` | `supported` | `2` / `0` | `true` |
| Safer | `225086::pairctx` | `safe` | `safe` | `0.0588` | `supported` | `0` / `2` | `true` |

## Top Evidence Windows

### `195389::pairctx`: `vulnerable`

- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`
- Hunk: `@@ -3,10 +3,9 @@     const protobuf::RepeatedPtrField<OpDef::AttrDef>& a2) {`

Removed:

```diff
    if (a1_set.find(def.name()) != a1_set.end()) {
      LOG(ERROR) << "AttrDef names must be unique, but '" << def.name()
                 << "' appears more than once";
    }
```

Added:

```diff
    DCHECK(a1_set.find(def.name()) == a1_set.end())
        << "AttrDef names must be unique, but '" << def.name()
        << "' appears more than once";
```

### `225086::pairctx`: `safe`

- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`
- Hunk: `@@ -3,9 +3,10 @@     const protobuf::RepeatedPtrField<OpDef::AttrDef>& a2) {`

Removed:

```diff
    DCHECK(a1_set.find(def.name()) == a1_set.end())
        << "AttrDef names must be unique, but '" << def.name()
        << "' appears more than once";
```

Added:

```diff
    if (a1_set.find(def.name()) != a1_set.end()) {
      LOG(ERROR) << "AttrDef names must be unique, but '" << def.name()
                 << "' appears more than once";
    }
```

## Interpretation Boundary

- This is an artifact-backed walkthrough over reproduced PrimeVul paired examples, not arbitrary online vulnerability scanning.
- The pair-coupled decision shows how the system uses paired task structure; it should be read together with the statistics in `reports/FINAL_SUBMISSION_STATISTICS.md`.
- Evidence windows are pseudo-localization/failure-triage artifacts. They are useful for review orientation, but they are not independent human gold labels.
- Source-aware routing is summarized in the external-generalization reports and final statistics table; this PrimeVul walkthrough focuses on the evidence-coupled paired-review path.
