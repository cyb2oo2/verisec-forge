# Learned Content Router Leave-One-Source Stress

This report holds out one source at router-training time and forces held-out rows to route to one of the remaining source experts.

## Protocol

- Router: `character n-gram naive bayes over diff-body-only text`
- Max features: `50000`
- Stress type: `leave-one-source-out open-set routing boundary`

## Held-Out Source Results

| Held-out source | Train sources | Held-out rows | Route distribution | Routed BA | Single BA | Oracle BA | Routed - single BA | Routed - oracle BA | Fallback rows |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `PrimeVul-time` | `DeltaSecommits, PatchEval` | `1562` | `{'DeltaSecommits': 1379, 'PatchEval': 183}` | `0.8585` | `0.8809` | `0.8835` | `-0.0224` | `-0.025` | `0` |
| `DeltaSecommits` | `PrimeVul-time, PatchEval` | `654` | `{'PatchEval': 25, 'PrimeVul-time': 629}` | `0.8486` | `0.8486` | `0.8563` | `0.0` | `-0.0077` | `0` |
| `PatchEval` | `PrimeVul-time, DeltaSecommits` | `538` | `{'DeltaSecommits': 58, 'PrimeVul-time': 480}` | `0.8048` | `0.8086` | `0.829` | `-0.0038` | `-0.0242` | `0` |

## Seen-Source Router Sanity

| Held-out source | Seen-source row accuracy | Seen-source pair accuracy |
| --- | ---: | ---: |
| `PrimeVul-time` | `0.995` | `0.995` |
| `DeltaSecommits` | `0.9929` | `0.9932` |
| `PatchEval` | `0.8863` | `0.886` |

## Interpretation

Leave-one-source-out routing should be read as an open-set boundary test. If routed existing experts trail the source-specific oracle, the system should keep source-aware routing as a closed-world adapter selection claim rather than a deployment-grade unseen-source expert discovery claim.
