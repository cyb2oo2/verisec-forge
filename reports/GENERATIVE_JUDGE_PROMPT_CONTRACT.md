# Generative Instruction Judge Contract

For each VeriPatch-RR prompt, output exactly one label:

```text
A_RISKIER
B_RISKIER
INSUFFICIENT_CONTEXT
```

No explanation, JSON, markdown, or extra text is allowed in the scored output.

For local causal-LM runs, the scored benchmark text should end with:

```text
Final answer (one label only):
```