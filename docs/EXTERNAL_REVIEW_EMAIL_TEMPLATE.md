# External Review Email Templates

Two outreach templates for requesting feedback on the VeriSec Forge /
VeriPatch-RR working draft. Send either alongside (or linking to)
`docs/EXTERNAL_REVIEW_REQUEST.md`. Neither claims the work is finished,
published, or ready for a top venue -- fill in the bracketed fields and adjust
tone to fit the actual relationship, but keep the claim boundaries below
intact.

## Version A: Supervisor / Collaborator

Tone: direct, not overpolished, working-draft framing explicit.

**Subject:** Feedback on my secure-patch relational-consistency draft?

> Hi [Name],
>
> I've been working on an independent project (VeriSec Forge / VeriPatch-RR)
> and would like your feedback before I take it further. Short version:
> pointwise vulnerability-classification accuracy can look strong while
> hiding a different failure -- a model's riskier-side judgment on a
> vulnerable/fixed patch pair is nearly unchanged when I swap the prose Side
> A / Side B labels, but collapses when I flip the diff-hunk structure with
> the gold answer held fixed. That ordering shows up in both a Qwen decoder
> classifier and a CodeBERT encoder classifier, which are architecturally
> different enough that I don't think it's an artifact of one model family.
>
> This is a working draft, not a finished paper -- I know the citation list
> and framing still need outside eyes. I'd value 15-20 minutes if you have
> it: does the framing hold up, is the evidence strong enough for the claim
> I'm making, and what's the one thing you'd fix before I send it wider?
>
> Everything is in the repo: `paper/draft_v0.md` for the draft,
> `docs/EXTERNAL_REVIEW_REQUEST.md` for a guided 5-10 minute reading path and
> the specific questions I'd like answered.
>
> Thanks,
> [Your name]

## Version B: Cold PI / PhD Advisor Outreach

Tone: concise, research-focused, no desperation, no overclaim.

**Subject:** Question about relational-consistency evaluation for secure-code
models

> Dear Professor [Name],
>
> I'm reaching out about an independent research project that seems relevant
> to your group's work on [specific area, e.g. code model evaluation /
> software security]. The core finding: secure-code classifiers that reach
> strong pointwise accuracy can still be inconsistent on the relation between
> a vulnerable/fixed patch pair -- nearly inert to relabeling the two sides,
> but highly sensitive to the underlying diff-hunk structure. This behavioral
> pattern replicates across a Qwen decoder classifier and a CodeBERT encoder
> classifier.
>
> The project also measures a benchmark confound (an external dataset's
> higher raw accuracy tracks a stronger presentation shortcut, not better
> reasoning) and tests a structural repair whose learned fine-tuning variant
> does not transfer -- a result I report as a limitation, not a success.
>
> This is a working draft (`paper/draft_v0.md` in the linked repository), not
> yet a preprint or submission. I'd welcome five minutes of your reaction to
> whether the framing is worth discussing further, and if there's interest
> I'm glad to send the full draft and reading guide
> (`docs/EXTERNAL_REVIEW_REQUEST.md`).
>
> Best regards,
> [Your name]
> [Affiliation / application context if relevant]

## Notes For Whoever Sends These

- Fill in the bracketed fields; do not send with placeholders still in them.
- Do not add lines claiming the work solves secure patch reasoning, proves
  that all strong models fail universally, proves a shared internal
  mechanism, validates the learned repair, or presents a deployed
  vulnerability scanner -- none of those claims are supported by the current
  evidence.
- Do not describe the draft as ready for top-conference submission; it is a
  working draft seeking feedback.
- Version B is for a first cold contact; do not attach the full draft PDF
  unprompted -- link it and let the recipient ask.
