# Professor Feedback Email Draft

Subject: Request for feedback on a secure-code evaluation claim

Hi Professor [Name],

I am working on a research artifact called VeriSec Forge / VeriPatch-RR. The
core question is whether secure-code models that look competent under
pointwise vulnerability detection preserve the vulnerable/fixed relation under
paired patch transformations.

The main claim is intentionally bounded: pointwise vulnerability accuracy is
not relational patch understanding, so side-order consistency, endpoint
robustness, and runtime evidence visibility should be measured separately. The
current draft includes PrimeVul controls, a Qwen/CodeBERT relational audit,
bounded low-canonical stress replications, readout ablations, and a small
external adapter smoke path.

Would you be willing to spend 10-15 minutes giving feedback on whether this
claim is framed at the right strength? I am especially interested in whether
the evidence hierarchy is clear, whether the limitations are strong enough for
a security/ML systems audience, and what the minimum next step would be before
sharing this as a preprint.

The short entry point is:
`docs/EXTERNAL_FEEDBACK_PACKET.md`

Thank you,
[Your Name]
