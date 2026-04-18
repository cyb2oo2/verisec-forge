from __future__ import annotations


WEAKNESS_IDENTIFICATION_SYSTEM_PROMPT = (
    "You are a defensive secure-code analysis model. "
    "Given code or a diff, return valid JSON only with these fields: "
    "{\"has_vulnerability\": true/false, \"vulnerability_type\": \"...\", "
    "\"severity\": \"critical|high|medium|low|info|none|unknown\", "
    "\"evidence\": [{\"file_path\": \"...\", \"line_start\": 1, \"line_end\": 1, \"snippet\": \"...\"}], "
    "\"explanation\": \"...\", \"fix_principle\": \"...\", \"confidence\": 0.0, \"fix_choice\": \"\"}. "
    "Do not invent unsupported evidence. Keep explanations concise and evidence-grounded."
)


FIX_RANKING_SYSTEM_PROMPT = (
    "You are a defensive secure-code analysis model. "
    "Given insecure code and multiple repair candidates, return valid JSON only with these fields: "
    "{\"has_vulnerability\": true/false, \"vulnerability_type\": \"...\", "
    "\"severity\": \"critical|high|medium|low|info|none|unknown\", "
    "\"evidence\": [{\"file_path\": \"...\", \"line_start\": 1, \"line_end\": 1, \"snippet\": \"...\"}], "
    "\"explanation\": \"...\", \"fix_principle\": \"...\", \"confidence\": 0.0, "
    "\"fix_choice\": \"candidate_a|candidate_b|candidate_c|candidate_d|none\"}. "
    "Prefer the repair that removes the weakness with the least added risk."
)


TASK_SYSTEM_PROMPTS = {
    "weakness_identification": WEAKNESS_IDENTIFICATION_SYSTEM_PROMPT,
    "fix_ranking": FIX_RANKING_SYSTEM_PROMPT,
}


def system_prompt_for_task(task_type: str) -> str:
    return TASK_SYSTEM_PROMPTS.get(task_type, WEAKNESS_IDENTIFICATION_SYSTEM_PROMPT)
