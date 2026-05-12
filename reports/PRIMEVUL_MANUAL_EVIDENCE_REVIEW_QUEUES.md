# PrimeVul Manual Evidence Review Queues

These queues are derived from the completed `codex_pilot` audit and are designed for independent follow-up review.

## Queue Files

- High-quality disagreement queue: `data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl`
- Insufficient-context queue: `data/processed/secure_code_primevul_manual_evidence_insufficient_context_v1.jsonl`

## Review Protocol

- Treat `codex_pilot` as a triage signal, not a final label.
- For high-quality disagreements, decide whether the stored gold side, pilot side, or pair orientation is wrong.
- For insufficient-context cases, inspect wider function/commit context before assigning a vulnerable side.
- Record reviewer identity, final adjudicated side, evidence span, and whether the original hunk window was sufficient.

## High-Quality Disagreement Queue

- Rows: `6`

- priority=`1` `manual_evidence_audit::211::2::squid__780c4ea1b4c9d2fb41f6962aa6ed73ae57f74b2b__CVE-2021-46784`: gold=`A`, pilot=`B`, q=`3`, action=`adjudicate_gold_vs_pilot_direction`
- priority=`2` `manual_evidence_audit::401::3::cyrus-imapd__621f9e41465b521399f691c241181300fab55995__CVE-2021-32056`: gold=`A`, pilot=`B`, q=`2`, action=`adjudicate_gold_vs_pilot_direction`
- priority=`1` `manual_evidence_audit::503::3::gnutls__d223040e498bd50a4b9e0aa493e78587ae1ed653__CVE-2008-1948`: gold=`B`, pilot=`A`, q=`3`, action=`adjudicate_gold_vs_pilot_direction`
- priority=`1` `manual_evidence_audit::13::2::squid__5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9__CVE-2021-46784`: gold=`B`, pilot=`A`, q=`3`, action=`adjudicate_gold_vs_pilot_direction`
- priority=`2` `manual_evidence_audit::13::4::linux-2.6__8a0a9bd4db63bc45e3017bedeafbd88d0eb84d02__CVE-2009-3238`: gold=`A`, pilot=`B`, q=`2`, action=`adjudicate_gold_vs_pilot_direction`
- priority=`2` `manual_evidence_audit::42::8::linux__6cd1ed50efd88261298577cd92a14f2768eddeeb__CVE-2020-36558`: gold=`A`, pilot=`B`, q=`2`, action=`adjudicate_gold_vs_pilot_direction`

## Insufficient-Context Queue

- Rows: `14`

- priority=`2` `manual_evidence_audit::601::1::hexchat__4e061a43b3453a9856d34250c3913175c45afe9d__CVE-2016-2087`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::503::1::linux__ad9f151e560b016b6ad3280b48e42fa11e1a5440__CVE-2021-46283`: gold=`B`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::211::1::rpm__bd36c5dc9fb6d90c46fbfed8c2d67516fc571ec8__CVE-2021-3521`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::307::4::GIMP__22e2571c25425f225abdb11a566cc281fca6f366__CVE-2017-17786`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::42::4::furnace__0eb02422d5161767e9983bdaa5c429762d3477ce__CVE-2022-1289`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::7::5::linux__04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5__CVE-2022-1055`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::123::7::linux__d80b64ff297e40c2b6f7d7abc1b3eba70d22a068__CVE-2020-12768`: gold=`B`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::99::7::src__79a034b4aed29e965f45a13409268290c9910043__CVE-2020-35679`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::7::9::linux__b2f37aead1b82a770c48b5d583f35ec22aabb61e__CVE-2022-1195`: gold=`A`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::42::10::gpac__ebfa346eff05049718f7b80041093b4c5581c24e__CVE-2021-31258`: gold=`B`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`3` `manual_evidence_audit::7::4::mruby__3cf291f72224715942beaf8553e42ba8891ab3c6__CVE-2022-1212`: gold=`B`, pilot=`unclear`, q=`0`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::7::5::qemu__1caff0340f49c93d535c6558a5138d20d475315c__CVE-2021-3416`: gold=`B`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`2` `manual_evidence_audit::211::5::php-src__2bcbc95f033c31b00595ed39f79c3a99b4ed0501__CVE-2020-7060`: gold=`B`, pilot=`unclear`, q=`1`, action=`inspect_wider_context_before_direction_label`
- priority=`3` `manual_evidence_audit::503::5::FreeRDP__ce21b9d7ecd967e0bc98ed31a6b3757848aa6c9e__CVE-2020-11523`: gold=`A`, pilot=`unclear`, q=`0`, action=`inspect_wider_context_before_direction_label`
