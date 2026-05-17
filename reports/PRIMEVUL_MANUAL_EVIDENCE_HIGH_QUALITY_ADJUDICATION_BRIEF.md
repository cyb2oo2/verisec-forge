# PrimeVul High-Quality Adjudication Brief

This brief summarizes the `6` high-quality pilot/gold disagreement cases before independent adjudication.
It is not a final label artifact; it is a compact reviewer guide for filling the focused adjudication CSV.

## Summary

- Cases: `6`
- Gold/pilot conflicts: `6`
- Model/pilot conflicts: `4`
- Final adjudication: `false`

## Case 1: `manual_evidence_audit::211::2::squid__780c4ea1b4c9d2fb41f6962aa6ed73ae57f74b2b__CVE-2021-46784`

- Pair key: `squid|780c4ea1b4c9d2fb41f6962aa6ed73ae57f74b2b|CVE-2021-46784`
- Project/CVE: `squid` / `CVE-2021-46784`
- Bucket/source: `26+` / `fresh_seeds_top5_v1`
- Gold/Pilot/Model vulnerable side: `A` / `B` / `A`
- Pilot evidence side/quality: `B` / `3`
- Side probabilities: A=`0.32082128524780273`, B=`0.2845759987831116`
- Pilot note: Side B removes bounded snprintf buffer handling and reintroduces appendf formatting

Reviewer questions:

- Does the selected evidence support side B over stored gold side A?
- Is the visible evidence span sufficient, or does this case require wider context?
- Should the final label be confirmed_gold, corrected_side, ambiguous, insufficient_context, or not_security_relevant?

Selected evidence windows:

### Window `B3`

- Header: `@@ -216,34 +214,34 @@                         break;`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk/safety support: `10` / `1`

Removed preview:

  - `                    memset(tmpbuf, '\0', TEMP_BUF_SIZE);`
  - ``
  - `                            snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",`
  - `                                     icon_url, escaped_selector, rfc1738_escape_part(host),`

Added preview:

  - `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",`
  - `                                           icon_url, escaped_selector, rfc1738_escape_part(host),`
  - `                                           *port ? ":" : "", port, html_quote(name));`
  - `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",`

## Case 2: `manual_evidence_audit::401::3::cyrus-imapd__621f9e41465b521399f691c241181300fab55995__CVE-2021-32056`

- Pair key: `cyrus-imapd|621f9e41465b521399f691c241181300fab55995|CVE-2021-32056`
- Project/CVE: `cyrus-imapd` / `CVE-2021-32056`
- Bucket/source: `11-25` / `fresh_seeds_top5_v1`
- Gold/Pilot/Model vulnerable side: `A` / `B` / `A`
- Pilot evidence side/quality: `B` / `2`
- Side probabilities: A=`0.3106943964958191`, B=`0.19314739108085632`
- Pilot note: Side B appears to move metadata read outside mailbox guard

Reviewer questions:

- Does the selected evidence support side B over stored gold side A?
- Is the visible evidence span sufficient, or does this case require wider context?
- Should the final label be confirmed_gold, corrected_side, ambiguous, insufficient_context, or not_security_relevant?

Selected evidence windows:

### Window `B1`

- Header: `@@ -25,24 +25,24 @@ `
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `        struct annotate_metadata oldmdata;`
  - `        r = read_old_value(d, key, keylen, &oldval, &oldmdata);`
  - `        if (r) goto out;`
  - ``

Added preview:

  - `    struct annotate_metadata oldmdata;`
  - `    r = read_old_value(d, key, keylen, &oldval, &oldmdata);`
  - `    if (r) goto out;`
  - ``

## Case 3: `manual_evidence_audit::503::3::gnutls__d223040e498bd50a4b9e0aa493e78587ae1ed653__CVE-2008-1948`

- Pair key: `gnutls|d223040e498bd50a4b9e0aa493e78587ae1ed653|CVE-2008-1948`
- Project/CVE: `gnutls` / `CVE-2008-1948`
- Bucket/source: `11-25` / `fresh_seeds_top5_v1`
- Gold/Pilot/Model vulnerable side: `B` / `A` / `A`
- Pilot evidence side/quality: `A` / `3`
- Side probabilities: A=`0.9437636137008667`, B=`0.14511536061763763`
- Pilot note: Side A removes short-record ciphertext length check

Reviewer questions:

- Does the selected evidence support side A over stored gold side B?
- Is the visible evidence span sufficient, or does this case require wider context?
- Should the final label be confirmed_gold, corrected_side, ambiguous, insufficient_context, or not_security_relevant?

Selected evidence windows:

### Window `A1`

- Header: `@@ -34,15 +34,6 @@     {`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `11` / `0`

Removed preview:

  - `    }`
  - ``
  - `  if (ciphertext.size < (unsigned) blocksize + hash_size)`
  - `    {`

Added preview:

  - None.

## Case 4: `manual_evidence_audit::13::2::squid__5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9__CVE-2021-46784`

- Pair key: `squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784`
- Project/CVE: `squid` / `CVE-2021-46784`
- Bucket/source: `26+` / `project_holdout_top5_v1`
- Gold/Pilot/Model vulnerable side: `B` / `A` / `A`
- Pilot evidence side/quality: `A` / `3`
- Side probabilities: A=`0.5544704794883728`, B=`0.36296921968460083`
- Pilot note: Side A removes bounded snprintf temporary buffer handling and reintroduces appendf formatting

Reviewer questions:

- Does the selected evidence support side A over stored gold side B?
- Is the visible evidence span sufficient, or does this case require wider context?
- Should the final label be confirmed_gold, corrected_side, ambiguous, insufficient_context, or not_security_relevant?

Selected evidence windows:

### Window `A3`

- Header: `@@ -221,37 +219,34 @@                         break;`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk/safety support: `13` / `1`

Removed preview:

  - `                    memset(tmpbuf, '\0', TEMP_BUF_SIZE);`
  - ``
  - `                            snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",`
  - `                            snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",`

Added preview:

  - `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",`
  - `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",`
  - `                        outbuf.appendf("\t%s\n", html_quote(name));`
  - `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"http://%s/%s\">%s</A>\n",`

## Case 5: `manual_evidence_audit::13::4::linux-2.6__8a0a9bd4db63bc45e3017bedeafbd88d0eb84d02__CVE-2009-3238`

- Pair key: `linux-2.6|8a0a9bd4db63bc45e3017bedeafbd88d0eb84d02|CVE-2009-3238`
- Project/CVE: `linux-2.6` / `CVE-2009-3238`
- Bucket/source: `11-25` / `project_holdout_top5_v1`
- Gold/Pilot/Model vulnerable side: `A` / `B` / `A`
- Pilot evidence side/quality: `B` / `2`
- Side probabilities: A=`0.7879312038421631`, B=`0.12002561241388321`
- Pilot note: Side B removes replacement RNG path and restores custom key hash based random generation

Reviewer questions:

- Does the selected evidence support side B over stored gold side A?
- Is the visible evidence span sufficient, or does this case require wider context?
- Should the final label be confirmed_gold, corrected_side, ambiguous, insufficient_context, or not_security_relevant?

Selected evidence windows:

### Window `B1`

- Header: `@@ -1,10 +1,14 @@ unsigned int get_random_int(void)`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `2` / `0`

Removed preview:

  - `	/*`
  - `	 * Use IP's RNG. It suits our purpose perfectly: it re-keys itself`
  - `	 * every second, from the entropy pool (and thus creates a limited`
  - `	 * drain on it), and uses halfMD4Transform within the second. We`

Added preview:

  - `	struct keydata *keyptr;`
  - `	__u32 *hash = get_cpu_var(get_random_int_hash);`
  - `	int ret;`
  - ``

### Window `B2`

- Header: `@@ -1,10 +1,14 @@ unsigned int get_random_int(void) [changed-window 2]`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `1` / `0`

Removed preview:

  - `	 * Use IP's RNG. It suits our purpose perfectly: it re-keys itself`
  - `	 * every second, from the entropy pool (and thus creates a limited`

Added preview:

  - None.

### Window `B3`

- Header: `@@ -1,10 +1,14 @@ unsigned int get_random_int(void) [changed-window 3]`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `1` / `0`

Removed preview:

  - `	 * every second, from the entropy pool (and thus creates a limited`
  - `	 * drain on it), and uses halfMD4Transform within the second. We`

Added preview:

  - None.

## Case 6: `manual_evidence_audit::42::8::linux__6cd1ed50efd88261298577cd92a14f2768eddeeb__CVE-2020-36558`

- Pair key: `linux|6cd1ed50efd88261298577cd92a14f2768eddeeb|CVE-2020-36558`
- Project/CVE: `linux` / `CVE-2020-36558`
- Bucket/source: `11-25` / `rank6_10_v1`
- Gold/Pilot/Model vulnerable side: `A` / `B` / `A`
- Pilot evidence side/quality: `B` / `2`
- Side probabilities: A=`0.9664104580879211`, B=`0.060086652636528015`
- Pilot note: Side B removes resize_user and font resize handling around console resize

Reviewer questions:

- Does the selected evidence support side B over stored gold side A?
- Is the visible evidence span sufficient, or does this case require wider context?
- Should the final label be confirmed_gold, corrected_side, ambiguous, insufficient_context, or not_security_relevant?

Selected evidence windows:

### Window `B2`

- Header: `@@ -544,15 +544,20 @@ 			return -EINVAL; [changed-window 7]`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `2` / `0`

Removed preview:

  - `			vc_cons[i].d->vc_resize_user = 1;`
  - `			vc_resize(vc_cons[i].d, v.v_cols, v.v_rows);`

Added preview:

  - None.

### Window `B3`

- Header: `@@ -544,15 +544,20 @@ 			return -EINVAL; [changed-window 6]`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `1` / `0`

Removed preview:

  - `				vc_cons[i].d->vc_font.height = v.v_clin;`
  - `			vc_cons[i].d->vc_resize_user = 1;`

Added preview:

  - None.

## Next Step

Fill `data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv`, then run the dry-run apply command from `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_WORKFLOW.md` before writing adjudicated JSONL.
