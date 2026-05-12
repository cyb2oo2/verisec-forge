# PrimeVul High-Quality Evidence Adjudication Packet

This packet is for independent review of high-quality `codex_pilot` disagreements.
The reviewer should decide whether the stored gold side, pilot side, or pair orientation is wrong.

## Adjudication Instructions

- Do not treat the pilot side as final; use it only as a triage hypothesis.
- Inspect the highlighted windows first, then wider context if needed.
- Fill the adjudication CSV with `final_vulnerable_side`, `label_status`, `evidence_span_sufficient`, `final_evidence_window_ids`, `reviewer`, `reviewed_at`, and `rationale`.
- If the visible windows are insufficient, set `evidence_span_sufficient=partial` or `no` rather than guessing.

## Queue Summary

- Rows: `6`

- Item 1: priority=`1`, gold=`A`, pilot=`B`, q=`3`, selected_windows=`B3`
- Item 2: priority=`2`, gold=`A`, pilot=`B`, q=`2`, selected_windows=`B1`
- Item 3: priority=`1`, gold=`B`, pilot=`A`, q=`3`, selected_windows=`A1`
- Item 4: priority=`1`, gold=`B`, pilot=`A`, q=`3`, selected_windows=`A3`
- Item 5: priority=`2`, gold=`A`, pilot=`B`, q=`2`, selected_windows=`B1;B2;B3`
- Item 6: priority=`2`, gold=`A`, pilot=`B`, q=`2`, selected_windows=`B2;B3`

---


## Item 1: `manual_evidence_audit::211::2::squid__780c4ea1b4c9d2fb41f6962aa6ed73ae57f74b2b__CVE-2021-46784`

### Adjudication Context

- Queue type: `high_quality_disagreement`
- Priority: `1`
- Review action: `adjudicate_gold_vs_pilot_direction`
- Gold vulnerable side: `A`
- Pilot vulnerable side: `B`
- Pilot evidence side: `B`
- Pilot evidence quality: `3`
- Pilot selected windows: `B3`
- Reason: `visible evidence conflicts with stored gold vulnerable side`
- Pilot note: `Side B removes bounded snprintf buffer handling and reintroduces appendf formatting`

Reviewer decision block:

```yaml
final_vulnerable_side: 
label_status: 
evidence_span_sufficient: 
final_evidence_window_ids: []
reviewer: 
reviewed_at: 
rationale: 
```


- Pair key: `squid|780c4ea1b4c9d2fb41f6962aa6ed73ae57f74b2b|CVE-2021-46784`
- Source pool: `fresh_seeds_top5_v1`
- Changed-line bucket: `26+`
- Project/CVE: `squid` / `CVE-2021-46784`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.036245`

### Side A

- ID: `210206::pairctx`
- Detector probability: `0.32082128524780273`

#### Window `A1`

- Header: `@@ -323,11 +327,12 @@ `
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
-     if (outbuf.length() > 0) {
-         entry->append(outbuf.rawContent(), outbuf.length());
```

Added preview:

```diff
+     if (outbuf.size() > 0) {
+         entry->append(outbuf.rawBuf(), outbuf.size());
+     outbuf.clean();
```

#### Window `A2`

- Header: `@@ -323,11 +327,12 @@  [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         entry->append(outbuf.rawContent(), outbuf.length());
```

Added preview:

```diff
+     if (outbuf.size() > 0) {
```

#### Window `A3`

- Header: `@@ -214,34 +216,34 @@                         break;`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `10`

Removed preview:

```diff
-                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
-                                            icon_url, escaped_selector, rfc1738_escape_part(host),
-                                            *port ? ":" : "", port, html_quote(name));
-                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",
```

Added preview:

```diff
+                     memset(tmpbuf, '\0', TEMP_BUF_SIZE);
+ 
+                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
+                                      icon_url, escaped_selector, rfc1738_escape_part(host),
```

### Side B

- ID: `430470::pairctx`
- Detector probability: `0.2845759987831116`

#### Window `B1`

- Header: `@@ -327,12 +323,11 @@ `
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
-     if (outbuf.size() > 0) {
-         entry->append(outbuf.rawBuf(), outbuf.size());
-     outbuf.clean();
```

Added preview:

```diff
+     if (outbuf.length() > 0) {
+         entry->append(outbuf.rawContent(), outbuf.length());
```

#### Window `B2`

- Header: `@@ -327,12 +323,11 @@  [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
-         entry->append(outbuf.rawBuf(), outbuf.size());
```

Added preview:

```diff
+     if (outbuf.length() > 0) {
```

#### Window `B3`

- Header: `@@ -216,34 +214,34 @@                         break;`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `10`
- Safety support: `1`

Removed preview:

```diff
-                     memset(tmpbuf, '\0', TEMP_BUF_SIZE);
- 
-                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
-                                      icon_url, escaped_selector, rfc1738_escape_part(host),
```

Added preview:

```diff
+                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
+                                            icon_url, escaped_selector, rfc1738_escape_part(host),
+                                            *port ? ":" : "", port, html_quote(name));
+                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",
```

---

## Item 2: `manual_evidence_audit::401::3::cyrus-imapd__621f9e41465b521399f691c241181300fab55995__CVE-2021-32056`

### Adjudication Context

- Queue type: `high_quality_disagreement`
- Priority: `2`
- Review action: `adjudicate_gold_vs_pilot_direction`
- Gold vulnerable side: `A`
- Pilot vulnerable side: `B`
- Pilot evidence side: `B`
- Pilot evidence quality: `2`
- Pilot selected windows: `B1`
- Reason: `visible evidence conflicts with stored gold vulnerable side`
- Pilot note: `Side B appears to move metadata read outside mailbox guard`

Reviewer decision block:

```yaml
final_vulnerable_side: 
label_status: 
evidence_span_sufficient: 
final_evidence_window_ids: []
reviewer: 
reviewed_at: 
rationale: 
```


- Pair key: `cyrus-imapd|621f9e41465b521399f691c241181300fab55995|CVE-2021-32056`
- Source pool: `fresh_seeds_top5_v1`
- Changed-line bucket: `11-25`
- Project/CVE: `cyrus-imapd` / `CVE-2021-32056`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.117547`

### Side A

- ID: `212934::pairctx`
- Detector probability: `0.3106943964958191`

#### Window `A1`

- Header: `@@ -25,24 +25,24 @@ `
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     struct annotate_metadata oldmdata;
-     r = read_old_value(d, key, keylen, &oldval, &oldmdata);
-     if (r) goto out;
-     /* if the value is identical, don't touch the mailbox */
```

Added preview:

```diff
+     if (mailbox) {
+         struct annotate_metadata oldmdata;
+         r = read_old_value(d, key, keylen, &oldval, &oldmdata);
+         if (r) goto out;
```

#### Window `A2`

- Header: `@@ -25,24 +25,24 @@  [changed-window 11]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `6`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+         /* if the value is identical, don't touch the mailbox */
+         if (oldval.len == value->len && (!value->len || !memcmp(oldval.s, value->s, value->len)))
```

#### Window `A3`

- Header: `@@ -25,24 +25,24 @@  [changed-window 8]`
- Direction labels: `candidate_removes_protection`
- Risk support: `6`
- Safety support: `0`

Removed preview:

```diff
-     /* if the value is identical, don't touch the mailbox */
-     if (oldval.len == value->len && (!value->len || !memcmp(oldval.s, value->s, value->len)))
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `463134::pairctx`
- Detector probability: `0.19314739108085632`

#### Window `B1`

- Header: `@@ -25,24 +25,24 @@ `
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         struct annotate_metadata oldmdata;
-         r = read_old_value(d, key, keylen, &oldval, &oldmdata);
-         if (r) goto out;
- 
```

Added preview:

```diff
+     struct annotate_metadata oldmdata;
+     r = read_old_value(d, key, keylen, &oldval, &oldmdata);
+     if (r) goto out;
+ 
```

#### Window `B2`

- Header: `@@ -25,24 +25,24 @@  [changed-window 18]`
- Direction labels: `candidate_removes_protection`
- Risk support: `6`
- Safety support: `0`

Removed preview:

```diff
-         /* if the value is identical, don't touch the mailbox */
-         if (oldval.len == value->len && (!value->len || !memcmp(oldval.s, value->s, value->len)))
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -25,24 +25,24 @@  [changed-window 5]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `6`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     /* if the value is identical, don't touch the mailbox */
+     if (oldval.len == value->len && (!value->len || !memcmp(oldval.s, value->s, value->len)))
```

---

## Item 3: `manual_evidence_audit::503::3::gnutls__d223040e498bd50a4b9e0aa493e78587ae1ed653__CVE-2008-1948`

### Adjudication Context

- Queue type: `high_quality_disagreement`
- Priority: `1`
- Review action: `adjudicate_gold_vs_pilot_direction`
- Gold vulnerable side: `B`
- Pilot vulnerable side: `A`
- Pilot evidence side: `A`
- Pilot evidence quality: `3`
- Pilot selected windows: `A1`
- Reason: `visible evidence conflicts with stored gold vulnerable side`
- Pilot note: `Side A removes short-record ciphertext length check`

Reviewer decision block:

```yaml
final_vulnerable_side: 
label_status: 
evidence_span_sufficient: 
final_evidence_window_ids: []
reviewer: 
reviewed_at: 
rationale: 
```


- Pair key: `gnutls|d223040e498bd50a4b9e0aa493e78587ae1ed653|CVE-2008-1948`
- Source pool: `fresh_seeds_top5_v1`
- Changed-line bucket: `11-25`
- Project/CVE: `gnutls` / `CVE-2008-1948`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.99996`
- Probability gap: `0.798648`

### Side A

- ID: `417234::pairctx`
- Detector probability: `0.9437636137008667`

#### Window `A1`

- Header: `@@ -34,15 +34,6 @@     {`
- Direction labels: `candidate_removes_protection`
- Risk support: `11`
- Safety support: `0`

Removed preview:

```diff
-     }
- 
-   if (ciphertext.size < (unsigned) blocksize + hash_size)
-     {
```

Added preview:

```diff
+ <empty>
```

#### Window `A2`

- Header: `@@ -98,6 +89,9 @@       if ((int)pad > (int)ciphertext.size - hash_size)`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `4`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	  _gnutls_record_log
+ 	    ("REC[%x]: Short record length %d > %d - %d (under attack?)\n",
+ 	     session, pad, ciphertext.size, hash_size);
```

#### Window `A3`

- Header: `@@ -98,6 +89,9 @@       if ((int)pad > (int)ciphertext.size - hash_size) [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `4`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	    ("REC[%x]: Short record length %d > %d - %d (under attack?)\n",
+ 	     session, pad, ciphertext.size, hash_size);
```

### Side B

- ID: `209003::pairctx`
- Detector probability: `0.14511536061763763`

#### Window `B1`

- Header: `@@ -34,6 +34,15 @@     {`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `11`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     }
+ 
+   if (ciphertext.size < (unsigned) blocksize + hash_size)
+     {
```

#### Window `B2`

- Header: `@@ -89,9 +98,6 @@       if ((int)pad > (int)ciphertext.size - hash_size)`
- Direction labels: `candidate_removes_protection`
- Risk support: `4`
- Safety support: `0`

Removed preview:

```diff
- 	  _gnutls_record_log
- 	    ("REC[%x]: Short record length %d > %d - %d (under attack?)\n",
- 	     session, pad, ciphertext.size, hash_size);
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -89,9 +98,6 @@       if ((int)pad > (int)ciphertext.size - hash_size) [changed-window 2]`
- Direction labels: `candidate_removes_protection`
- Risk support: `4`
- Safety support: `0`

Removed preview:

```diff
- 	    ("REC[%x]: Short record length %d > %d - %d (under attack?)\n",
- 	     session, pad, ciphertext.size, hash_size);
```

Added preview:

```diff
+ <empty>
```

---

## Item 4: `manual_evidence_audit::13::2::squid__5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9__CVE-2021-46784`

### Adjudication Context

- Queue type: `high_quality_disagreement`
- Priority: `1`
- Review action: `adjudicate_gold_vs_pilot_direction`
- Gold vulnerable side: `B`
- Pilot vulnerable side: `A`
- Pilot evidence side: `A`
- Pilot evidence quality: `3`
- Pilot selected windows: `A3`
- Reason: `visible evidence conflicts with stored gold vulnerable side`
- Pilot note: `Side A removes bounded snprintf temporary buffer handling and reintroduces appendf formatting`

Reviewer decision block:

```yaml
final_vulnerable_side: 
label_status: 
evidence_span_sufficient: 
final_evidence_window_ids: []
reviewer: 
reviewed_at: 
rationale: 
```


- Pair key: `squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784`
- Source pool: `project_holdout_top5_v1`
- Changed-line bucket: `26+`
- Project/CVE: `squid` / `CVE-2021-46784`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `1.0`
- Probability gap: `0.191501`

### Side A

- ID: `224281::pairctx`
- Detector probability: `0.5544704794883728`

#### Window `A1`

- Header: `@@ -335,12 +328,11 @@ `
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
-     if (outbuf.size() > 0) {
-         entry->append(outbuf.rawBuf(), outbuf.size());
-     outbuf.clean();
```

Added preview:

```diff
+     if (outbuf.length() > 0) {
+         entry->append(outbuf.rawContent(), outbuf.length());
```

#### Window `A2`

- Header: `@@ -335,12 +328,11 @@  [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
-         entry->append(outbuf.rawBuf(), outbuf.size());
```

Added preview:

```diff
+     if (outbuf.length() > 0) {
```

#### Window `A3`

- Header: `@@ -221,37 +219,34 @@                         break;`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `13`
- Safety support: `1`

Removed preview:

```diff
-                     memset(tmpbuf, '\0', TEMP_BUF_SIZE);
- 
-                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
-                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",
```

Added preview:

```diff
+                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
+                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",
+                         outbuf.appendf("\t%s\n", html_quote(name));
+                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"http://%s/%s\">%s</A>\n",
```

### Side B

- ID: `195309::pairctx`
- Detector probability: `0.36296921968460083`

#### Window `B1`

- Header: `@@ -328,11 +335,12 @@ `
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
-     if (outbuf.length() > 0) {
-         entry->append(outbuf.rawContent(), outbuf.length());
```

Added preview:

```diff
+     if (outbuf.size() > 0) {
+         entry->append(outbuf.rawBuf(), outbuf.size());
+     outbuf.clean();
```

#### Window `B2`

- Header: `@@ -328,11 +335,12 @@  [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         entry->append(outbuf.rawContent(), outbuf.length());
```

Added preview:

```diff
+     if (outbuf.size() > 0) {
```

#### Window `B3`

- Header: `@@ -219,34 +221,37 @@                         break;`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `13`

Removed preview:

```diff
-                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
-                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",
-                         outbuf.appendf("\t%s\n", html_quote(name));
-                             outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"http://%s/%s\">%s</A>\n",
```

Added preview:

```diff
+                     memset(tmpbuf, '\0', TEMP_BUF_SIZE);
+ 
+                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n",
+                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s%s%s/\">%s</A>\n",
```

---

## Item 5: `manual_evidence_audit::13::4::linux-2.6__8a0a9bd4db63bc45e3017bedeafbd88d0eb84d02__CVE-2009-3238`

### Adjudication Context

- Queue type: `high_quality_disagreement`
- Priority: `2`
- Review action: `adjudicate_gold_vs_pilot_direction`
- Gold vulnerable side: `A`
- Pilot vulnerable side: `B`
- Pilot evidence side: `B`
- Pilot evidence quality: `2`
- Pilot selected windows: `B1;B2;B3`
- Reason: `visible evidence conflicts with stored gold vulnerable side`
- Pilot note: `Side B removes replacement RNG path and restores custom key hash based random generation`

Reviewer decision block:

```yaml
final_vulnerable_side: 
label_status: 
evidence_span_sufficient: 
final_evidence_window_ids: []
reviewer: 
reviewed_at: 
rationale: 
```


- Pair key: `linux-2.6|8a0a9bd4db63bc45e3017bedeafbd88d0eb84d02|CVE-2009-3238`
- Source pool: `project_holdout_top5_v1`
- Changed-line bucket: `11-25`
- Project/CVE: `linux-2.6` / `CVE-2009-3238`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.667906`

### Side A

- ID: `216119::pairctx`
- Detector probability: `0.7879312038421631`

#### Window `A1`

- Header: `@@ -1,14 +1,10 @@ unsigned int get_random_int(void)`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- 	struct keydata *keyptr;
- 	__u32 *hash = get_cpu_var(get_random_int_hash);
- 	int ret;
- 
```

Added preview:

```diff
+ 	/*
+ 	 * Use IP's RNG. It suits our purpose perfectly: it re-keys itself
+ 	 * every second, from the entropy pool (and thus creates a limited
+ 	 * drain on it), and uses halfMD4Transform within the second. We
```

#### Window `A2`

- Header: `@@ -1,14 +1,10 @@ unsigned int get_random_int(void) [changed-window 13]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	 * Use IP's RNG. It suits our purpose perfectly: it re-keys itself
+ 	 * every second, from the entropy pool (and thus creates a limited
```

#### Window `A3`

- Header: `@@ -1,14 +1,10 @@ unsigned int get_random_int(void) [changed-window 14]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	 * every second, from the entropy pool (and thus creates a limited
+ 	 * drain on it), and uses halfMD4Transform within the second. We
```

### Side B

- ID: `499883::pairctx`
- Detector probability: `0.12002561241388321`

#### Window `B1`

- Header: `@@ -1,10 +1,14 @@ unsigned int get_random_int(void)`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- 	/*
- 	 * Use IP's RNG. It suits our purpose perfectly: it re-keys itself
- 	 * every second, from the entropy pool (and thus creates a limited
- 	 * drain on it), and uses halfMD4Transform within the second. We
```

Added preview:

```diff
+ 	struct keydata *keyptr;
+ 	__u32 *hash = get_cpu_var(get_random_int_hash);
+ 	int ret;
+ 
```

#### Window `B2`

- Header: `@@ -1,10 +1,14 @@ unsigned int get_random_int(void) [changed-window 2]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 	 * Use IP's RNG. It suits our purpose perfectly: it re-keys itself
- 	 * every second, from the entropy pool (and thus creates a limited
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -1,10 +1,14 @@ unsigned int get_random_int(void) [changed-window 3]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 	 * every second, from the entropy pool (and thus creates a limited
- 	 * drain on it), and uses halfMD4Transform within the second. We
```

Added preview:

```diff
+ <empty>
```

---

## Item 6: `manual_evidence_audit::42::8::linux__6cd1ed50efd88261298577cd92a14f2768eddeeb__CVE-2020-36558`

### Adjudication Context

- Queue type: `high_quality_disagreement`
- Priority: `2`
- Review action: `adjudicate_gold_vs_pilot_direction`
- Gold vulnerable side: `A`
- Pilot vulnerable side: `B`
- Pilot evidence side: `B`
- Pilot evidence quality: `2`
- Pilot selected windows: `B2;B3`
- Reason: `visible evidence conflicts with stored gold vulnerable side`
- Pilot note: `Side B removes resize_user and font resize handling around console resize`

Reviewer decision block:

```yaml
final_vulnerable_side: 
label_status: 
evidence_span_sufficient: 
final_evidence_window_ids: []
reviewer: 
reviewed_at: 
rationale: 
```


- Pair key: `linux|6cd1ed50efd88261298577cd92a14f2768eddeeb|CVE-2020-36558`
- Source pool: `rank6_10_v1`
- Changed-line bucket: `11-25`
- Project/CVE: `linux` / `CVE-2020-36558`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.993919`
- Probability gap: `0.906324`

### Side A

- ID: `212365::pairctx`
- Detector probability: `0.9664104580879211`

#### Window `A1`

- Header: `@@ -544,20 +544,15 @@ 			return -EINVAL;`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 			struct vc_data *vcp;
- 
- 			vcp = vc_cons[i].d;
- 			if (vcp) {
```

Added preview:

```diff
+ 			if (v.v_vlin)
+ 				vc_cons[i].d->vc_scan_lines = v.v_vlin;
+ 			if (v.v_clin)
+ 				vc_cons[i].d->vc_font.height = v.v_clin;
```

#### Window `A2`

- Header: `@@ -544,20 +544,15 @@ 			return -EINVAL; [changed-window 16]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 			vc_cons[i].d->vc_resize_user = 1;
+ 			vc_resize(vc_cons[i].d, v.v_cols, v.v_rows);
```

#### Window `A3`

- Header: `@@ -544,20 +544,15 @@ 			return -EINVAL; [changed-window 15]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 				vc_cons[i].d->vc_font.height = v.v_clin;
+ 			vc_cons[i].d->vc_resize_user = 1;
```

### Side B

- ID: `458189::pairctx`
- Detector probability: `0.060086652636528015`

#### Window `B1`

- Header: `@@ -544,15 +544,20 @@ 			return -EINVAL;`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 			if (v.v_vlin)
- 				vc_cons[i].d->vc_scan_lines = v.v_vlin;
- 			if (v.v_clin)
- 				vc_cons[i].d->vc_font.height = v.v_clin;
```

Added preview:

```diff
+ 			struct vc_data *vcp;
+ 
+ 			vcp = vc_cons[i].d;
+ 			if (vcp) {
```

#### Window `B2`

- Header: `@@ -544,15 +544,20 @@ 			return -EINVAL; [changed-window 7]`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- 			vc_cons[i].d->vc_resize_user = 1;
- 			vc_resize(vc_cons[i].d, v.v_cols, v.v_rows);
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -544,15 +544,20 @@ 			return -EINVAL; [changed-window 6]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 				vc_cons[i].d->vc_font.height = v.v_clin;
- 			vc_cons[i].d->vc_resize_user = 1;
```

Added preview:

```diff
+ <empty>
```

---
