# PrimeVul Insufficient-Context Review Brief

This brief summarizes the insufficient-context manual evidence queue for wider-context review.
It is not a final label artifact. Its purpose is to identify where the hunk/window evidence is too narrow for reliable adjudication.

## Summary

- Cases: `14`
- Final adjudication: `false`
- Bucket counts: `{'00-02': 2, '03-05': 2, '06-10': 4, '11-25': 2, '26+': 4}`
- Pilot evidence-side counts: `{'both': 8, 'unclear': 6}`
- Source-pool counts: `{'fresh_seeds_top5_v1': 6, 'project_holdout_top5_v1': 2, 'rank6_10_v1': 4, 'top5_v1': 2}`

## Case 1: `manual_evidence_audit::601::1::hexchat__4e061a43b3453a9856d34250c3913175c45afe9d__CVE-2016-2087`

- Pair key: `hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087`
- Project/CVE: `hexchat` / `CVE-2016-2087`
- Bucket/source: `26+` / `fresh_seeds_top5_v1`
- Gold/model vulnerable side: `A` / `A`
- Pilot evidence side/quality: `unclear` / `1`
- Side probabilities: A=`0.709019124507904`, B=`0.2958398759365082`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Large capability handling rewrite shows mixed protection and risk signals

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- Review surrounding control flow because this is a large-diff case.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -17,27 +19,66 @@ 	for (i=0; extensions[i]; i++)`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_introduces_risk`
- Risk/safety support: `13` / `10`

Removed preview:

  - `		gsize x;`
  - `		/* if the SASL password is set AND auth mode is set to SASL, request SASL auth */`
  - `		if (!g_strcmp0 (extension, "sasl") &&`
  - `			((serv->loginmethod == LOGIN_SASL && strlen (serv->password) != 0)`

Added preview:

  - `		if (!strcmp (extension, "identify-msg"))`
  - `			strcat (buffer, "identify-msg ");`
  - `			want_cap = 1;`
  - `		}`

### Window `B1`

- Header: `@@ -19,66 +17,27 @@ 	for (i=0; extensions[i]; i++)`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_removes_risk`
- Risk/safety support: `10` / `13`

Removed preview:

  - `		if (!strcmp (extension, "identify-msg"))`
  - `			strcat (buffer, "identify-msg ");`
  - `			want_cap = 1;`
  - `		}`

Added preview:

  - `		gsize x;`
  - `		/* if the SASL password is set AND auth mode is set to SASL, request SASL auth */`
  - `		if (!g_strcmp0 (extension, "sasl") &&`
  - `			((serv->loginmethod == LOGIN_SASL && strlen (serv->password) != 0)`

## Case 2: `manual_evidence_audit::503::1::linux__ad9f151e560b016b6ad3280b48e42fa11e1a5440__CVE-2021-46283`

- Pair key: `linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283`
- Project/CVE: `linux` / `CVE-2021-46283`
- Bucket/source: `26+` / `fresh_seeds_top5_v1`
- Gold/model vulnerable side: `B` / `A`
- Pilot evidence side/quality: `both` / `1`
- Side probabilities: A=`0.8539127111434937`, B=`0.7170118689537048`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Both sides show major error path and userdata handling changes with mixed signals

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- Review surrounding control flow because this is a large-diff case.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -193,75 +225,44 @@ `
- Direction labels: `candidate_removes_protection,candidate_introduces_risk`
- Risk/safety support: `24` / `0`

Removed preview:

  - `			goto err_set_alloc_name;`
  - `				goto err_set_init;`
  - `				goto err_set_init;`
  - `				goto err_set_init;`

Added preview:

  - `			goto err_set_expr_alloc;`
  - `				goto err_set_expr_alloc;`
  - `				goto err_set_expr_alloc;`
  - `				goto err_set_expr_alloc;`

### Window `A2`

- Header: `@@ -176,13 +176,45 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name);`
- Direction labels: `candidate_adds_protection`
- Risk/safety support: `0` / `20`

Removed preview:

  - `		goto err_set_alloc_name;`
  - `			goto err_set_alloc_name;`

Added preview:

  - `		goto err_set_name;`
  - ``
  - `	udata = NULL;`
  - `	if (udlen) {`

### Window `B2`

- Header: `@@ -176,45 +176,13 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name);`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `20` / `0`

Removed preview:

  - `		goto err_set_name;`
  - ``
  - `	udata = NULL;`
  - `	if (udlen) {`

Added preview:

  - `		goto err_set_alloc_name;`
  - `			goto err_set_alloc_name;`

## Case 3: `manual_evidence_audit::211::1::rpm__bd36c5dc9fb6d90c46fbfed8c2d67516fc571ec8__CVE-2021-3521`

- Pair key: `rpm|bd36c5dc9fb6d90c46fbfed8c2d67516fc571ec8|CVE-2021-3521`
- Project/CVE: `rpm` / `CVE-2021-3521`
- Bucket/source: `26+` / `fresh_seeds_top5_v1`
- Gold/model vulnerable side: `A` / `A`
- Pilot evidence side/quality: `both` / `1`
- Side probabilities: A=`0.9623913168907166`, B=`0.2240554541349411`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Packet parsing rewrite has mixed allocation and parsing changes without enough context

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- Review surrounding control flow because this is a large-diff case.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -4,69 +4,31 @@     const uint8_t *p = pkts;`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk/safety support: `13` / `11`

Removed preview:

  - `    pgpDigParams selfsig = NULL;`
  - `    int i = 0;`
  - `    int alloced = 16; /* plenty for normal cases */`
  - `    struct pgpPkt *all = xmalloc(alloced * sizeof(*all));`

Added preview:

  - `    struct pgpPkt pkt;`
  - `	if (decodePkt(p, (pend - p), &pkt))`
  - `	    if (pkttype && pkt.tag != pkttype) {`
  - `		digp = pgpDigParamsNew(pkt.tag);`

### Window `B1`

- Header: `@@ -4,31 +4,69 @@     const uint8_t *p = pkts;`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk/safety support: `11` / `13`

Removed preview:

  - `    struct pgpPkt pkt;`
  - `	if (decodePkt(p, (pend - p), &pkt))`
  - `	    if (pkttype && pkt.tag != pkttype) {`
  - `		digp = pgpDigParamsNew(pkt.tag);`

Added preview:

  - `    pgpDigParams selfsig = NULL;`
  - `    int i = 0;`
  - `    int alloced = 16; /* plenty for normal cases */`
  - `    struct pgpPkt *all = xmalloc(alloced * sizeof(*all));`

## Case 4: `manual_evidence_audit::307::4::GIMP__22e2571c25425f225abdb11a566cc281fca6f366__CVE-2017-17786`

- Pair key: `GIMP|22e2571c25425f225abdb11a566cc281fca6f366|CVE-2017-17786`
- Project/CVE: `GIMP` / `CVE-2017-17786`
- Bucket/source: `03-05` / `fresh_seeds_top5_v1`
- Gold/model vulnerable side: `A` / `A`
- Pilot evidence side/quality: `unclear` / `1`
- Side probabilities: A=`0.847967803478241`, B=`0.10521053522825241`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: AlphaBits condition changes are too context dependent in the shown windows

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -143,8 +143,7 @@              info.bpp != 24 && info.bpp != 32)      ||`
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `            (info.bpp == 16 && info.alphaBits != 1 &&`
  - `             info.alphaBits != 0)                   ||`

Added preview:

  - `            (info.bpp == 16 && info.alphaBits != 1) ||`

### Window `B1`

- Header: `@@ -143,7 +143,8 @@              info.bpp != 24 && info.bpp != 32)      ||`
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `            (info.bpp == 16 && info.alphaBits != 1) ||`

Added preview:

  - `            (info.bpp == 16 && info.alphaBits != 1 &&`
  - `             info.alphaBits != 0)                   ||`

## Case 5: `manual_evidence_audit::42::4::furnace__0eb02422d5161767e9983bdaa5c429762d3477ce__CVE-2022-1289`

- Pair key: `furnace|0eb02422d5161767e9983bdaa5c429762d3477ce|CVE-2022-1289`
- Project/CVE: `furnace` / `CVE-2022-1289`
- Bucket/source: `26+` / `project_holdout_top5_v1`
- Gold/model vulnerable side: `A` / `A`
- Pilot evidence side/quality: `both` / `1`
- Side probabilities: A=`0.9260365962982178`, B=`0.4532618522644043`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Pattern effect rendering changes include mixed range checks and formatting changes

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- Review surrounding control flow because this is a large-diff case.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -195,33 +195,27 @@           sprintf(id,"..##PE%d_%d_%d",k,i,j);`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk/safety support: `3` / `1`

Removed preview:

  - `          if (pat->data[i][index]>0xff) {`
  - `            sprintf(id,"??##PE%d_%d_%d",k,i,j);`
  - `            const unsigned char data=pat->data[i][index];`
  - `            sprintf(id,"%.2X##PE%d_%d_%d",data,k,i,j);`

Added preview:

  - `          sprintf(id,"%.2X##PE%d_%d_%d",pat->data[i][index],k,i,j);`
  - `          if (pat->data[i][index]<0x10) {`
  - `            ImGui::PushStyleColor(ImGuiCol_Text,uiColors[fxColors[pat->data[i][index]]]);`
  - `          } else if (pat->data[i][index]<0x20) {`

### Window `B3`

- Header: `@@ -195,27 +195,33 @@           sprintf(id,"..##PE%d_%d_%d",k,i,j); [changed-window 10]`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `3` / `0`

Removed preview:

  - `          } else if (pat->data[i][index]<0x90) {`
  - `            ImGui::PushStyleColor(ImGuiCol_Text,uiColors[GUI_COLOR_PATTERN_EFFECT_INVALID]);`

Added preview:

  - None.

## Case 6: `manual_evidence_audit::7::5::linux__04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5__CVE-2022-1055`

- Pair key: `linux|04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5|CVE-2022-1055`
- Project/CVE: `linux` / `CVE-2022-1055`
- Bucket/source: `06-10` / `project_holdout_top5_v1`
- Gold/model vulnerable side: `A` / `A`
- Pilot evidence side/quality: `both` / `1`
- Side probabilities: A=`0.729519784450531`, B=`0.5851011276245117`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Pointer initialization is reordered and appears semantically close in the shown windows

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -10,9 +10,9 @@ 	bool prio_allocate;`
- Direction labels: `candidate_adds_protection`
- Risk/safety support: `0` / `2`

Removed preview:

  - `	struct Qdisc *q;`
  - `	struct tcf_chain *chain;`

Added preview:

  - `	struct Qdisc *q = NULL;`
  - `	struct tcf_chain *chain = NULL;`

### Window `A2`

- Header: `@@ -41,8 +41,6 @@ 	tp = NULL;`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `2` / `0`

Removed preview:

  - `	q = NULL;`
  - `	chain = NULL;`

Added preview:

  - None.

### Window `B1`

- Header: `@@ -10,9 +10,9 @@ 	bool prio_allocate;`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `2` / `0`

Removed preview:

  - `	struct Qdisc *q = NULL;`
  - `	struct tcf_chain *chain = NULL;`

Added preview:

  - `	struct Qdisc *q;`
  - `	struct tcf_chain *chain;`

### Window `B2`

- Header: `@@ -41,6 +41,8 @@ 	tp = NULL;`
- Direction labels: `candidate_adds_protection`
- Risk/safety support: `0` / `2`

Removed preview:

  - None.

Added preview:

  - `	q = NULL;`
  - `	chain = NULL;`

## Case 7: `manual_evidence_audit::123::7::linux__d80b64ff297e40c2b6f7d7abc1b3eba70d22a068__CVE-2020-12768`

- Pair key: `linux|d80b64ff297e40c2b6f7d7abc1b3eba70d22a068|CVE-2020-12768`
- Project/CVE: `linux` / `CVE-2020-12768`
- Bucket/source: `11-25` / `rank6_10_v1`
- Gold/model vulnerable side: `B` / `A`
- Pilot evidence side/quality: `both` / `1`
- Side probabilities: A=`0.8652240633964539`, B=`0.13660839200019836`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Save area cleanup and error label rewiring is mixed and needs wider function context

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -1,32 +1,31 @@ static int svm_cpu_init(int cpu)`
- Direction labels: `candidate_removes_protection,candidate_introduces_risk`
- Risk/safety support: `8` / `0`

Removed preview:

  - `	int r;`
  - `	r = -ENOMEM;`
  - `		goto err_1;`
  - `		r = -ENOMEM;`

Added preview:

  - `		goto free_cpu_data;`
  - `			goto free_save_area;`
  - `free_save_area:`
  - `	__free_page(sd->save_area);`

### Window `B1`

- Header: `@@ -1,31 +1,32 @@ static int svm_cpu_init(int cpu)`
- Direction labels: `candidate_adds_protection,candidate_removes_risk`
- Risk/safety support: `0` / `8`

Removed preview:

  - `		goto free_cpu_data;`
  - `			goto free_save_area;`
  - `free_save_area:`
  - `	__free_page(sd->save_area);`

Added preview:

  - `	int r;`
  - `	r = -ENOMEM;`
  - `		goto err_1;`
  - `		r = -ENOMEM;`

## Case 8: `manual_evidence_audit::99::7::src__79a034b4aed29e965f45a13409268290c9910043__CVE-2020-35679`

- Pair key: `src|79a034b4aed29e965f45a13409268290c9910043|CVE-2020-35679`
- Project/CVE: `src` / `CVE-2020-35679`
- Bucket/source: `06-10` / `rank6_10_v1`
- Gold/model vulnerable side: `A` / `A`
- Pilot evidence side/quality: `both` / `1`
- Side probabilities: A=`0.9284088015556335`, B=`0.046378206461668015`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Regex return and regfree control flow differ but security impact is unclear from the shown window

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -12,11 +11,7 @@ 	if (regcomp(&preg, pattern, cflags) != 0)`
- Direction labels: `candidate_removes_risk`
- Risk/safety support: `0` / `1`

Removed preview:

  - `	ret = regexec(&preg, string, 0, NULL, 0);`
  - ``
  - `	regfree(&preg);`
  - ``

Added preview:

  - `	if (regexec(&preg, string, 0, NULL, 0) != 0)`

### Window `B1`

- Header: `@@ -11,7 +12,11 @@ 	if (regcomp(&preg, pattern, cflags) != 0)`
- Direction labels: `candidate_introduces_risk`
- Risk/safety support: `1` / `0`

Removed preview:

  - `	if (regexec(&preg, string, 0, NULL, 0) != 0)`

Added preview:

  - `	ret = regexec(&preg, string, 0, NULL, 0);`
  - ``
  - `	regfree(&preg);`
  - ``

## Case 9: `manual_evidence_audit::7::9::linux__b2f37aead1b82a770c48b5d583f35ec22aabb61e__CVE-2022-1195`

- Pair key: `linux|b2f37aead1b82a770c48b5d583f35ec22aabb61e|CVE-2022-1195`
- Project/CVE: `linux` / `CVE-2022-1195`
- Bucket/source: `03-05` / `rank6_10_v1`
- Gold/model vulnerable side: `A` / `A`
- Pilot evidence side/quality: `both` / `1`
- Side probabilities: A=`0.4882833957672119`, B=`0.4882833957672119`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: tty null assignment appears on both sides and the security direction is unclear

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A2`

- Header: `@@ -22,13 +22,13 @@ 	 */ [changed-window 1]`
- Direction labels: `candidate_adds_protection`
- Risk/safety support: `0` / `1`

Removed preview:

  - None.

Added preview:

  - `	ax->tty = NULL;`
  - ``

### Window `B2`

- Header: `@@ -22,13 +22,13 @@ 	 */ [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk/safety support: `1` / `0`

Removed preview:

  - `	ax->tty = NULL;`
  - ``

Added preview:

  - None.

## Case 10: `manual_evidence_audit::42::10::gpac__ebfa346eff05049718f7b80041093b4c5581c24e__CVE-2021-31258`

- Pair key: `gpac|ebfa346eff05049718f7b80041093b4c5581c24e|CVE-2021-31258`
- Project/CVE: `gpac` / `CVE-2021-31258`
- Bucket/source: `11-25` / `rank6_10_v1`
- Gold/model vulnerable side: `B` / `A`
- Pilot evidence side/quality: `both` / `1`
- Side probabilities: A=`0.7371581792831421`, B=`0.272024542093277`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: SL config copy direction and null checks are mixed and need wider API context

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A3`

- Header: `@@ -12,28 +12,26 @@ 	if (e) return e; [changed-window 14]`
- Direction labels: `candidate_adds_protection`
- Risk/safety support: `0` / `1`

Removed preview:

  - `	return gf_odf_desc_copy((GF_Descriptor *) slConfig, (GF_Descriptor **) slc);`

Added preview:

  - `	if (!slc) return GF_OK;`

### Window `B3`

- Header: `@@ -12,26 +12,28 @@ 	if (e) return e; [changed-window 14]`
- Direction labels: `candidate_adds_protection`
- Risk/safety support: `0` / `1`

Removed preview:

  - `	return gf_odf_desc_copy((GF_Descriptor *) slc, (GF_Descriptor **) slConfig);`

Added preview:

  - `	if (!slConfig) return GF_OK;`

## Case 11: `manual_evidence_audit::7::4::mruby__3cf291f72224715942beaf8553e42ba8891ab3c6__CVE-2022-1212`

- Pair key: `mruby|3cf291f72224715942beaf8553e42ba8891ab3c6|CVE-2022-1212`
- Project/CVE: `mruby` / `CVE-2022-1212`
- Bucket/source: `00-02` / `top5_v1`
- Gold/model vulnerable side: `B` / `A`
- Pilot evidence side/quality: `unclear` / `0`
- Side probabilities: A=`0.7356416583061218`, B=`0.7356416583061218`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Shown break_new lines are effectively identical and provide no directional evidence

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -1069,9 +1069,9 @@           }`
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `            mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);`

Added preview:

  - `            mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);`

### Window `B1`

- Header: `@@ -1069,9 +1069,9 @@           }`
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `            mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);`

Added preview:

  - `            mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);`

## Case 12: `manual_evidence_audit::7::5::qemu__1caff0340f49c93d535c6558a5138d20d475315c__CVE-2021-3416`

- Pair key: `qemu|1caff0340f49c93d535c6558a5138d20d475315c|CVE-2021-3416`
- Project/CVE: `qemu` / `CVE-2021-3416`
- Bucket/source: `00-02` / `top5_v1`
- Gold/model vulnerable side: `B` / `A`
- Pilot evidence side/quality: `unclear` / `1`
- Side probabilities: A=`0.49609383940696716`, B=`0.4263215959072113`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Receive callback wrapper change has unclear security effect in the shown window

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -5,7 +5,7 @@ `
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `        nc->info->receive(nc, buf, size);`

Added preview:

  - `        qemu_receive_packet(nc, buf, size);`

### Window `B1`

- Header: `@@ -5,7 +5,7 @@ `
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `        qemu_receive_packet(nc, buf, size);`

Added preview:

  - `        nc->info->receive(nc, buf, size);`

## Case 13: `manual_evidence_audit::211::5::php-src__2bcbc95f033c31b00595ed39f79c3a99b4ed0501__CVE-2020-7060`

- Pair key: `php-src|2bcbc95f033c31b00595ed39f79c3a99b4ed0501|CVE-2020-7060`
- Project/CVE: `php-src` / `CVE-2020-7060`
- Bucket/source: `06-10` / `fresh_seeds_top5_v1`
- Gold/model vulnerable side: `B` / `A`
- Pilot evidence side/quality: `unclear` / `1`
- Side probabilities: A=`0.8925625681877136`, B=`0.07423137128353119`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: CP950 private-use condition is refactored and needs helper semantics to judge

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -42,11 +42,7 @@ `
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `				if (w <= 0 &&`
  - `					(((c1 >= 0xfa && c1 <= 0xfe) || (c1 >= 0x8e && c1 <= 0xa0) ||`
  - `					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8))`
  - `					 && ((c > 0x39 && c < 0x7f) || (c > 0xa0 && c < 0xff))) ||`

Added preview:

  - `				if (w <= 0 && is_in_cp950_pua(c1, c)) {`

### Window `B1`

- Header: `@@ -42,7 +42,11 @@ `
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `				if (w <= 0 && is_in_cp950_pua(c1, c)) {`

Added preview:

  - `				if (w <= 0 &&`
  - `					(((c1 >= 0xfa && c1 <= 0xfe) || (c1 >= 0x8e && c1 <= 0xa0) ||`
  - `					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8))`
  - `					 && ((c > 0x39 && c < 0x7f) || (c > 0xa0 && c < 0xff))) ||`

## Case 14: `manual_evidence_audit::503::5::FreeRDP__ce21b9d7ecd967e0bc98ed31a6b3757848aa6c9e__CVE-2020-11523`

- Pair key: `FreeRDP|ce21b9d7ecd967e0bc98ed31a6b3757848aa6c9e|CVE-2020-11523`
- Project/CVE: `FreeRDP` / `CVE-2020-11523`
- Bucket/source: `06-10` / `fresh_seeds_top5_v1`
- Gold/model vulnerable side: `A` / `A`
- Pilot evidence side/quality: `unclear` / `0`
- Side probabilities: A=`0.6791787147521973`, B=`0.5506073832511902`
- Reason: hunk/window evidence is too narrow for a reliable side decision
- Pilot note: Rectangle helper refactor changes representation but shown windows provide no security direction

Wider-context requests:

- Inspect the full changed hunk around each selected window.
- Check whether the removed lines or added lines contain the actual vulnerable behavior.
- Compare both sides before choosing a final vulnerable side; current evidence is mixed.
- If wider context is still insufficient, keep label_status=insufficient_context instead of guessing.

Selected narrow evidence windows:

### Window `A1`

- Header: `@@ -1,7 +1,7 @@-INLINE void gdi_RectToRgn(HGDI_RECT rect, HGDI_RGN rgn)`
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `	rgn->x = rect->left;`
  - `	rgn->y = rect->top;`
  - `	rgn->w = rect->right - rect->left + 1;`
  - `	rgn->h = rect->bottom - rect->top + 1;`

Added preview:

  - `INLINE void gdi_RectToCRgn(const HGDI_RECT rect, INT32* x, INT32* y, INT32* w, INT32* h)`
  - `	*x = rect->left;`
  - `	*y = rect->top;`
  - `	*w = rect->right - rect->left + 1;`

### Window `B1`

- Header: `@@ -1,7 +1,7 @@-INLINE void gdi_RectToCRgn(const HGDI_RECT rect, INT32* x, INT32* y, INT32* w, INT32* h)`
- Direction labels: `direction_unclear`
- Risk/safety support: `0` / `0`

Removed preview:

  - `	*x = rect->left;`
  - `	*y = rect->top;`
  - `	*w = rect->right - rect->left + 1;`
  - `	*h = rect->bottom - rect->top + 1;`

Added preview:

  - `INLINE void gdi_RectToRgn(HGDI_RECT rect, HGDI_RGN rgn)`
  - `	rgn->x = rect->left;`
  - `	rgn->y = rect->top;`
  - `	rgn->w = rect->right - rect->left + 1;`

## Next Step

Use this brief to decide whether the existing selected windows can be expanded into sufficient evidence spans. If not, keep the row marked as insufficient context rather than forcing a vulnerable-side decision.
