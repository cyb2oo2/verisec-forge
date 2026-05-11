# PrimeVul Manual Evidence Review Packet

Use this packet to annotate the JSONL file without reading raw one-line JSON. Copy the final decisions back into the `annotation` object for each `audit_id`.

Annotation fields:

- `human_vulnerable_side`: `A`, `B`, or `unclear`.
- `evidence_side`: `A`, `B`, `both`, `none`, or `unclear`.
- `evidence_quality`: `0` no evidence, `1` weak, `2` plausible, `3` strong direct evidence.
- `selected_window_ids`: window IDs such as `A1`, `A2`, `B1`.
- `label_issue`: `none`, `ambiguous`, `wrong_label`, or `insufficient_context`.

## Item 1: `manual_evidence_audit::307::1::drogon__3c785326c63a34aa1799a639ae185bc9453cb447__CVE-2022-25297`

- Pair key: `drogon|3c785326c63a34aa1799a639ae185bc9453cb447|CVE-2022-25297`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `drogon` / `CVE-2022-25297`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.999989`
- Probability gap: `0.352792`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `250692::pairctx`
- Detector probability: `0.8606036305427551`

#### Window `A1`

- Header: `@@ -1,28 +1,26 @@-int HttpFileImpl::save(const std::string &path) const`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `9`

Removed preview:

```diff
-     assert(!path.empty());
-     if (fileName_.empty())
-         return -1;
-     filesystem::path fsPath(utils::toNativePath(path));
```

Added preview:

```diff
+ int HttpFileImpl::saveAs(const std::string &fileName) const
+     assert(!fileName.empty());
+     filesystem::path fsFileName(utils::toNativePath(fileName));
+     if (!fsFileName.is_absolute() && (!fsFileName.has_parent_path() ||
```

#### Window `A2`

- Header: `@@ -1,28 +1,26 @@-int HttpFileImpl::save(const std::string &path) const [changed-window 12]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+                                       (fsFileName.begin()->string() != "." &&
+                                        fsFileName.begin()->string() != "..")))
```

#### Window `A3`

- Header: `@@ -1,28 +1,26 @@-int HttpFileImpl::save(const std::string &path) const [changed-window 11]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `4`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     if (!fsFileName.is_absolute() && (!fsFileName.has_parent_path() ||
+                                       (fsFileName.begin()->string() != "." &&
```

### Side B

- ID: `197057::pairctx`
- Detector probability: `0.5078119039535522`

#### Window `B1`

- Header: `@@ -1,26 +1,28 @@-int HttpFileImpl::saveAs(const std::string &fileName) const`
- Direction labels: `candidate_removes_protection`
- Risk support: `8`
- Safety support: `0`

Removed preview:

```diff
-     assert(!fileName.empty());
-     filesystem::path fsFileName(utils::toNativePath(fileName));
-     if (!fsFileName.is_absolute() && (!fsFileName.has_parent_path() ||
-                                       (fsFileName.begin()->string() != "." &&
```

Added preview:

```diff
+ int HttpFileImpl::save(const std::string &path) const
+     assert(!path.empty());
+     if (fileName_.empty())
+         return -1;
```

#### Window `B2`

- Header: `@@ -1,26 +1,28 @@-int HttpFileImpl::saveAs(const std::string &fileName) const [changed-window 5]`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
-                                       (fsFileName.begin()->string() != "." &&
-                                        fsFileName.begin()->string() != "..")))
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -1,26 +1,28 @@-int HttpFileImpl::saveAs(const std::string &fileName) const [changed-window 4]`
- Direction labels: `candidate_removes_protection`
- Risk support: `4`
- Safety support: `0`

Removed preview:

```diff
-     if (!fsFileName.is_absolute() && (!fsFileName.has_parent_path() ||
-                                       (fsFileName.begin()->string() != "." &&
```

Added preview:

```diff
+ <empty>
```

---

## Item 2: `manual_evidence_audit::401::1::gpac__3dbe11b37d65c8472faf0654410068e5500b3adb__CVE-2022-1441`

- Pair key: `gpac|3dbe11b37d65c8472faf0654410068e5500b3adb|CVE-2022-1441`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `gpac` / `CVE-2022-1441`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `1.0`
- Probability gap: `0.710533`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `236125::pairctx`
- Detector probability: `0.8233283758163452`

#### Window `A1`

- Header: `@@ -1,18 +1,10 @@ GF_Err diST_box_read(GF_Box *s, GF_BitStream *bs)`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `2`
- Safety support: `4`

Removed preview:

```diff
- 	u32 i;
- 	char str[1024];
- 	i=0;
- 	str[0]=0;
```

Added preview:

```diff
+ 	p->content_script_types = gf_malloc(sizeof(char) * (s->size+1));
+ 	if (!p->content_script_types) return GF_OUT_OF_MEM;
+ 	gf_bs_read_data(bs, p->content_script_types, s->size);
+ 	p->content_script_types[s->size] = 0;
```

#### Window `A2`

- Header: `@@ -1,18 +1,10 @@ GF_Err diST_box_read(GF_Box *s, GF_BitStream *bs) [changed-window 13]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `2`
- Safety support: `4`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	p->content_script_types = gf_malloc(sizeof(char) * (s->size+1));
+ 	if (!p->content_script_types) return GF_OUT_OF_MEM;
```

#### Window `A3`

- Header: `@@ -1,18 +1,10 @@ GF_Err diST_box_read(GF_Box *s, GF_BitStream *bs) [changed-window 12]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `2`
- Safety support: `2`

Removed preview:

```diff
- 	p->content_script_types = gf_strdup(str);
```

Added preview:

```diff
+ 	p->content_script_types = gf_malloc(sizeof(char) * (s->size+1));
```

### Side B

- ID: `195984::pairctx`
- Detector probability: `0.11279541254043579`

#### Window `B1`

- Header: `@@ -1,10 +1,18 @@ GF_Err diST_box_read(GF_Box *s, GF_BitStream *bs)`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `4`
- Safety support: `2`

Removed preview:

```diff
- 	p->content_script_types = gf_malloc(sizeof(char) * (s->size+1));
- 	if (!p->content_script_types) return GF_OUT_OF_MEM;
- 	gf_bs_read_data(bs, p->content_script_types, s->size);
- 	p->content_script_types[s->size] = 0;
```

Added preview:

```diff
+ 	u32 i;
+ 	char str[1024];
+ 	i=0;
+ 	str[0]=0;
```

#### Window `B2`

- Header: `@@ -1,10 +1,18 @@ GF_Err diST_box_read(GF_Box *s, GF_BitStream *bs) [changed-window 3]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `4`
- Safety support: `2`

Removed preview:

```diff
- 	p->content_script_types = gf_malloc(sizeof(char) * (s->size+1));
- 	if (!p->content_script_types) return GF_OUT_OF_MEM;
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -1,10 +1,18 @@ GF_Err diST_box_read(GF_Box *s, GF_BitStream *bs) [changed-window 4]`
- Direction labels: `candidate_removes_protection`
- Risk support: `3`
- Safety support: `0`

Removed preview:

```diff
- 	if (!p->content_script_types) return GF_OUT_OF_MEM;
- 	gf_bs_read_data(bs, p->content_script_types, s->size);
```

Added preview:

```diff
+ <empty>
```

---

## Item 3: `manual_evidence_audit::601::1::hexchat__4e061a43b3453a9856d34250c3913175c45afe9d__CVE-2016-2087`

- Pair key: `hexchat|4e061a43b3453a9856d34250c3913175c45afe9d|CVE-2016-2087`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `hexchat` / `CVE-2016-2087`
- Changed-line bucket: `26+`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.413179`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `199767::pairctx`
- Detector probability: `0.709019124507904`

#### Window `A1`

- Header: `@@ -17,27 +19,66 @@ 	for (i=0; extensions[i]; i++)`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_introduces_risk`
- Risk support: `13`
- Safety support: `10`

Removed preview:

```diff
- 		gsize x;
- 		/* if the SASL password is set AND auth mode is set to SASL, request SASL auth */
- 		if (!g_strcmp0 (extension, "sasl") &&
- 			((serv->loginmethod == LOGIN_SASL && strlen (serv->password) != 0)
```

Added preview:

```diff
+ 		if (!strcmp (extension, "identify-msg"))
+ 			strcat (buffer, "identify-msg ");
+ 			want_cap = 1;
+ 		}
```

#### Window `A2`

- Header: `@@ -17,27 +19,66 @@ 	for (i=0; extensions[i]; i++) [changed-window 66]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 			&& ((serv->loginmethod == LOGIN_SASL && strlen (serv->password) != 0)
+ 			|| (serv->loginmethod == LOGIN_SASLEXTERNAL && serv->have_cert)))
```

#### Window `A3`

- Header: `@@ -17,27 +19,66 @@ 	for (i=0; extensions[i]; i++) [changed-window 4]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 			((serv->loginmethod == LOGIN_SASL && strlen (serv->password) != 0)
- 				|| (serv->loginmethod == LOGIN_SASLEXTERNAL && serv->have_cert)))
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `292205::pairctx`
- Detector probability: `0.2958398759365082`

#### Window `B1`

- Header: `@@ -19,66 +17,27 @@ 	for (i=0; extensions[i]; i++)`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_removes_risk`
- Risk support: `10`
- Safety support: `13`

Removed preview:

```diff
- 		if (!strcmp (extension, "identify-msg"))
- 			strcat (buffer, "identify-msg ");
- 			want_cap = 1;
- 		}
```

Added preview:

```diff
+ 		gsize x;
+ 		/* if the SASL password is set AND auth mode is set to SASL, request SASL auth */
+ 		if (!g_strcmp0 (extension, "sasl") &&
+ 			((serv->loginmethod == LOGIN_SASL && strlen (serv->password) != 0)
```

#### Window `B2`

- Header: `@@ -19,66 +17,27 @@ 	for (i=0; extensions[i]; i++) [changed-window 60]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 			&& ((serv->loginmethod == LOGIN_SASL && strlen (serv->password) != 0)
- 			|| (serv->loginmethod == LOGIN_SASLEXTERNAL && serv->have_cert)))
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -19,66 +17,27 @@ 	for (i=0; extensions[i]; i++) [changed-window 5]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 			((serv->loginmethod == LOGIN_SASL && strlen (serv->password) != 0)
+ 				|| (serv->loginmethod == LOGIN_SASLEXTERNAL && serv->have_cert)))
```

---

## Item 4: `manual_evidence_audit::503::1::linux__ad9f151e560b016b6ad3280b48e42fa11e1a5440__CVE-2021-46283`

- Pair key: `linux|ad9f151e560b016b6ad3280b48e42fa11e1a5440|CVE-2021-46283`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `linux` / `CVE-2021-46283`
- Changed-line bucket: `26+`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `1.0`
- Probability gap: `0.136901`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `328360::pairctx`
- Detector probability: `0.8539127111434937`

#### Window `A1`

- Header: `@@ -193,75 +225,44 @@ `
- Direction labels: `candidate_removes_protection,candidate_introduces_risk`
- Risk support: `24`
- Safety support: `0`

Removed preview:

```diff
- 			goto err_set_alloc_name;
- 				goto err_set_init;
- 				goto err_set_init;
- 				goto err_set_init;
```

Added preview:

```diff
+ 			goto err_set_expr_alloc;
+ 				goto err_set_expr_alloc;
+ 				goto err_set_expr_alloc;
+ 				goto err_set_expr_alloc;
```

#### Window `A2`

- Header: `@@ -176,13 +176,45 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name);`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `20`

Removed preview:

```diff
- 		goto err_set_alloc_name;
- 			goto err_set_alloc_name;
```

Added preview:

```diff
+ 		goto err_set_name;
+ 
+ 	udata = NULL;
+ 	if (udlen) {
```

#### Window `A3`

- Header: `@@ -176,13 +176,45 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name); [changed-window 6]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `2`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 		udata = set->data + size;
+ 		nla_memcpy(udata, nla[NFTA_SET_USERDATA], udlen);
```

### Side B

- ID: `202069::pairctx`
- Detector probability: `0.7170118689537048`

#### Window `B1`

- Header: `@@ -225,44 +193,75 @@ `
- Direction labels: `candidate_adds_protection,candidate_removes_risk`
- Risk support: `0`
- Safety support: `24`

Removed preview:

```diff
- 			goto err_set_expr_alloc;
- 				goto err_set_expr_alloc;
- 				goto err_set_expr_alloc;
- 				goto err_set_expr_alloc;
```

Added preview:

```diff
+ 			goto err_set_alloc_name;
+ 				goto err_set_init;
+ 				goto err_set_init;
+ 				goto err_set_init;
```

#### Window `B2`

- Header: `@@ -176,45 +176,13 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name);`
- Direction labels: `candidate_removes_protection`
- Risk support: `20`
- Safety support: `0`

Removed preview:

```diff
- 		goto err_set_name;
- 
- 	udata = NULL;
- 	if (udlen) {
```

Added preview:

```diff
+ 		goto err_set_alloc_name;
+ 			goto err_set_alloc_name;
```

#### Window `B3`

- Header: `@@ -176,45 +176,13 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name); [changed-window 5]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `2`
- Safety support: `1`

Removed preview:

```diff
- 		udata = set->data + size;
- 		nla_memcpy(udata, nla[NFTA_SET_USERDATA], udlen);
```

Added preview:

```diff
+ <empty>
```

---

## Item 5: `manual_evidence_audit::211::1::rpm__bd36c5dc9fb6d90c46fbfed8c2d67516fc571ec8__CVE-2021-3521`

- Pair key: `rpm|bd36c5dc9fb6d90c46fbfed8c2d67516fc571ec8|CVE-2021-3521`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `rpm` / `CVE-2021-3521`
- Changed-line bucket: `26+`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.738336`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `196889::pairctx`
- Detector probability: `0.9623913168907166`

#### Window `A1`

- Header: `@@ -4,69 +4,31 @@     const uint8_t *p = pkts;`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `13`
- Safety support: `11`

Removed preview:

```diff
-     pgpDigParams selfsig = NULL;
-     int i = 0;
-     int alloced = 16; /* plenty for normal cases */
-     struct pgpPkt *all = xmalloc(alloced * sizeof(*all));
```

Added preview:

```diff
+     struct pgpPkt pkt;
+ 	if (decodePkt(p, (pend - p), &pkt))
+ 	    if (pkttype && pkt.tag != pkttype) {
+ 		digp = pgpDigParamsNew(pkt.tag);
```

#### Window `A2`

- Header: `@@ -4,69 +4,31 @@     const uint8_t *p = pkts; [changed-window 3]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `2`
- Safety support: `4`

Removed preview:

```diff
-     int alloced = 16; /* plenty for normal cases */
-     struct pgpPkt *all = xmalloc(alloced * sizeof(*all));
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -4,69 +4,31 @@     const uint8_t *p = pkts; [changed-window 4]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `3`

Removed preview:

```diff
-     struct pgpPkt *all = xmalloc(alloced * sizeof(*all));
```

Added preview:

```diff
+     struct pgpPkt pkt;
```

### Side B

- ID: `247337::pairctx`
- Detector probability: `0.2240554541349411`

#### Window `B1`

- Header: `@@ -4,31 +4,69 @@     const uint8_t *p = pkts;`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `11`
- Safety support: `13`

Removed preview:

```diff
-     struct pgpPkt pkt;
- 	if (decodePkt(p, (pend - p), &pkt))
- 	    if (pkttype && pkt.tag != pkttype) {
- 		digp = pgpDigParamsNew(pkt.tag);
```

Added preview:

```diff
+     pgpDigParams selfsig = NULL;
+     int i = 0;
+     int alloced = 16; /* plenty for normal cases */
+     struct pgpPkt *all = xmalloc(alloced * sizeof(*all));
```

#### Window `B2`

- Header: `@@ -4,31 +4,69 @@     const uint8_t *p = pkts; [changed-window 4]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `4`
- Safety support: `2`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     int alloced = 16; /* plenty for normal cases */
+     struct pgpPkt *all = xmalloc(alloced * sizeof(*all));
```

#### Window `B3`

- Header: `@@ -4,31 +4,69 @@     const uint8_t *p = pkts; [changed-window 5]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `3`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     struct pgpPkt *all = xmalloc(alloced * sizeof(*all));
+     int expect = 0;
```

---

## Item 6: `manual_evidence_audit::307::2::gpac__b03c9f252526bb42fbd1b87b9f5e339c3cf2390a__CVE-2021-40573`

- Pair key: `gpac|b03c9f252526bb42fbd1b87b9f5e339c3cf2390a|CVE-2021-40573`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `gpac` / `CVE-2021-40573`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.998504`
- Probability gap: `0.436267`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `195334::pairctx`
- Detector probability: `0.5467381477355957`

#### Window `A1`

- Header: `@@ -51,8 +50,7 @@ 		extent_count = gf_bs_read_u16(bs);`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_introduces_risk`
- Risk support: `2`
- Safety support: `1`

Removed preview:

```diff
- 			GF_ItemExtentEntry *extent_entry;
- 			GF_SAFEALLOC(extent_entry, GF_ItemExtentEntry);
```

Added preview:

```diff
+ 			GF_ItemExtentEntry *extent_entry = (GF_ItemExtentEntry *)gf_malloc(sizeof(GF_ItemExtentEntry));
```

#### Window `A2`

- Header: `@@ -21,8 +21,7 @@ 	}`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_introduces_risk`
- Risk support: `2`
- Safety support: `1`

Removed preview:

```diff
- 		GF_ItemLocationEntry *location_entry;
- 		GF_SAFEALLOC(location_entry, GF_ItemLocationEntry);
```

Added preview:

```diff
+ 		GF_ItemLocationEntry *location_entry = (GF_ItemLocationEntry *)gf_malloc(sizeof(GF_ItemLocationEntry));
```

#### Window `A3`

- Header: `@@ -51,8 +50,7 @@ 		extent_count = gf_bs_read_u16(bs); [changed-window 2]`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_introduces_risk`
- Risk support: `2`
- Safety support: `1`

Removed preview:

```diff
- 			GF_SAFEALLOC(extent_entry, GF_ItemExtentEntry);
```

Added preview:

```diff
+ 			GF_ItemExtentEntry *extent_entry = (GF_ItemExtentEntry *)gf_malloc(sizeof(GF_ItemExtentEntry));
```

### Side B

- ID: `224728::pairctx`
- Detector probability: `0.11047115176916122`

#### Window `B1`

- Header: `@@ -50,7 +51,8 @@ 		extent_count = gf_bs_read_u16(bs);`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `2`

Removed preview:

```diff
- 			GF_ItemExtentEntry *extent_entry = (GF_ItemExtentEntry *)gf_malloc(sizeof(GF_ItemExtentEntry));
```

Added preview:

```diff
+ 			GF_ItemExtentEntry *extent_entry;
+ 			GF_SAFEALLOC(extent_entry, GF_ItemExtentEntry);
```

#### Window `B2`

- Header: `@@ -21,7 +21,8 @@ 	}`
- Direction labels: `candidate_adds_protection,candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `2`

Removed preview:

```diff
- 		GF_ItemLocationEntry *location_entry = (GF_ItemLocationEntry *)gf_malloc(sizeof(GF_ItemLocationEntry));
```

Added preview:

```diff
+ 		GF_ItemLocationEntry *location_entry;
+ 		GF_SAFEALLOC(location_entry, GF_ItemLocationEntry);
```

#### Window `B3`

- Header: `@@ -50,7 +51,8 @@ 		extent_count = gf_bs_read_u16(bs); [changed-window 1]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `2`

Removed preview:

```diff
- 			GF_ItemExtentEntry *extent_entry = (GF_ItemExtentEntry *)gf_malloc(sizeof(GF_ItemExtentEntry));
```

Added preview:

```diff
+ 			GF_ItemExtentEntry *extent_entry;
```

---

## Item 7: `manual_evidence_audit::211::2::squid__780c4ea1b4c9d2fb41f6962aa6ed73ae57f74b2b__CVE-2021-46784`

- Pair key: `squid|780c4ea1b4c9d2fb41f6962aa6ed73ae57f74b2b|CVE-2021-46784`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `squid` / `CVE-2021-46784`
- Changed-line bucket: `26+`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.036245`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

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

## Item 8: `manual_evidence_audit::211::3::ImageMagick__f221ea0fa3171f0f4fdf74ac9d81b203b9534c23__CVE-2022-32546`

- Pair key: `ImageMagick|f221ea0fa3171f0f4fdf74ac9d81b203b9534c23|CVE-2022-32546`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `ImageMagick` / `CVE-2022-32546`
- Changed-line bucket: `03-05`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.195348`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `195237::pairctx`
- Detector probability: `0.6992544531822205`

#### Window `A1`

- Header: `@@ -150,8 +150,8 @@     /*`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     width=(size_t)CastDoubleToLong(floor(bounds.x2-bounds.x1+0.5));
-     height=(size_t)CastDoubleToLong(floor(bounds.y2-bounds.y1+0.5));
```

Added preview:

```diff
+     width=(size_t) floor(bounds.x2-bounds.x1+0.5);
+     height=(size_t) floor(bounds.y2-bounds.y1+0.5);
```

#### Window `A2`

- Header: `@@ -150,8 +150,8 @@     /* [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk support: `10`
- Safety support: `0`

Removed preview:

```diff
-     width=(size_t)CastDoubleToLong(floor(bounds.x2-bounds.x1+0.5));
-     height=(size_t)CastDoubleToLong(floor(bounds.y2-bounds.y1+0.5));
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -150,8 +150,8 @@     /* [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     height=(size_t)CastDoubleToLong(floor(bounds.y2-bounds.y1+0.5));
```

Added preview:

```diff
+     width=(size_t) floor(bounds.x2-bounds.x1+0.5);
```

### Side B

- ID: `223089::pairctx`
- Detector probability: `0.5039061903953552`

#### Window `B1`

- Header: `@@ -150,8 +150,8 @@     /*`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     width=(size_t) floor(bounds.x2-bounds.x1+0.5);
-     height=(size_t) floor(bounds.y2-bounds.y1+0.5);
```

Added preview:

```diff
+     width=(size_t)CastDoubleToLong(floor(bounds.x2-bounds.x1+0.5));
+     height=(size_t)CastDoubleToLong(floor(bounds.y2-bounds.y1+0.5));
```

#### Window `B2`

- Header: `@@ -150,8 +150,8 @@     /* [changed-window 3]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `10`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     width=(size_t)CastDoubleToLong(floor(bounds.x2-bounds.x1+0.5));
+     height=(size_t)CastDoubleToLong(floor(bounds.y2-bounds.y1+0.5));
```

#### Window `B3`

- Header: `@@ -150,8 +150,8 @@     /* [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     height=(size_t) floor(bounds.y2-bounds.y1+0.5);
```

Added preview:

```diff
+     width=(size_t)CastDoubleToLong(floor(bounds.x2-bounds.x1+0.5));
```

---

## Item 9: `manual_evidence_audit::401::3::cyrus-imapd__621f9e41465b521399f691c241181300fab55995__CVE-2021-32056`

- Pair key: `cyrus-imapd|621f9e41465b521399f691c241181300fab55995|CVE-2021-32056`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `cyrus-imapd` / `CVE-2021-32056`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.117547`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

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

## Item 10: `manual_evidence_audit::503::3::gnutls__d223040e498bd50a4b9e0aa493e78587ae1ed653__CVE-2008-1948`

- Pair key: `gnutls|d223040e498bd50a4b9e0aa493e78587ae1ed653|CVE-2008-1948`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `gnutls` / `CVE-2008-1948`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.99996`
- Probability gap: `0.798648`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

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

## Item 11: `manual_evidence_audit::307::3::tensorflow__698e01511f62a3c185754db78ebce0eee1f0184d__CVE-2021-29614`

- Pair key: `tensorflow|698e01511f62a3c185754db78ebce0eee1f0184d|CVE-2021-29614`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `tensorflow` / `CVE-2021-29614`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.997116`
- Probability gap: `0.025491`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `243619::pairctx`
- Detector probability: `0.272024542093277`

#### Window `A1`

- Header: `@@ -44,14 +44,13 @@     // can copy the memory directly.`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `3`
- Safety support: `1`

Removed preview:

```diff
-         const T* in_data = reinterpret_cast<const T*>(flat_in(i).data());
- 
-         if (flat_in(i).size() > fixed_length) {
-           memcpy(out_data, in_data, fixed_length);
```

Added preview:

```diff
+         const auto to_copy =
+             std::min(flat_in(i).size(), static_cast<size_t>(fixed_length));
+         memcpy(out_data, flat_in(i).data(), to_copy);
+         // Note: increase out_data by width since it's already of type T* so
```

#### Window `A2`

- Header: `@@ -44,14 +44,13 @@     // can copy the memory directly. [changed-window 10]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `4`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+             std::min(flat_in(i).size(), static_cast<size_t>(fixed_length));
+         memcpy(out_data, flat_in(i).data(), to_copy);
```

#### Window `A3`

- Header: `@@ -44,14 +44,13 @@     // can copy the memory directly. [changed-window 9]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `4`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+         const auto to_copy =
+             std::min(flat_in(i).size(), static_cast<size_t>(fixed_length));
```

### Side B

- ID: `196739::pairctx`
- Detector probability: `0.2465333640575409`

#### Window `B1`

- Header: `@@ -44,13 +44,14 @@     // can copy the memory directly.`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `3`

Removed preview:

```diff
-         const auto to_copy =
-             std::min(flat_in(i).size(), static_cast<size_t>(fixed_length));
-         memcpy(out_data, flat_in(i).data(), to_copy);
-         // Note: increase out_data by width since it's already of type T* so
```

Added preview:

```diff
+         const T* in_data = reinterpret_cast<const T*>(flat_in(i).data());
+ 
+         if (flat_in(i).size() > fixed_length) {
+           memcpy(out_data, in_data, fixed_length);
```

#### Window `B2`

- Header: `@@ -44,13 +44,14 @@     // can copy the memory directly. [changed-window 2]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `4`
- Safety support: `1`

Removed preview:

```diff
-             std::min(flat_in(i).size(), static_cast<size_t>(fixed_length));
-         memcpy(out_data, flat_in(i).data(), to_copy);
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -44,13 +44,14 @@     // can copy the memory directly. [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk support: `4`
- Safety support: `0`

Removed preview:

```diff
-         const auto to_copy =
-             std::min(flat_in(i).size(), static_cast<size_t>(fixed_length));
```

Added preview:

```diff
+ <empty>
```

---

## Item 12: `manual_evidence_audit::307::4::GIMP__22e2571c25425f225abdb11a566cc281fca6f366__CVE-2017-17786`

- Pair key: `GIMP|22e2571c25425f225abdb11a566cc281fca6f366|CVE-2017-17786`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `GIMP` / `CVE-2017-17786`
- Changed-line bucket: `03-05`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.986543`
- Probability gap: `0.742757`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `215994::pairctx`
- Detector probability: `0.847967803478241`

#### Window `A1`

- Header: `@@ -143,8 +143,7 @@              info.bpp != 24 && info.bpp != 32)      ||`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-             (info.bpp == 16 && info.alphaBits != 1 &&
-              info.alphaBits != 0)                   ||
```

Added preview:

```diff
+             (info.bpp == 16 && info.alphaBits != 1) ||
```

#### Window `A2`

- Header: `@@ -143,8 +143,7 @@              info.bpp != 24 && info.bpp != 32)      || [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-              info.alphaBits != 0)                   ||
```

Added preview:

```diff
+             (info.bpp == 16 && info.alphaBits != 1) ||
```

#### Window `A3`

- Header: `@@ -143,8 +143,7 @@              info.bpp != 24 && info.bpp != 32)      || [changed-window 1]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-             (info.bpp == 16 && info.alphaBits != 1 &&
-              info.alphaBits != 0)                   ||
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `498639::pairctx`
- Detector probability: `0.10521053522825241`

#### Window `B1`

- Header: `@@ -143,7 +143,8 @@              info.bpp != 24 && info.bpp != 32)      ||`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-             (info.bpp == 16 && info.alphaBits != 1) ||
```

Added preview:

```diff
+             (info.bpp == 16 && info.alphaBits != 1 &&
+              info.alphaBits != 0)                   ||
```

#### Window `B2`

- Header: `@@ -143,7 +143,8 @@              info.bpp != 24 && info.bpp != 32)      || [changed-window 1]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-             (info.bpp == 16 && info.alphaBits != 1) ||
```

Added preview:

```diff
+             (info.bpp == 16 && info.alphaBits != 1 &&
```

#### Window `B3`

- Header: `@@ -143,7 +143,8 @@              info.bpp != 24 && info.bpp != 32)      || [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+             (info.bpp == 16 && info.alphaBits != 1 &&
+              info.alphaBits != 0)                   ||
```

---

## Item 13: `manual_evidence_audit::123::2::libxml2__bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2__CVE-2021-3517`

- Pair key: `libxml2|bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2|CVE-2021-3517`
- Source pool: `project_holdout_top5_v1`
- Project/CVE: `libxml2` / `CVE-2021-3517`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.922736`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `200381::pairctx`
- Detector probability: `0.9626730680465698`

#### Window `A1`

- Header: `@@ -106,25 +106,11 @@ 	    } else {`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- 		 * It must match either:
- 		 *   110xxxxx 10xxxxxx
- 		 *   1110xxxx 10xxxxxx 10xxxxxx
- 		 *   11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
```

Added preview:

```diff
+ 		if (*cur < 0xC0) {
```

#### Window `A2`

- Header: `@@ -106,25 +106,11 @@ 	    } else { [changed-window 13]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 		    (((cur[0] & 0xE0) == 0xE0) && ((cur[2] & 0xC0) != 0x80)) ||
- 		    (((cur[0] & 0xF0) == 0xF0) && ((cur[3] & 0xC0) != 0x80)) ||
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -106,25 +106,11 @@ 	    } else { [changed-window 14]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 		    (((cur[0] & 0xF0) == 0xF0) && ((cur[3] & 0xC0) != 0x80)) ||
- 		    (((cur[0] & 0xF8) == 0xF8))) {
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `302155::pairctx`
- Detector probability: `0.03993731737136841`

#### Window `B1`

- Header: `@@ -106,11 +106,25 @@ 	    } else {`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- 		if (*cur < 0xC0) {
```

Added preview:

```diff
+ 		 * It must match either:
+ 		 *   110xxxxx 10xxxxxx
+ 		 *   1110xxxx 10xxxxxx 10xxxxxx
+ 		 *   11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
```

#### Window `B2`

- Header: `@@ -106,11 +106,25 @@ 	    } else { [changed-window 14]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 		    (((cur[0] & 0xE0) == 0xE0) && ((cur[2] & 0xC0) != 0x80)) ||
+ 		    (((cur[0] & 0xF0) == 0xF0) && ((cur[3] & 0xC0) != 0x80)) ||
```

#### Window `B3`

- Header: `@@ -106,11 +106,25 @@ 	    } else { [changed-window 15]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 		    (((cur[0] & 0xF0) == 0xF0) && ((cur[3] & 0xC0) != 0x80)) ||
+ 		    (((cur[0] & 0xF8) == 0xF8))) {
```

---

## Item 14: `manual_evidence_audit::7::2::nanopb__aa9d0d1ca78d6adec3adfeecf3a706c7f9df81f2__CVE-2020-5235`

- Pair key: `nanopb|aa9d0d1ca78d6adec3adfeecf3a706c7f9df81f2|CVE-2020-5235`
- Source pool: `project_holdout_top5_v1`
- Project/CVE: `nanopb` / `CVE-2020-5235`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.673998`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `197114::pairctx`
- Detector probability: `0.8980534672737122`

#### Window `A1`

- Header: `@@ -106,11 +106,11 @@                 if (*size == PB_SIZE_MAX)`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
-                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, (size_t)(*size + 1)))
-                 pItem = *(char**)iter->pData + iter->pos->data_size * (*size);
-                 (*size)++;
```

Added preview:

```diff
+                 (*size)++;
+                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, *size))
+                 pItem = *(char**)iter->pData + iter->pos->data_size * (*size - 1);
```

#### Window `A2`

- Header: `@@ -106,11 +106,11 @@                 if (*size == PB_SIZE_MAX) [changed-window 3]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
-                 pItem = *(char**)iter->pData + iter->pos->data_size * (*size);
```

Added preview:

```diff
+                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, *size))
```

#### Window `A3`

- Header: `@@ -106,11 +106,11 @@                 if (*size == PB_SIZE_MAX) [changed-window 1]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `3`
- Safety support: `1`

Removed preview:

```diff
-                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, (size_t)(*size + 1)))
```

Added preview:

```diff
+                 (*size)++;
```

### Side B

- ID: `252505::pairctx`
- Detector probability: `0.2240554541349411`

#### Window `B1`

- Header: `@@ -106,11 +106,11 @@                 if (*size == PB_SIZE_MAX)`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
-                 (*size)++;
-                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, *size))
-                 pItem = *(char**)iter->pData + iter->pos->data_size * (*size - 1);
```

Added preview:

```diff
+                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, (size_t)(*size + 1)))
+                 pItem = *(char**)iter->pData + iter->pos->data_size * (*size);
+                 (*size)++;
```

#### Window `B2`

- Header: `@@ -106,11 +106,11 @@                 if (*size == PB_SIZE_MAX) [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
-                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, *size))
```

Added preview:

```diff
+                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, (size_t)(*size + 1)))
```

#### Window `B3`

- Header: `@@ -106,11 +106,11 @@                 if (*size == PB_SIZE_MAX) [changed-window 3]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `2`

Removed preview:

```diff
-                 pItem = *(char**)iter->pData + iter->pos->data_size * (*size - 1);
```

Added preview:

```diff
+                 if (!allocate_field(stream, iter->pData, iter->pos->data_size, (size_t)(*size + 1)))
```

---

## Item 15: `manual_evidence_audit::13::2::squid__5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9__CVE-2021-46784`

- Pair key: `squid|5e2ea2b13bd98f53e29964ca26bb0d602a8a12b9|CVE-2021-46784`
- Source pool: `project_holdout_top5_v1`
- Project/CVE: `squid` / `CVE-2021-46784`
- Changed-line bucket: `26+`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `1.0`
- Probability gap: `0.191501`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

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

## Item 16: `manual_evidence_audit::42::4::furnace__0eb02422d5161767e9983bdaa5c429762d3477ce__CVE-2022-1289`

- Pair key: `furnace|0eb02422d5161767e9983bdaa5c429762d3477ce|CVE-2022-1289`
- Source pool: `project_holdout_top5_v1`
- Project/CVE: `furnace` / `CVE-2022-1289`
- Changed-line bucket: `26+`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.999977`
- Probability gap: `0.472775`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `196841::pairctx`
- Detector probability: `0.9260365962982178`

#### Window `A1`

- Header: `@@ -195,33 +195,27 @@           sprintf(id,"..##PE%d_%d_%d",k,i,j);`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `3`
- Safety support: `1`

Removed preview:

```diff
-           if (pat->data[i][index]>0xff) {
-             sprintf(id,"??##PE%d_%d_%d",k,i,j);
-             const unsigned char data=pat->data[i][index];
-             sprintf(id,"%.2X##PE%d_%d_%d",data,k,i,j);
```

Added preview:

```diff
+           sprintf(id,"%.2X##PE%d_%d_%d",pat->data[i][index],k,i,j);
+           if (pat->data[i][index]<0x10) {
+             ImGui::PushStyleColor(ImGuiCol_Text,uiColors[fxColors[pat->data[i][index]]]);
+           } else if (pat->data[i][index]<0x20) {
```

#### Window `A2`

- Header: `@@ -195,33 +195,27 @@           sprintf(id,"..##PE%d_%d_%d",k,i,j); [changed-window 12]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `3`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+           } else if (pat->data[i][index]<0x90) {
+             ImGui::PushStyleColor(ImGuiCol_Text,uiColors[GUI_COLOR_PATTERN_EFFECT_INVALID]);
```

#### Window `A3`

- Header: `@@ -195,33 +195,27 @@           sprintf(id,"..##PE%d_%d_%d",k,i,j); [changed-window 13]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `3`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+             ImGui::PushStyleColor(ImGuiCol_Text,uiColors[GUI_COLOR_PATTERN_EFFECT_INVALID]);
+           } else if (pat->data[i][index]<0xa0) {
```

### Side B

- ID: `246237::pairctx`
- Detector probability: `0.4532618522644043`

#### Window `B1`

- Header: `@@ -195,27 +195,33 @@           sprintf(id,"..##PE%d_%d_%d",k,i,j);`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `3`

Removed preview:

```diff
-           sprintf(id,"%.2X##PE%d_%d_%d",pat->data[i][index],k,i,j);
-           if (pat->data[i][index]<0x10) {
-             ImGui::PushStyleColor(ImGuiCol_Text,uiColors[fxColors[pat->data[i][index]]]);
-           } else if (pat->data[i][index]<0x20) {
```

Added preview:

```diff
+           if (pat->data[i][index]>0xff) {
+             sprintf(id,"??##PE%d_%d_%d",k,i,j);
+             const unsigned char data=pat->data[i][index];
+             sprintf(id,"%.2X##PE%d_%d_%d",data,k,i,j);
```

#### Window `B2`

- Header: `@@ -195,27 +195,33 @@           sprintf(id,"..##PE%d_%d_%d",k,i,j); [changed-window 20]`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
-             ImGui::PushStyleColor(ImGuiCol_Text,uiColors[extFxColors[pat->data[i][index]-0xe0]]);
```

Added preview:

```diff
+             sprintf(id,"??##PE%d_%d_%d",k,i,j);
```

#### Window `B3`

- Header: `@@ -195,27 +195,33 @@           sprintf(id,"..##PE%d_%d_%d",k,i,j); [changed-window 10]`
- Direction labels: `candidate_removes_protection`
- Risk support: `3`
- Safety support: `0`

Removed preview:

```diff
-           } else if (pat->data[i][index]<0x90) {
-             ImGui::PushStyleColor(ImGuiCol_Text,uiColors[GUI_COLOR_PATTERN_EFFECT_INVALID]);
```

Added preview:

```diff
+ <empty>
```

---

## Item 17: `manual_evidence_audit::13::4::linux-2.6__8a0a9bd4db63bc45e3017bedeafbd88d0eb84d02__CVE-2009-3238`

- Pair key: `linux-2.6|8a0a9bd4db63bc45e3017bedeafbd88d0eb84d02|CVE-2009-3238`
- Source pool: `project_holdout_top5_v1`
- Project/CVE: `linux-2.6` / `CVE-2009-3238`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.667906`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

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

## Item 18: `manual_evidence_audit::7::4::linux-2.6__8faece5f906725c10e7a1f6caf84452abadbdc7b__CVE-2009-0787`

- Pair key: `linux-2.6|8faece5f906725c10e7a1f6caf84452abadbdc7b|CVE-2009-0787`
- Source pool: `project_holdout_top5_v1`
- Project/CVE: `linux-2.6` / `CVE-2009-0787`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.999446`
- Probability gap: `0.296582`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `490193::pairctx`
- Detector probability: `0.8740772008895874`

#### Window `A1`

- Header: `@@ -1,11 +1,10 @@-ecryptfs_write_metadata_to_contents(struct ecryptfs_crypt_stat *crypt_stat,`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `3`

Removed preview:

```diff
- 				    struct dentry *ecryptfs_dentry,
- 				    char *virt)
- 				  0, crypt_stat->num_header_bytes_at_front);
```

Added preview:

```diff
+ ecryptfs_write_metadata_to_contents(struct dentry *ecryptfs_dentry,
+ 				    char *virt, size_t virt_len)
+ 				  0, virt_len);
```

#### Window `A2`

- Header: `@@ -1,11 +1,10 @@-ecryptfs_write_metadata_to_contents(struct ecryptfs_crypt_stat *crypt_stat, [changed-window 3]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ ecryptfs_write_metadata_to_contents(struct dentry *ecryptfs_dentry,
+ 				    char *virt, size_t virt_len)
```

#### Window `A3`

- Header: `@@ -1,11 +1,10 @@-ecryptfs_write_metadata_to_contents(struct ecryptfs_crypt_stat *crypt_stat, [changed-window 4]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- 				  0, crypt_stat->num_header_bytes_at_front);
```

Added preview:

```diff
+ 				    char *virt, size_t virt_len)
```

### Side B

- ID: `215467::pairctx`
- Detector probability: `0.5774953961372375`

#### Window `B1`

- Header: `@@ -1,10 +1,11 @@-ecryptfs_write_metadata_to_contents(struct dentry *ecryptfs_dentry,`
- Direction labels: `candidate_removes_protection`
- Risk support: `3`
- Safety support: `0`

Removed preview:

```diff
- 				    char *virt, size_t virt_len)
- 				  0, virt_len);
```

Added preview:

```diff
+ ecryptfs_write_metadata_to_contents(struct ecryptfs_crypt_stat *crypt_stat,
+ 				    struct dentry *ecryptfs_dentry,
+ 				    char *virt)
+ 				  0, crypt_stat->num_header_bytes_at_front);
```

#### Window `B2`

- Header: `@@ -1,10 +1,11 @@-ecryptfs_write_metadata_to_contents(struct dentry *ecryptfs_dentry, [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- 				    char *virt, size_t virt_len)
```

Added preview:

```diff
+ ecryptfs_write_metadata_to_contents(struct ecryptfs_crypt_stat *crypt_stat,
```

#### Window `B3`

- Header: `@@ -1,10 +1,11 @@-ecryptfs_write_metadata_to_contents(struct dentry *ecryptfs_dentry, [changed-window 5]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 				  0, virt_len);
```

Added preview:

```diff
+ 				  0, crypt_stat->num_header_bytes_at_front);
```

---

## Item 19: `manual_evidence_audit::7::5::linux__04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5__CVE-2022-1055`

- Pair key: `linux|04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5|CVE-2022-1055`
- Source pool: `project_holdout_top5_v1`
- Project/CVE: `linux` / `CVE-2022-1055`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.993235`
- Probability gap: `0.144419`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `212414::pairctx`
- Detector probability: `0.729519784450531`

#### Window `A1`

- Header: `@@ -10,9 +10,9 @@ 	bool prio_allocate;`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- 	struct Qdisc *q;
- 	struct tcf_chain *chain;
```

Added preview:

```diff
+ 	struct Qdisc *q = NULL;
+ 	struct tcf_chain *chain = NULL;
```

#### Window `A2`

- Header: `@@ -41,8 +41,6 @@ 	tp = NULL;`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- 	q = NULL;
- 	chain = NULL;
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -10,9 +10,9 @@ 	bool prio_allocate; [changed-window 3]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 	struct tcf_chain *chain;
```

Added preview:

```diff
+ 	struct tcf_chain *chain = NULL;
```

### Side B

- ID: `459107::pairctx`
- Detector probability: `0.5851011276245117`

#### Window `B1`

- Header: `@@ -10,9 +10,9 @@ 	bool prio_allocate;`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- 	struct Qdisc *q = NULL;
- 	struct tcf_chain *chain = NULL;
```

Added preview:

```diff
+ 	struct Qdisc *q;
+ 	struct tcf_chain *chain;
```

#### Window `B2`

- Header: `@@ -41,6 +41,8 @@ 	tp = NULL;`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	q = NULL;
+ 	chain = NULL;
```

#### Window `B3`

- Header: `@@ -10,9 +10,9 @@ 	bool prio_allocate; [changed-window 3]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 	struct tcf_chain *chain = NULL;
```

Added preview:

```diff
+ 	struct tcf_chain *chain;
```

---

## Item 20: `manual_evidence_audit::123::5::tensorflow__801c1c6be5324219689c98e1bd3e0ca365ee834d__CVE-2021-29588`

- Pair key: `tensorflow|801c1c6be5324219689c98e1bd3e0ca365ee834d|CVE-2021-29588`
- Source pool: `project_holdout_top5_v1`
- Project/CVE: `tensorflow` / `CVE-2021-29588`
- Changed-line bucket: `03-05`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.999417`
- Probability gap: `0.973571`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `197892::pairctx`
- Detector probability: `0.9843062162399292`

#### Window `A1`

- Header: `@@ -26,10 +26,6 @@           : nullptr;`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 
-   // Prevent divisions by 0
-   TF_LITE_ENSURE(context, params->stride_height > 0);
-   TF_LITE_ENSURE(context, params->stride_width > 0);
```

Added preview:

```diff
+ <empty>
```

#### Window `A2`

- Header: `@@ -26,10 +26,6 @@           : nullptr; [changed-window 3]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-   TF_LITE_ENSURE(context, params->stride_height > 0);
-   TF_LITE_ENSURE(context, params->stride_width > 0);
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -26,10 +26,6 @@           : nullptr; [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-   // Prevent divisions by 0
-   TF_LITE_ENSURE(context, params->stride_height > 0);
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `265428::pairctx`
- Detector probability: `0.01073516346514225`

#### Window `B1`

- Header: `@@ -26,6 +26,10 @@           : nullptr;`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 
+   // Prevent divisions by 0
+   TF_LITE_ENSURE(context, params->stride_height > 0);
+   TF_LITE_ENSURE(context, params->stride_width > 0);
```

#### Window `B2`

- Header: `@@ -26,6 +26,10 @@           : nullptr; [changed-window 3]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+   TF_LITE_ENSURE(context, params->stride_height > 0);
+   TF_LITE_ENSURE(context, params->stride_width > 0);
```

#### Window `B3`

- Header: `@@ -26,6 +26,10 @@           : nullptr; [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+   // Prevent divisions by 0
+   TF_LITE_ENSURE(context, params->stride_height > 0);
```

---

## Item 21: `manual_evidence_audit::99::6::linux__505d9dcb0f7ddf9d075e729523a33d38642ae680__CVE-2021-3744`

- Pair key: `linux|505d9dcb0f7ddf9d075e729523a33d38642ae680|CVE-2021-3744`
- Source pool: `rank6_10_v1`
- Project/CVE: `linux` / `CVE-2021-3744`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.999964`
- Probability gap: `0.387118`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `197135::pairctx`
- Detector probability: `0.43782347440719604`

#### Window `A1`

- Header: `@@ -245,19 +245,17 @@ 		ret = ccp_init_dm_workarea(&tag, cmd_q, authsize,`
- Direction labels: `candidate_removes_risk`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 			goto e_final_wa;
- 		if (ret) {
- 			ccp_dm_free(&tag);
- 			goto e_final_wa;
```

Added preview:

```diff
+ 			goto e_tag;
+ 		if (ret)
+ 			goto e_tag;
+ e_tag:
```

#### Window `A2`

- Header: `@@ -245,19 +245,17 @@ 		ret = ccp_init_dm_workarea(&tag, cmd_q, authsize, [changed-window 4]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- 			ccp_dm_free(&tag);
- 			goto e_final_wa;
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -245,19 +245,17 @@ 		ret = ccp_init_dm_workarea(&tag, cmd_q, authsize, [changed-window 3]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- 		if (ret) {
- 			ccp_dm_free(&tag);
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `253699::pairctx`
- Detector probability: `0.05070536211133003`

#### Window `B1`

- Header: `@@ -245,17 +245,19 @@ 		ret = ccp_init_dm_workarea(&tag, cmd_q, authsize,`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 			goto e_tag;
- 		if (ret)
- 			goto e_tag;
- e_tag:
```

Added preview:

```diff
+ 			goto e_final_wa;
+ 		if (ret) {
+ 			ccp_dm_free(&tag);
+ 			goto e_final_wa;
```

#### Window `B2`

- Header: `@@ -245,17 +245,19 @@ 		ret = ccp_init_dm_workarea(&tag, cmd_q, authsize, [changed-window 6]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 			ccp_dm_free(&tag);
+ 			goto e_final_wa;
```

#### Window `B3`

- Header: `@@ -245,17 +245,19 @@ 		ret = ccp_init_dm_workarea(&tag, cmd_q, authsize, [changed-window 5]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 		if (ret) {
+ 			ccp_dm_free(&tag);
```

---

## Item 22: `manual_evidence_audit::13::6::linux__8423f0b6d513b259fdab9c9bf4aaa6188d054c2d__CVE-2022-3303`

- Pair key: `linux|8423f0b6d513b259fdab9c9bf4aaa6188d054c2d|CVE-2022-3303`
- Source pool: `rank6_10_v1`
- Project/CVE: `linux` / `CVE-2022-3303`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.999972`
- Probability gap: `0.180786`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `289293::pairctx`
- Detector probability: `0.622459352016449`

#### Window `A1`

- Header: `@@ -13,14 +13,14 @@ 		runtime = substream->runtime;`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 		err = snd_pcm_oss_make_ready(substream);
- 		if (err < 0)
- 			return err;
```

Added preview:

```diff
+ 		err = snd_pcm_oss_make_ready_locked(substream);
+ 		if (err < 0)
+ 			goto unlock;
```

#### Window `A2`

- Header: `@@ -13,14 +13,14 @@ 		runtime = substream->runtime; [changed-window 3]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 			return err;
```

Added preview:

```diff
+ 		err = snd_pcm_oss_make_ready_locked(substream);
```

#### Window `A3`

- Header: `@@ -13,14 +13,14 @@ 		runtime = substream->runtime; [changed-window 4]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `3`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 		err = snd_pcm_oss_make_ready_locked(substream);
+ 		if (err < 0)
```

### Side B

- ID: `199159::pairctx`
- Detector probability: `0.44167301058769226`

#### Window `B1`

- Header: `@@ -13,14 +13,14 @@ 		runtime = substream->runtime;`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 		err = snd_pcm_oss_make_ready_locked(substream);
- 		if (err < 0)
- 			goto unlock;
```

Added preview:

```diff
+ 		err = snd_pcm_oss_make_ready(substream);
+ 		if (err < 0)
+ 			return err;
```

#### Window `B2`

- Header: `@@ -13,14 +13,14 @@ 		runtime = substream->runtime; [changed-window 3]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 		err = snd_pcm_oss_make_ready_locked(substream);
```

Added preview:

```diff
+ 			return err;
```

#### Window `B3`

- Header: `@@ -13,14 +13,14 @@ 		runtime = substream->runtime; [changed-window 4]`
- Direction labels: `candidate_removes_protection`
- Risk support: `3`
- Safety support: `0`

Removed preview:

```diff
- 		err = snd_pcm_oss_make_ready_locked(substream);
- 		if (err < 0)
```

Added preview:

```diff
+ <empty>
```

---

## Item 23: `manual_evidence_audit::42::7::libyang__298b30ea4ebee137226acf9bb38678bd82704582__CVE-2021-28903`

- Pair key: `libyang|298b30ea4ebee137226acf9bb38678bd82704582|CVE-2021-28903`
- Source pool: `rank6_10_v1`
- Project/CVE: `libyang` / `CVE-2021-28903`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.993995`
- Probability gap: `0.703064`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `204825::pairctx`
- Detector probability: `0.729519784450531`

#### Window `A1`

- Header: `@@ -1,5 +1,4 @@-lyxml_parse_elem(struct ly_ctx *ctx, const char *data, unsigned int *len, struct lyxml_elem *parent, int options,`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
-                  int bt_count)
```

Added preview:

```diff
+ lyxml_parse_elem(struct ly_ctx *ctx, const char *data, unsigned int *len, struct lyxml_elem *parent, int options)
```

#### Window `A2`

- Header: `@@ -202,7 +196,7 @@                     lyxml_add_child(ctx, elem, child);`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-                 child = lyxml_parse_elem(ctx, c, &size, elem, options, bt_count + 1);
```

Added preview:

```diff
+                 child = lyxml_parse_elem(ctx, c, &size, elem, options);
```

#### Window `A3`

- Header: `@@ -1,5 +1,4 @@-lyxml_parse_elem(struct ly_ctx *ctx, const char *data, unsigned int *len, struct lyxml_elem *parent, int options, [changed-window all]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
-                  int bt_count)
```

Added preview:

```diff
+ lyxml_parse_elem(struct ly_ctx *ctx, const char *data, unsigned int *len, struct lyxml_elem *parent, int options)
```

### Side B

- ID: `366009::pairctx`
- Detector probability: `0.026455773040652275`

#### Window `B1`

- Header: `@@ -1,4 +1,5 @@-lyxml_parse_elem(struct ly_ctx *ctx, const char *data, unsigned int *len, struct lyxml_elem *parent, int options)`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ lyxml_parse_elem(struct ly_ctx *ctx, const char *data, unsigned int *len, struct lyxml_elem *parent, int options,
+                  int bt_count)
```

#### Window `B2`

- Header: `@@ -196,7 +202,7 @@                     lyxml_add_child(ctx, elem, child);`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-                 child = lyxml_parse_elem(ctx, c, &size, elem, options);
```

Added preview:

```diff
+                 child = lyxml_parse_elem(ctx, c, &size, elem, options, bt_count + 1);
```

#### Window `B3`

- Header: `@@ -1,4 +1,5 @@-lyxml_parse_elem(struct ly_ctx *ctx, const char *data, unsigned int *len, struct lyxml_elem *parent, int options) [changed-window all]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ lyxml_parse_elem(struct ly_ctx *ctx, const char *data, unsigned int *len, struct lyxml_elem *parent, int options,
+                  int bt_count)
```

---

## Item 24: `manual_evidence_audit::123::7::linux__d80b64ff297e40c2b6f7d7abc1b3eba70d22a068__CVE-2020-12768`

- Pair key: `linux|d80b64ff297e40c2b6f7d7abc1b3eba70d22a068|CVE-2020-12768`
- Source pool: `rank6_10_v1`
- Project/CVE: `linux` / `CVE-2020-12768`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `1.0`
- Probability gap: `0.728616`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `432423::pairctx`
- Detector probability: `0.8652240633964539`

#### Window `A1`

- Header: `@@ -1,32 +1,31 @@ static int svm_cpu_init(int cpu)`
- Direction labels: `candidate_removes_protection,candidate_introduces_risk`
- Risk support: `8`
- Safety support: `0`

Removed preview:

```diff
- 	int r;
- 	r = -ENOMEM;
- 		goto err_1;
- 		r = -ENOMEM;
```

Added preview:

```diff
+ 		goto free_cpu_data;
+ 			goto free_save_area;
+ free_save_area:
+ 	__free_page(sd->save_area);
```

#### Window `A2`

- Header: `@@ -1,32 +1,31 @@ static int svm_cpu_init(int cpu) [changed-window 4]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- 		r = -ENOMEM;
```

Added preview:

```diff
+ 		goto free_cpu_data;
```

#### Window `A3`

- Header: `@@ -1,32 +1,31 @@ static int svm_cpu_init(int cpu) [changed-window 9]`
- Direction labels: `candidate_introduces_risk`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ free_save_area:
+ 	__free_page(sd->save_area);
```

### Side B

- ID: `210296::pairctx`
- Detector probability: `0.13660839200019836`

#### Window `B1`

- Header: `@@ -1,31 +1,32 @@ static int svm_cpu_init(int cpu)`
- Direction labels: `candidate_adds_protection,candidate_removes_risk`
- Risk support: `0`
- Safety support: `8`

Removed preview:

```diff
- 		goto free_cpu_data;
- 			goto free_save_area;
- free_save_area:
- 	__free_page(sd->save_area);
```

Added preview:

```diff
+ 	int r;
+ 	r = -ENOMEM;
+ 		goto err_1;
+ 		r = -ENOMEM;
```

#### Window `B2`

- Header: `@@ -1,31 +1,32 @@ static int svm_cpu_init(int cpu) [changed-window 5]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- 			goto free_save_area;
```

Added preview:

```diff
+ 		r = -ENOMEM;
```

#### Window `B3`

- Header: `@@ -1,31 +1,32 @@ static int svm_cpu_init(int cpu) [changed-window 2]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- 		goto free_cpu_data;
```

Added preview:

```diff
+ 	r = -ENOMEM;
```

---

## Item 25: `manual_evidence_audit::7::7::redis__789f10156009b404950ad717642a9496ed887083__CVE-2021-29478`

- Pair key: `redis|789f10156009b404950ad717642a9496ed887083|CVE-2021-29478`
- Source pool: `rank6_10_v1`
- Project/CVE: `redis` / `CVE-2021-29478`
- Changed-line bucket: `00-02`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.903472`
- Probability gap: `0.498855`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `199227::pairctx`
- Detector probability: `0.7866228222846985`

#### Window `A1`

- Header: `@@ -1,3 +1,3 @@ size_t intsetBlobLen(intset *is) {`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
-     return sizeof(intset)+(size_t)intrev32ifbe(is->length)*intrev32ifbe(is->encoding);
```

Added preview:

```diff
+     return sizeof(intset)+intrev32ifbe(is->length)*intrev32ifbe(is->encoding);
```

#### Window `A2`

- Header: `@@ -1,3 +1,3 @@ size_t intsetBlobLen(intset *is) { [changed-window all]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
-     return sizeof(intset)+(size_t)intrev32ifbe(is->length)*intrev32ifbe(is->encoding);
```

Added preview:

```diff
+     return sizeof(intset)+intrev32ifbe(is->length)*intrev32ifbe(is->encoding);
```

### Side B

- ID: `290629::pairctx`
- Detector probability: `0.28776782751083374`

#### Window `B1`

- Header: `@@ -1,3 +1,3 @@ size_t intsetBlobLen(intset *is) {`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
-     return sizeof(intset)+intrev32ifbe(is->length)*intrev32ifbe(is->encoding);
```

Added preview:

```diff
+     return sizeof(intset)+(size_t)intrev32ifbe(is->length)*intrev32ifbe(is->encoding);
```

#### Window `B2`

- Header: `@@ -1,3 +1,3 @@ size_t intsetBlobLen(intset *is) { [changed-window all]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
-     return sizeof(intset)+intrev32ifbe(is->length)*intrev32ifbe(is->encoding);
```

Added preview:

```diff
+     return sizeof(intset)+(size_t)intrev32ifbe(is->length)*intrev32ifbe(is->encoding);
```

---

## Item 26: `manual_evidence_audit::99::7::src__79a034b4aed29e965f45a13409268290c9910043__CVE-2020-35679`

- Pair key: `src|79a034b4aed29e965f45a13409268290c9910043|CVE-2020-35679`
- Source pool: `rank6_10_v1`
- Project/CVE: `src` / `CVE-2020-35679`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.999921`
- Probability gap: `0.882031`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `213469::pairctx`
- Detector probability: `0.9284088015556335`

#### Window `A1`

- Header: `@@ -12,11 +11,7 @@ 	if (regcomp(&preg, pattern, cflags) != 0)`
- Direction labels: `candidate_removes_risk`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 	ret = regexec(&preg, string, 0, NULL, 0);
- 
- 	regfree(&preg);
- 
```

Added preview:

```diff
+ 	if (regexec(&preg, string, 0, NULL, 0) != 0)
```

#### Window `A2`

- Header: `@@ -12,11 +11,7 @@ 	if (regcomp(&preg, pattern, cflags) != 0) [changed-window 2]`
- Direction labels: `candidate_removes_risk`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 
- 	regfree(&preg);
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -12,11 +11,7 @@ 	if (regcomp(&preg, pattern, cflags) != 0) [changed-window 3]`
- Direction labels: `candidate_removes_risk`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 	regfree(&preg);
- 
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `468895::pairctx`
- Detector probability: `0.046378206461668015`

#### Window `B1`

- Header: `@@ -11,7 +12,11 @@ 	if (regcomp(&preg, pattern, cflags) != 0)`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 	if (regexec(&preg, string, 0, NULL, 0) != 0)
```

Added preview:

```diff
+ 	ret = regexec(&preg, string, 0, NULL, 0);
+ 
+ 	regfree(&preg);
+ 
```

#### Window `B2`

- Header: `@@ -11,7 +12,11 @@ 	if (regcomp(&preg, pattern, cflags) != 0) [changed-window 3]`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 
+ 	regfree(&preg);
```

#### Window `B3`

- Header: `@@ -11,7 +12,11 @@ 	if (regcomp(&preg, pattern, cflags) != 0) [changed-window 4]`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	regfree(&preg);
+ 
```

---

## Item 27: `manual_evidence_audit::42::8::linux__6cd1ed50efd88261298577cd92a14f2768eddeeb__CVE-2020-36558`

- Pair key: `linux|6cd1ed50efd88261298577cd92a14f2768eddeeb|CVE-2020-36558`
- Source pool: `rank6_10_v1`
- Project/CVE: `linux` / `CVE-2020-36558`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.993919`
- Probability gap: `0.906324`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

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

## Item 28: `manual_evidence_audit::13::8::linux__c8c2a057fdc7de1cd16f4baa51425b932a42eb39__CVE-2019-19045`

- Pair key: `linux|c8c2a057fdc7de1cd16f4baa51425b932a42eb39|CVE-2019-19045`
- Source pool: `rank6_10_v1`
- Project/CVE: `linux` / `CVE-2019-19045`
- Changed-line bucket: `03-05`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.999699`
- Probability gap: `0.923784`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `214909::pairctx`
- Detector probability: `0.9453993439674377`

#### Window `A1`

- Header: `@@ -37,10 +37,8 @@ 	}`
- Direction labels: `candidate_removes_risk`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 	if (err) {
- 		kvfree(in);
- 	}
```

Added preview:

```diff
+ 	if (err)
```

#### Window `A2`

- Header: `@@ -37,10 +37,8 @@ 	} [changed-window 1]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `2`
- Safety support: `1`

Removed preview:

```diff
- 	if (err) {
- 		kvfree(in);
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -37,10 +37,8 @@ 	} [changed-window 2]`
- Direction labels: `candidate_adds_protection,candidate_removes_risk`
- Risk support: `0`
- Safety support: `3`

Removed preview:

```diff
- 		kvfree(in);
```

Added preview:

```diff
+ 	if (err)
```

### Side B

- ID: `481267::pairctx`
- Detector probability: `0.02161533571779728`

#### Window `B1`

- Header: `@@ -37,8 +37,10 @@ 	}`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 	if (err)
```

Added preview:

```diff
+ 	if (err) {
+ 		kvfree(in);
+ 	}
```

#### Window `B2`

- Header: `@@ -37,8 +37,10 @@ 	} [changed-window 2]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `2`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	if (err) {
+ 		kvfree(in);
```

#### Window `B3`

- Header: `@@ -37,8 +37,10 @@ 	} [changed-window 3]`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 		kvfree(in);
+ 	}
```

---

## Item 29: `manual_evidence_audit::7::8::znc__a4a5aeeb17d32937d8c7d743dae9a4cc755ce773__CVE-2018-14056`

- Pair key: `znc|a4a5aeeb17d32937d8c7d743dae9a4cc755ce773|CVE-2018-14056`
- Source pool: `rank6_10_v1`
- Project/CVE: `znc` / `CVE-2018-14056`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.902225`
- Probability gap: `0.640104`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `197927::pairctx`
- Detector probability: `0.9326989054679871`

#### Window `A1`

- Header: `@@ -1,13 +1,11 @@ CString CWebSock::GetSkinPath(const CString& sSkinName) {`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     const CString sSkin = sSkinName.Replace_n("/", "_").Replace_n(".", "_");
- 
-     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkin;
-         sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkin;
```

Added preview:

```diff
+     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkinName;
+         sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkinName;
+             sRet = CString(_SKINDIR_) + "/" + sSkinName;
```

#### Window `A2`

- Header: `@@ -1,13 +1,11 @@ CString CWebSock::GetSkinPath(const CString& sSkinName) { [changed-window 3]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkin;
```

Added preview:

```diff
+     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkinName;
```

#### Window `A3`

- Header: `@@ -1,13 +1,11 @@ CString CWebSock::GetSkinPath(const CString& sSkinName) { [changed-window 4]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkin;
```

Added preview:

```diff
+     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkinName;
```

### Side B

- ID: `265791::pairctx`
- Detector probability: `0.2925952970981598`

#### Window `B1`

- Header: `@@ -1,11 +1,13 @@ CString CWebSock::GetSkinPath(const CString& sSkinName) {`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkinName;
-         sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkinName;
-             sRet = CString(_SKINDIR_) + "/" + sSkinName;
```

Added preview:

```diff
+     const CString sSkin = sSkinName.Replace_n("/", "_").Replace_n(".", "_");
+ 
+     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkin;
+         sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkin;
```

#### Window `B2`

- Header: `@@ -1,11 +1,13 @@ CString CWebSock::GetSkinPath(const CString& sSkinName) { [changed-window 1]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkinName;
```

Added preview:

```diff
+     const CString sSkin = sSkinName.Replace_n("/", "_").Replace_n(".", "_");
```

#### Window `B3`

- Header: `@@ -1,11 +1,13 @@ CString CWebSock::GetSkinPath(const CString& sSkinName) { [changed-window 4]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         sRet = CZNC::Get().GetCurPath() + "/webskins/" + sSkinName;
```

Added preview:

```diff
+     CString sRet = CZNC::Get().GetZNCPath() + "/webskins/" + sSkin;
```

---

## Item 30: `manual_evidence_audit::99::9::keepkey-firmware__e49d45594002d4d3fbc1f03488e6dfc0a0a65836__CVE-2021-31616`

- Pair key: `keepkey-firmware|e49d45594002d4d3fbc1f03488e6dfc0a0a65836|CVE-2021-31616`
- Source pool: `rank6_10_v1`
- Project/CVE: `keepkey-firmware` / `CVE-2021-31616`
- Changed-line bucket: `03-05`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.999816`
- Probability gap: `0.068865`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `220894::pairctx`
- Detector probability: `0.23231014609336853`

#### Window `A1`

- Header: `@@ -4,10 +4,10 @@   // offset = deposit function hash + address + address + uint256`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-   if (msg->has_data_length && len > 0) {
-     return len < 256 ? (uint8_t)len : 0;
```

Added preview:

```diff
+   if (msg->has_data_length && len > 0 && len < 256) {
+     return (uint8_t)len;
```

#### Window `A2`

- Header: `@@ -4,10 +4,10 @@   // offset = deposit function hash + address + address + uint256 [changed-window 1]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
-   if (msg->has_data_length && len > 0) {
```

Added preview:

```diff
+   if (msg->has_data_length && len > 0 && len < 256) {
```

#### Window `A3`

- Header: `@@ -4,10 +4,10 @@   // offset = deposit function hash + address + address + uint256 [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
-     return len < 256 ? (uint8_t)len : 0;
```

Added preview:

```diff
+   if (msg->has_data_length && len > 0 && len < 256) {
```

### Side B

- ID: `195057::pairctx`
- Detector probability: `0.16344544291496277`

#### Window `B1`

- Header: `@@ -4,10 +4,10 @@   // offset = deposit function hash + address + address + uint256`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-   if (msg->has_data_length && len > 0 && len < 256) {
-     return (uint8_t)len;
```

Added preview:

```diff
+   if (msg->has_data_length && len > 0) {
+     return len < 256 ? (uint8_t)len : 0;
```

#### Window `B2`

- Header: `@@ -4,10 +4,10 @@   // offset = deposit function hash + address + address + uint256 [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
-   if (msg->has_data_length && len > 0 && len < 256) {
```

Added preview:

```diff
+   if (msg->has_data_length && len > 0) {
```

#### Window `B3`

- Header: `@@ -4,10 +4,10 @@   // offset = deposit function hash + address + address + uint256 [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
-     return (uint8_t)len;
```

Added preview:

```diff
+   if (msg->has_data_length && len > 0) {
```

---

## Item 31: `manual_evidence_audit::7::9::linux__b2f37aead1b82a770c48b5d583f35ec22aabb61e__CVE-2022-1195`

- Pair key: `linux|b2f37aead1b82a770c48b5d583f35ec22aabb61e|CVE-2022-1195`
- Source pool: `rank6_10_v1`
- Project/CVE: `linux` / `CVE-2022-1195`
- Changed-line bucket: `03-05`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.887729`
- Probability gap: `0.0`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `210636::pairctx`
- Detector probability: `0.4882833957672119`

#### Window `A1`

- Header: `@@ -22,13 +22,13 @@ 	 */`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	ax->tty = NULL;
- 
```

Added preview:

```diff
+ 	ax->tty = NULL;
+ 
```

#### Window `A2`

- Header: `@@ -22,13 +22,13 @@ 	 */ [changed-window 1]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	ax->tty = NULL;
+ 
```

#### Window `A3`

- Header: `@@ -22,13 +22,13 @@ 	 */ [changed-window 2]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 	ax->tty = NULL;
```

Added preview:

```diff
+ 
```

### Side B

- ID: `438876::pairctx`
- Detector probability: `0.4882833957672119`

#### Window `B1`

- Header: `@@ -22,13 +22,13 @@ 	 */`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	ax->tty = NULL;
- 
```

Added preview:

```diff
+ 	ax->tty = NULL;
+ 
```

#### Window `B2`

- Header: `@@ -22,13 +22,13 @@ 	 */ [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 	ax->tty = NULL;
- 
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -22,13 +22,13 @@ 	 */ [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 
```

Added preview:

```diff
+ 	ax->tty = NULL;
```

---

## Item 32: `manual_evidence_audit::42::10::gpac__ebfa346eff05049718f7b80041093b4c5581c24e__CVE-2021-31258`

- Pair key: `gpac|ebfa346eff05049718f7b80041093b4c5581c24e|CVE-2021-31258`
- Source pool: `rank6_10_v1`
- Project/CVE: `gpac` / `CVE-2021-31258`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.985305`
- Probability gap: `0.465134`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `267342::pairctx`
- Detector probability: `0.7371581792831421`

#### Window `A1`

- Header: `@@ -12,28 +12,26 @@ 	if (e) return e;`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 		slc = & ((GF_MPEGSampleEntryBox *)entry)->slc;
- 		slc = & ((GF_MPEGAudioSampleEntryBox *)entry)->slc;
- 		slc = & ((GF_MPEGVisualSampleEntryBox *)entry)->slc;
- 	if (*slc) {
```

Added preview:

```diff
+ 	slc = NULL;
+ 	*slConfig = NULL;
+ 		slc = ((GF_MPEGSampleEntryBox *)entry)->slc;
+ 		slc = ((GF_MPEGAudioSampleEntryBox *)entry)->slc;
```

#### Window `A2`

- Header: `@@ -12,28 +12,26 @@ 	if (e) return e; [changed-window 15]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	return gf_odf_desc_copy((GF_Descriptor *) slConfig, (GF_Descriptor **) slc);
```

Added preview:

```diff
+ 	return gf_odf_desc_copy((GF_Descriptor *) slc, (GF_Descriptor **) slConfig);
```

#### Window `A3`

- Header: `@@ -12,28 +12,26 @@ 	if (e) return e; [changed-window 14]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 	return gf_odf_desc_copy((GF_Descriptor *) slConfig, (GF_Descriptor **) slc);
```

Added preview:

```diff
+ 	if (!slc) return GF_OK;
```

### Side B

- ID: `197972::pairctx`
- Detector probability: `0.272024542093277`

#### Window `B1`

- Header: `@@ -12,26 +12,28 @@ 	if (e) return e;`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	slc = NULL;
- 	*slConfig = NULL;
- 		slc = ((GF_MPEGSampleEntryBox *)entry)->slc;
- 		slc = ((GF_MPEGAudioSampleEntryBox *)entry)->slc;
```

Added preview:

```diff
+ 		slc = & ((GF_MPEGSampleEntryBox *)entry)->slc;
+ 		slc = & ((GF_MPEGAudioSampleEntryBox *)entry)->slc;
+ 		slc = & ((GF_MPEGVisualSampleEntryBox *)entry)->slc;
+ 	if (*slc) {
```

#### Window `B2`

- Header: `@@ -12,26 +12,28 @@ 	if (e) return e; [changed-window 15]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	return gf_odf_desc_copy((GF_Descriptor *) slc, (GF_Descriptor **) slConfig);
```

Added preview:

```diff
+ 	return gf_odf_desc_copy((GF_Descriptor *) slConfig, (GF_Descriptor **) slc);
```

#### Window `B3`

- Header: `@@ -12,26 +12,28 @@ 	if (e) return e; [changed-window 14]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 	return gf_odf_desc_copy((GF_Descriptor *) slc, (GF_Descriptor **) slConfig);
```

Added preview:

```diff
+ 	if (!slConfig) return GF_OK;
```

---

## Item 33: `manual_evidence_audit::7::2::mruby__b1d0296a937fe278239bdfac840a3fd0e93b3ee9__CVE-2022-1286`

- Pair key: `mruby|b1d0296a937fe278239bdfac840a3fd0e93b3ee9|CVE-2022-1286`
- Source pool: `top5_v1`
- Project/CVE: `mruby` / `CVE-2022-1286`
- Changed-line bucket: `03-05`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.999148`
- Probability gap: `0.685929`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `196621::pairctx`
- Detector probability: `0.7138307690620422`

#### Window `A1`

- Header: `@@ -5,9 +5,6 @@   MRB_CLASS_ORIGIN(c);`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-   if (h && mt_del(mrb, h, mid)) {
-     mrb_mc_clear_by_class(mrb, c);
-     return;
-   }
```

Added preview:

```diff
+   if (h && mt_del(mrb, h, mid)) return;
```

#### Window `A2`

- Header: `@@ -5,9 +5,6 @@   MRB_CLASS_ORIGIN(c); [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
-   if (h && mt_del(mrb, h, mid)) {
-     mrb_mc_clear_by_class(mrb, c);
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -5,9 +5,6 @@   MRB_CLASS_ORIGIN(c); [changed-window 2]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
-     mrb_mc_clear_by_class(mrb, c);
-     return;
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `241311::pairctx`
- Detector probability: `0.02790137380361557`

#### Window `B1`

- Header: `@@ -5,6 +5,9 @@   MRB_CLASS_ORIGIN(c);`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-   if (h && mt_del(mrb, h, mid)) return;
```

Added preview:

```diff
+   if (h && mt_del(mrb, h, mid)) {
+     mrb_mc_clear_by_class(mrb, c);
+     return;
+   }
```

#### Window `B2`

- Header: `@@ -5,6 +5,9 @@   MRB_CLASS_ORIGIN(c); [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
-   if (h && mt_del(mrb, h, mid)) return;
```

Added preview:

```diff
+   if (h && mt_del(mrb, h, mid)) {
```

#### Window `B3`

- Header: `@@ -5,6 +5,9 @@   MRB_CLASS_ORIGIN(c); [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+   if (h && mt_del(mrb, h, mid)) {
+     mrb_mc_clear_by_class(mrb, c);
```

---

## Item 34: `manual_evidence_audit::42::3::gst-plugins-good__9181191511f9c0be6a89c98b311f49d66bd46dc3__CVE-2021-3497`

- Pair key: `gst-plugins-good|9181191511f9c0be6a89c98b311f49d66bd46dc3|CVE-2021-3497`
- Source pool: `top5_v1`
- Project/CVE: `gst-plugins-good` / `CVE-2021-3497`
- Changed-line bucket: `26+`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.999868`
- Probability gap: `0.091026`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `444835::pairctx`
- Detector probability: `0.6261242032051086`

#### Window `A1`

- Header: `@@ -90,59 +99,57 @@       data += 4;`
- Direction labels: `candidate_removes_protection`
- Risk support: `6`
- Safety support: `0`

Removed preview:

```diff
-       if (blocksize == 0 || size < blocksize)
-         break;
- 
-       g_assert ((newbuf == NULL) == (outdata == NULL));
```

Added preview:

```diff
+       if (blocksize == 0 || size < blocksize) {
+         GST_ERROR_OBJECT (element, "Too small wavpack buffer");
+         gst_buffer_unmap (*buf, &map);
+         g_object_unref (adapter);
```

#### Window `A2`

- Header: `@@ -30,10 +36,10 @@     /* -20 because ck_size is the size of the wavpack block -8`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     wvh.ck_size = size + sizeof (Wavpack4Header) - 20;
-     newbuf = gst_buffer_new_allocate (NULL, sizeof (Wavpack4Header) - 12, NULL);
```

Added preview:

```diff
+     wvh.ck_size = size + WAVPACK4_HEADER_SIZE - 20;
+     newbuf = gst_buffer_new_allocate (NULL, WAVPACK4_HEADER_SIZE - 12, NULL);
```

#### Window `A3`

- Header: `@@ -30,10 +36,10 @@     /* -20 because ck_size is the size of the wavpack block -8 [changed-window 3]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     newbuf = gst_buffer_new_allocate (NULL, sizeof (Wavpack4Header) - 12, NULL);
```

Added preview:

```diff
+     newbuf = gst_buffer_new_allocate (NULL, WAVPACK4_HEADER_SIZE - 12, NULL);
```

### Side B

- ID: `211032::pairctx`
- Detector probability: `0.5350984334945679`

#### Window `B1`

- Header: `@@ -99,57 +90,59 @@       data += 4;`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `6`

Removed preview:

```diff
-       if (blocksize == 0 || size < blocksize) {
-         GST_ERROR_OBJECT (element, "Too small wavpack buffer");
-         gst_buffer_unmap (*buf, &map);
-         g_object_unref (adapter);
```

Added preview:

```diff
+       if (blocksize == 0 || size < blocksize)
+         break;
+ 
+       g_assert ((newbuf == NULL) == (outdata == NULL));
```

#### Window `B2`

- Header: `@@ -36,10 +30,10 @@     /* -20 because ck_size is the size of the wavpack block -8`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     wvh.ck_size = size + WAVPACK4_HEADER_SIZE - 20;
-     newbuf = gst_buffer_new_allocate (NULL, WAVPACK4_HEADER_SIZE - 12, NULL);
```

Added preview:

```diff
+     wvh.ck_size = size + sizeof (Wavpack4Header) - 20;
+     newbuf = gst_buffer_new_allocate (NULL, sizeof (Wavpack4Header) - 12, NULL);
```

#### Window `B3`

- Header: `@@ -36,10 +30,10 @@     /* -20 because ck_size is the size of the wavpack block -8 [changed-window 3]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-     newbuf = gst_buffer_new_allocate (NULL, WAVPACK4_HEADER_SIZE - 12, NULL);
```

Added preview:

```diff
+     newbuf = gst_buffer_new_allocate (NULL, sizeof (Wavpack4Header) - 12, NULL);
```

---

## Item 35: `manual_evidence_audit::7::4::mruby__3cf291f72224715942beaf8553e42ba8891ab3c6__CVE-2022-1212`

- Pair key: `mruby|3cf291f72224715942beaf8553e42ba8891ab3c6|CVE-2022-1212`
- Source pool: `top5_v1`
- Project/CVE: `mruby` / `CVE-2022-1212`
- Changed-line bucket: `00-02`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.989747`
- Probability gap: `0.0`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `274773::pairctx`
- Detector probability: `0.7356416583061218`

#### Window `A1`

- Header: `@@ -1069,9 +1069,9 @@           }`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-             mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
```

Added preview:

```diff
+             mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
```

#### Window `A2`

- Header: `@@ -1069,9 +1069,9 @@           } [changed-window all]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-             mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
```

Added preview:

```diff
+             mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
```

### Side B

- ID: `198439::pairctx`
- Detector probability: `0.7356416583061218`

#### Window `B1`

- Header: `@@ -1069,9 +1069,9 @@           }`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-             mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
```

Added preview:

```diff
+             mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
```

#### Window `B2`

- Header: `@@ -1069,9 +1069,9 @@           } [changed-window all]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-             mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
```

Added preview:

```diff
+             mrb->exc = (struct RObject*)break_new(mrb, RBREAK_TAG_BREAK, proc, v);
```

---

## Item 36: `manual_evidence_audit::99::5::nDPI__1ec621c85b9411cc611652fd57a892cfef478af3__CVE-2021-36082`

- Pair key: `nDPI|1ec621c85b9411cc611652fd57a892cfef478af3|CVE-2021-36082`
- Source pool: `top5_v1`
- Project/CVE: `nDPI` / `CVE-2021-36082`
- Changed-line bucket: `26+`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.313863`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `195820::pairctx`
- Detector probability: `0.965217649936676`

#### Window `A1`

- Header: `@@ -210,36 +210,34 @@ 	i += 4 + extension_len, offset += 4 + extension_len;`
- Direction labels: `candidate_removes_protection`
- Risk support: `11`
- Safety support: `0`

Removed preview:

```diff
-       ja3_str_len = snprintf(ja3_str, JA3_STR_LEN, "%u,", ja3.server.tls_handshake_version);
- 
-       for(i=0; (i<ja3.server.num_cipher) && (JA3_STR_LEN > ja3_str_len); i++) {
- 	rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.cipher[i]);
```

Added preview:

```diff
+       ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.server.tls_handshake_version);
+ 
+       for(i=0; i<ja3.server.num_cipher; i++) {
+ 	rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.cipher[i]);
```

#### Window `A2`

- Header: `@@ -825,47 +823,47 @@ 	      int rc;`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	      ja3_str_len = snprintf(ja3_str, JA3_STR_LEN, "%u,", ja3.client.tls_handshake_version);
- 		rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
- 	      rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, ",");
- 		rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
```

Added preview:

```diff
+ 	      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.client.tls_handshake_version);
+ 		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
+ 	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
+ 		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
```

#### Window `A3`

- Header: `@@ -210,36 +210,34 @@ 	i += 4 + extension_len, offset += 4 + extension_len; [changed-window 20]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- 	for(i=0; (i<ja3.server.num_elliptic_curve_point_format) && (JA3_STR_LEN > ja3_str_len); i++) {
```

Added preview:

```diff
+ 	int rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.tls_extension[i]);
```

### Side B

- ID: `234082::pairctx`
- Detector probability: `0.6513549089431763`

#### Window `B1`

- Header: `@@ -210,34 +210,36 @@ 	i += 4 + extension_len, offset += 4 + extension_len;`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `11`

Removed preview:

```diff
-       ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.server.tls_handshake_version);
- 
-       for(i=0; i<ja3.server.num_cipher; i++) {
- 	rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.cipher[i]);
```

Added preview:

```diff
+       ja3_str_len = snprintf(ja3_str, JA3_STR_LEN, "%u,", ja3.server.tls_handshake_version);
+ 
+       for(i=0; (i<ja3.server.num_cipher) && (JA3_STR_LEN > ja3_str_len); i++) {
+ 	rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.cipher[i]);
```

#### Window `B2`

- Header: `@@ -823,47 +825,47 @@ 	      int rc;`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.client.tls_handshake_version);
- 		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
- 	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
- 		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u",
```

Added preview:

```diff
+ 	      ja3_str_len = snprintf(ja3_str, JA3_STR_LEN, "%u,", ja3.client.tls_handshake_version);
+ 		rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
+ 	      rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, ",");
+ 		rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u",
```

#### Window `B3`

- Header: `@@ -210,34 +210,36 @@ 	i += 4 + extension_len, offset += 4 + extension_len; [changed-window 18]`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- 	int rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.tls_extension[i]);
```

Added preview:

```diff
+       for(i=0; (i<ja3.server.num_tls_extension) && (JA3_STR_LEN > ja3_str_len); i++) {
```

---

## Item 37: `manual_evidence_audit::7::5::qemu__1caff0340f49c93d535c6558a5138d20d475315c__CVE-2021-3416`

- Pair key: `qemu|1caff0340f49c93d535c6558a5138d20d475315c|CVE-2021-3416`
- Source pool: `top5_v1`
- Project/CVE: `qemu` / `CVE-2021-3416`
- Changed-line bucket: `00-02`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.95879`
- Probability gap: `0.069772`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `442189::pairctx`
- Detector probability: `0.49609383940696716`

#### Window `A1`

- Header: `@@ -5,7 +5,7 @@ `
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         nc->info->receive(nc, buf, size);
```

Added preview:

```diff
+         qemu_receive_packet(nc, buf, size);
```

#### Window `A2`

- Header: `@@ -5,7 +5,7 @@  [changed-window all]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         nc->info->receive(nc, buf, size);
```

Added preview:

```diff
+         qemu_receive_packet(nc, buf, size);
```

### Side B

- ID: `210887::pairctx`
- Detector probability: `0.4263215959072113`

#### Window `B1`

- Header: `@@ -5,7 +5,7 @@ `
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         qemu_receive_packet(nc, buf, size);
```

Added preview:

```diff
+         nc->info->receive(nc, buf, size);
```

#### Window `B2`

- Header: `@@ -5,7 +5,7 @@  [changed-window all]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
-         qemu_receive_packet(nc, buf, size);
```

Added preview:

```diff
+         nc->info->receive(nc, buf, size);
```

---

## Item 38: `manual_evidence_audit::13::5::radare2__2b77b277d67ce061ee6ef839e7139ebc2103c1e3__CVE-2022-1244`

- Pair key: `radare2|2b77b277d67ce061ee6ef839e7139ebc2103c1e3|CVE-2022-1244`
- Source pool: `top5_v1`
- Project/CVE: `radare2` / `CVE-2022-1244`
- Changed-line bucket: `03-05`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.99998`
- Probability gap: `0.836476`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `207780::pairctx`
- Detector probability: `0.9694401025772095`

#### Window `A1`

- Header: `@@ -103,8 +103,7 @@ 			if (deps && !deps[j]) {`
- Direction labels: `candidate_removes_protection`
- Risk support: `2`
- Safety support: `0`

Removed preview:

```diff
- 			// ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
- 			ut64 pa = va2pa (img[j].address, cache->n_maps, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

Added preview:

```diff
+ 			ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

#### Window `A2`

- Header: `@@ -103,8 +103,7 @@ 			if (deps && !deps[j]) { [changed-window 1]`
- Direction labels: `candidate_removes_protection`
- Risk support: `4`
- Safety support: `0`

Removed preview:

```diff
- 			// ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
- 			ut64 pa = va2pa (img[j].address, cache->n_maps, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -103,8 +103,7 @@ 			if (deps && !deps[j]) { [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 			ut64 pa = va2pa (img[j].address, cache->n_maps, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

Added preview:

```diff
+ 			ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

### Side B

- ID: `401034::pairctx`
- Detector probability: `0.13296423852443695`

#### Window `B1`

- Header: `@@ -103,7 +103,8 @@ 			if (deps && !deps[j]) {`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `2`

Removed preview:

```diff
- 			ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

Added preview:

```diff
+ 			// ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
+ 			ut64 pa = va2pa (img[j].address, cache->n_maps, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

#### Window `B2`

- Header: `@@ -103,7 +103,8 @@ 			if (deps && !deps[j]) { [changed-window 1]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 			ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

Added preview:

```diff
+ 			// ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

#### Window `B3`

- Header: `@@ -103,7 +103,8 @@ 			if (deps && !deps[j]) { [changed-window 2]`
- Direction labels: `candidate_adds_protection`
- Risk support: `0`
- Safety support: `4`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 			// ut64 pa = va2pa (img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
+ 			ut64 pa = va2pa (img[j].address, cache->n_maps, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
```

---

## Item 39: `manual_evidence_audit::401::4::ImageMagick6__d5e7c2b5ba384e7d0d8ddac6c9ae2319cb74b9c5__CVE-2018-15607`

- Pair key: `ImageMagick6|d5e7c2b5ba384e7d0d8ddac6c9ae2319cb74b9c5|CVE-2018-15607`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `ImageMagick6` / `CVE-2018-15607`
- Changed-line bucket: `11-25`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `1.0`
- Probability gap: `0.699534`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `210554::pairctx`
- Detector probability: `0.8807970285415649`

#### Window `A1`

- Header: `@@ -190,13 +190,6 @@       (void) ReadBlobByte(image);`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `16`
- Safety support: `1`

Removed preview:

```diff
-     number_pixels=(MagickSizeType) viff_info.columns*viff_info.rows;
-     if (number_pixels != (size_t) number_pixels)
-       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-     if (number_pixels > GetBlobSize(image))
```

Added preview:

```diff
+ <empty>
```

#### Window `A2`

- Header: `@@ -212,6 +205,11 @@     /*`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `12`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     number_pixels=(MagickSizeType) viff_info.columns*viff_info.rows;
+     if (number_pixels != (size_t) number_pixels)
+       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+     if (number_pixels == 0)
```

#### Window `A3`

- Header: `@@ -190,13 +190,6 @@       (void) ReadBlobByte(image); [changed-window 2]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `5`
- Safety support: `1`

Removed preview:

```diff
-     if (number_pixels != (size_t) number_pixels)
-       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `437401::pairctx`
- Detector probability: `0.18126320838928223`

#### Window `B1`

- Header: `@@ -190,6 +190,13 @@       (void) ReadBlobByte(image);`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `16`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     number_pixels=(MagickSizeType) viff_info.columns*viff_info.rows;
+     if (number_pixels != (size_t) number_pixels)
+       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
+     if (number_pixels > GetBlobSize(image))
```

#### Window `B2`

- Header: `@@ -205,11 +212,6 @@     /*`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `12`
- Safety support: `1`

Removed preview:

```diff
-     number_pixels=(MagickSizeType) viff_info.columns*viff_info.rows;
-     if (number_pixels != (size_t) number_pixels)
-       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
-     if (number_pixels == 0)
```

Added preview:

```diff
+ <empty>
```

#### Window `B3`

- Header: `@@ -190,6 +190,13 @@       (void) ReadBlobByte(image); [changed-window 2]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `5`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+     if (number_pixels != (size_t) number_pixels)
+       ThrowReaderException(ResourceLimitError,"MemoryAllocationFailed");
```

---

## Item 40: `manual_evidence_audit::211::5::php-src__2bcbc95f033c31b00595ed39f79c3a99b4ed0501__CVE-2020-7060`

- Pair key: `php-src|2bcbc95f033c31b00595ed39f79c3a99b4ed0501|CVE-2020-7060`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `php-src` / `CVE-2020-7060`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `1.0`
- Probability gap: `0.818331`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `464942::pairctx`
- Detector probability: `0.8925625681877136`

#### Window `A1`

- Header: `@@ -42,11 +42,7 @@ `
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 				if (w <= 0 &&
- 					(((c1 >= 0xfa && c1 <= 0xfe) || (c1 >= 0x8e && c1 <= 0xa0) ||
- 					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8))
- 					 && ((c > 0x39 && c < 0x7f) || (c > 0xa0 && c < 0xff))) ||
```

Added preview:

```diff
+ 				if (w <= 0 && is_in_cp950_pua(c1, c)) {
```

#### Window `A2`

- Header: `@@ -42,11 +42,7 @@  [changed-window 2]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 					(((c1 >= 0xfa && c1 <= 0xfe) || (c1 >= 0x8e && c1 <= 0xa0) ||
- 					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8))
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -42,11 +42,7 @@  [changed-window 3]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8))
- 					 && ((c > 0x39 && c < 0x7f) || (c > 0xa0 && c < 0xff))) ||
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `213037::pairctx`
- Detector probability: `0.07423137128353119`

#### Window `B1`

- Header: `@@ -42,7 +42,11 @@ `
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 				if (w <= 0 && is_in_cp950_pua(c1, c)) {
```

Added preview:

```diff
+ 				if (w <= 0 &&
+ 					(((c1 >= 0xfa && c1 <= 0xfe) || (c1 >= 0x8e && c1 <= 0xa0) ||
+ 					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8))
+ 					 && ((c > 0x39 && c < 0x7f) || (c > 0xa0 && c < 0xff))) ||
```

#### Window `B2`

- Header: `@@ -42,7 +42,11 @@  [changed-window 3]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 					(((c1 >= 0xfa && c1 <= 0xfe) || (c1 >= 0x8e && c1 <= 0xa0) ||
+ 					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8))
```

#### Window `B3`

- Header: `@@ -42,7 +42,11 @@  [changed-window 4]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8))
+ 					 && ((c > 0x39 && c < 0x7f) || (c > 0xa0 && c < 0xff))) ||
```

---

## Item 41: `manual_evidence_audit::503::5::FreeRDP__ce21b9d7ecd967e0bc98ed31a6b3757848aa6c9e__CVE-2020-11523`

- Pair key: `FreeRDP|ce21b9d7ecd967e0bc98ed31a6b3757848aa6c9e|CVE-2020-11523`
- Source pool: `fresh_seeds_top5_v1`
- Project/CVE: `FreeRDP` / `CVE-2020-11523`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `A`
- True inversion candidate: `False`
- Side model score: `0.999712`
- Probability gap: `0.128571`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `212839::pairctx`
- Detector probability: `0.6791787147521973`

#### Window `A1`

- Header: `@@ -1,7 +1,7 @@-INLINE void gdi_RectToRgn(HGDI_RECT rect, HGDI_RGN rgn)`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	rgn->x = rect->left;
- 	rgn->y = rect->top;
- 	rgn->w = rect->right - rect->left + 1;
- 	rgn->h = rect->bottom - rect->top + 1;
```

Added preview:

```diff
+ INLINE void gdi_RectToCRgn(const HGDI_RECT rect, INT32* x, INT32* y, INT32* w, INT32* h)
+ 	*x = rect->left;
+ 	*y = rect->top;
+ 	*w = rect->right - rect->left + 1;
```

#### Window `A2`

- Header: `@@ -1,7 +1,7 @@-INLINE void gdi_RectToRgn(HGDI_RECT rect, HGDI_RGN rgn) [changed-window 1]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	rgn->x = rect->left;
```

Added preview:

```diff
+ INLINE void gdi_RectToCRgn(const HGDI_RECT rect, INT32* x, INT32* y, INT32* w, INT32* h)
```

#### Window `A3`

- Header: `@@ -1,7 +1,7 @@-INLINE void gdi_RectToRgn(HGDI_RECT rect, HGDI_RGN rgn) [changed-window 4]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	rgn->w = rect->right - rect->left + 1;
- 	rgn->h = rect->bottom - rect->top + 1;
```

Added preview:

```diff
+ <empty>
```

### Side B

- ID: `462482::pairctx`
- Detector probability: `0.5506073832511902`

#### Window `B1`

- Header: `@@ -1,7 +1,7 @@-INLINE void gdi_RectToCRgn(const HGDI_RECT rect, INT32* x, INT32* y, INT32* w, INT32* h)`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	*x = rect->left;
- 	*y = rect->top;
- 	*w = rect->right - rect->left + 1;
- 	*h = rect->bottom - rect->top + 1;
```

Added preview:

```diff
+ INLINE void gdi_RectToRgn(HGDI_RECT rect, HGDI_RGN rgn)
+ 	rgn->x = rect->left;
+ 	rgn->y = rect->top;
+ 	rgn->w = rect->right - rect->left + 1;
```

#### Window `B2`

- Header: `@@ -1,7 +1,7 @@-INLINE void gdi_RectToCRgn(const HGDI_RECT rect, INT32* x, INT32* y, INT32* w, INT32* h) [changed-window 8]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	rgn->w = rect->right - rect->left + 1;
+ 	rgn->h = rect->bottom - rect->top + 1;
```

#### Window `B3`

- Header: `@@ -1,7 +1,7 @@-INLINE void gdi_RectToCRgn(const HGDI_RECT rect, INT32* x, INT32* y, INT32* w, INT32* h) [changed-window 1]`
- Direction labels: `direction_unclear`
- Risk support: `0`
- Safety support: `0`

Removed preview:

```diff
- 	*x = rect->left;
```

Added preview:

```diff
+ INLINE void gdi_RectToRgn(HGDI_RECT rect, HGDI_RGN rgn)
```

---

## Item 42: `manual_evidence_audit::7::10::linux__42933c8aa14be1caa9eda41f65cde8a3a95d3e39__CVE-2022-0487`

- Pair key: `linux|42933c8aa14be1caa9eda41f65cde8a3a95d3e39|CVE-2022-0487`
- Source pool: `rank6_10_v1`
- Project/CVE: `linux` / `CVE-2022-0487`
- Changed-line bucket: `06-10`
- Model vulnerable side: `A`
- Gold vulnerable side: `B`
- True inversion candidate: `True`
- Side model score: `0.881797`
- Probability gap: `0.54234`

### Annotation Block

```yaml
human_vulnerable_side: 
evidence_side: 
evidence_quality: 
selected_window_ids: []
label_issue: none
notes: 
```

### Side A

- ID: `386074::pairctx`
- Detector probability: `0.7057850360870361`

#### Window `A1`

- Header: `@@ -31,10 +28,11 @@ 		pm_runtime_put(ms_dev(host));`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- 	platform_set_drvdata(pdev, NULL);
- 
```

Added preview:

```diff
+ 	memstick_remove_host(msh);
+ 	memstick_free_host(msh);
+ 	platform_set_drvdata(pdev, NULL);
```

#### Window `A2`

- Header: `@@ -21,9 +21,6 @@ 	}`
- Direction labels: `candidate_removes_risk`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 	memstick_remove_host(msh);
- 	memstick_free_host(msh);
- 
```

Added preview:

```diff
+ <empty>
```

#### Window `A3`

- Header: `@@ -31,10 +28,11 @@ 		pm_runtime_put(ms_dev(host)); [changed-window 4]`
- Direction labels: `candidate_adds_protection,candidate_introduces_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	memstick_free_host(msh);
+ 	platform_set_drvdata(pdev, NULL);
```

### Side B

- ID: `206735::pairctx`
- Detector probability: `0.16344544291496277`

#### Window `B1`

- Header: `@@ -28,11 +31,10 @@ 		pm_runtime_put(ms_dev(host));`
- Direction labels: `candidate_removes_risk`
- Risk support: `0`
- Safety support: `1`

Removed preview:

```diff
- 	memstick_remove_host(msh);
- 	memstick_free_host(msh);
- 	platform_set_drvdata(pdev, NULL);
```

Added preview:

```diff
+ 	platform_set_drvdata(pdev, NULL);
+ 
```

#### Window `B2`

- Header: `@@ -21,6 +21,9 @@ 	}`
- Direction labels: `candidate_introduces_risk`
- Risk support: `1`
- Safety support: `0`

Removed preview:

```diff
- <empty>
```

Added preview:

```diff
+ 	memstick_remove_host(msh);
+ 	memstick_free_host(msh);
+ 
```

#### Window `B3`

- Header: `@@ -28,11 +31,10 @@ 		pm_runtime_put(ms_dev(host)); [changed-window 4]`
- Direction labels: `candidate_removes_protection,candidate_removes_risk`
- Risk support: `1`
- Safety support: `1`

Removed preview:

```diff
- 	memstick_free_host(msh);
- 	platform_set_drvdata(pdev, NULL);
```

Added preview:

```diff
+ <empty>
```

---
