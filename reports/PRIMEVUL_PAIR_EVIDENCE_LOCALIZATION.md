# PrimeVul Pair Evidence Localization

This report adds a heuristic evidence-localization layer on top of paired diff predictions. It does not claim gold evidence-span supervision; it scores whether the selected hunks directionally support a vulnerable or safe candidate-side decision.

## Summary

| scope | rows | pairs | accuracy | support_rate | pseudo_loc_acc | vuln_pseudo_loc | safe_pseudo_loc | supported_error_rate | unsupported_error_rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| all rows | 1261 | 614 | 0.8493 | 0.6376 | 0.6003 | 0.5952 | 0.6054 | 0.0933 | 0.2516 |
| pair-coupled rows | 1156 | 565 | 0.8573 | 0.6592 | 0.6202 | 0.6176 | 0.6228 | 0.0945 | 0.236 |

## Aggregate Signals

- Top direction labels: `[('candidate_adds_protection', 517), ('direction_unclear', 500), ('candidate_removes_protection', 500), ('candidate_removes_risk', 100), ('candidate_introduces_risk', 98)]`
- Top CWEs: `[('cwe-787', 220), ('cwe-125', 143), ('cwe-703', 117), ('cwe-476', 109), ('cwe-416', 78), ('cwe-369', 46), ('cwe-190', 45), ('cwe-119', 40), ('cwe-200', 34), ('cwe-20', 34)]`
- Support confusion: `{'pred_supported__gold_supported': 729, 'pred_supported__gold_unsupported': 75, 'pred_unsupported__gold_supported': 28, 'pred_unsupported__gold_unsupported': 429}`

## Hunk-Limit Sweep

| hunk_limit | support_rate | pseudo_loc_acc | vuln_pseudo_loc | safe_pseudo_loc | supported_error_rate | unsupported_error_rate |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.6297 | 0.5916 | 0.5873 | 0.5959 | 0.0957 | 0.2441 |
| 2 | 0.6376 | 0.6003 | 0.5952 | 0.6054 | 0.0933 | 0.2516 |
| 3 | 0.6408 | 0.6051 | 0.6 | 0.6101 | 0.0928 | 0.2539 |
| 5 | 0.6392 | 0.6035 | 0.5984 | 0.6086 | 0.0906 | 0.2571 |

## Unsupported Predictions

### 206917::pairctx

- Project/CVE/CWE: `httpd` / `CVE-2021-26691` / `cwe-787`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.6825737357139587`
- Support: `unsupported` risk `0` safety `0` net `0`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -1,6 +1,6 @@ static int identity_count(void *v, const char *key, const char *val)` risk `0` safety `0` directions `direction_unclear`
- Removed: `    *count += strlen(key) * 3 + strlen(val) * 3 + 2;`
- Added: `    *count += strlen(key) * 3 + strlen(val) * 3 + 1;`

### 214003::pairctx

- Project/CVE/CWE: `libvncserver` / `CVE-2018-20020` / `cwe-787`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.41679662466049194`
- Support: `unsupported` risk `0` safety `0` net `0`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -16,7 +16,7 @@ ` risk `0` safety `0` directions `direction_unclear`
- Removed: `    if (hdr.nSubrects > RFB_BUFFER_SIZE / (4 + (BPP / 8)) || !ReadFromRFBServer(client, client->buffer, hdr.nSubrects * (4 + (BPP / 8))))`
- Added: `    if (hdr.nSubrects * (4 + (BPP / 8)) > RFB_BUFFER_SIZE || !ReadFromRFBServer(client, client->buffer, hdr.nSubrects * (4 + (BPP / 8))))`

### 450812::pairctx

- Project/CVE/CWE: `gnulib` / `CVE-2017-15670` / `cwe-119`
- Gold/Pred/Correct: `0` / `0` / `True`
- Probability: `0.6206215620040894`
- Support: `unsupported` risk `0` safety `0` net `0`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -504,7 +504,7 @@                   *p = '\0';` risk `0` safety `0` directions `direction_unclear`
- Removed: `                *((char *) mempcpy (newp, dirname + 1, end_name - dirname))`
- Added: `                *((char *) mempcpy (newp, dirname + 1, end_name - dirname - 1))`

### 204495::pairctx

- Project/CVE/CWE: `linux` / `CVE-2022-3103` / `cwe-193`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.596433162689209`
- Support: `unsupported` risk `0` safety `0` net `0`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -8,7 +8,7 @@ 	    (cd->flags & IORING_ASYNC_CANCEL_FD_FIXED)) {` risk `0` safety `0` directions `direction_unclear`
- Removed: `		if (unlikely(fd >= ctx->nr_user_files))`
- Added: `		if (unlikely(fd > ctx->nr_user_files))`

### 198239::pairctx

- Project/CVE/CWE: `barebox` / `CVE-2021-37848` / `cwe-200`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.43014732003211975`
- Support: `unsupported` risk `0` safety `0` net `0`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -45,7 +45,7 @@ 		if (ret)` risk `0` safety `0` directions `direction_unclear`
- Removed: `		if (!crypto_memneq(passwd1_sum, key, keylen))`
- Added: `		if (strncmp(passwd1_sum, key, keylen) == 0)`
- Hunk `@@ -53,7 +53,7 @@ 		if (ret)` risk `0` safety `0` directions `direction_unclear`
- Removed: `		if (!crypto_memneq(passwd1_sum, passwd2_sum, hash_len))`
- Added: `		if (strncmp(passwd1_sum, passwd2_sum, hash_len) == 0)`

### 411896::pairctx

- Project/CVE/CWE: `tor` / `CVE-2012-3517` / `cwe-399`
- Gold/Pred/Correct: `0` / `1` / `False`
- Probability: `0.7879312038421631`
- Support: `unsupported` risk `0` safety `0` net `0`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -43,7 +43,7 @@     int flavor = networkstatus_parse_flavor_name(tok->args[1]);` risk `0` safety `0` directions `direction_unclear`
- Removed: `               escaped(tok->args[2]));`
- Added: `               escaped(tok->args[1]));`

## Errors

### 411896::pairctx

- Project/CVE/CWE: `tor` / `CVE-2012-3517` / `cwe-399`
- Gold/Pred/Correct: `0` / `1` / `False`
- Probability: `0.7879312038421631`
- Support: `unsupported` risk `0` safety `0` net `0`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -43,7 +43,7 @@     int flavor = networkstatus_parse_flavor_name(tok->args[1]);` risk `0` safety `0` directions `direction_unclear`
- Removed: `               escaped(tok->args[2]));`
- Added: `               escaped(tok->args[1]));`

### 220100::pairctx

- Project/CVE/CWE: `linux` / `CVE-2022-24448` / `cwe-909`
- Gold/Pred/Correct: `0` / `1` / `False`
- Probability: `0.5698526501655579`
- Support: `supported` risk `1` safety `0` net `1`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -24,7 +24,7 @@ 		return err;` risk `1` safety `0` directions `candidate_removes_protection`
- Removed: `		return nfs_open(inode, filp);`
- Added: `		openflags--;`

### 195073::pairctx

- Project/CVE/CWE: `tensorflow` / `CVE-2022-23584` / `cwe-416`
- Gold/Pred/Correct: `1` / `0` / `False`
- Probability: `0.00807762611657381`
- Support: `unsupported` risk `1` safety `0` net `1`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -18,6 +18,7 @@     if (width != static_cast<int64_t>(decode.width) || width <= 0 ||` risk `1` safety `0` directions `candidate_introduces_risk`
- Added: `      png::CommonFreeDecode(&decode);`

### 318099::pairctx

- Project/CVE/CWE: `wireless-drivers` / `CVE-2019-15504` / `cwe-415`
- Gold/Pred/Correct: `0` / `1` / `False`
- Probability: `0.9752018451690674`
- Support: `unsupported` risk `0` safety `1` net `-1`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -53,7 +53,6 @@ 	kfree(rsi_dev->tx_buffer);` risk `0` safety `1` directions `candidate_removes_risk`
- Removed: `	kfree(rsi_dev);`

### 224281::pairctx

- Project/CVE/CWE: `squid` / `CVE-2021-46784` / `cwe-400`
- Gold/Pred/Correct: `0` / `1` / `False`
- Probability: `0.5544704794883728`
- Support: `supported` risk `13` safety `3` net `10`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -335,12 +328,11 @@ ` risk `0` safety `2` directions `candidate_adds_protection`
- Removed: `    if (outbuf.size() > 0) { |         entry->append(outbuf.rawBuf(), outbuf.size()); |     outbuf.clean();`
- Added: `    if (outbuf.length() > 0) { |         entry->append(outbuf.rawContent(), outbuf.length());`
- Hunk `@@ -221,37 +219,34 @@                         break;` risk `13` safety `1` directions `candidate_removes_protection, candidate_removes_risk`
- Removed: `                    memset(tmpbuf, '\0', TEMP_BUF_SIZE); |  |                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%`
- Added: `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n", |                             outbuf.appendf("<IMG border=\"0\"`

### 475970::pairctx

- Project/CVE/CWE: `ImageMagick` / `CVE-2021-20310` / `cwe-369`
- Gold/Pred/Correct: `0` / `1` / `False`
- Probability: `0.7981867790222168`
- Support: `unsupported` risk `0` safety `0` net `0`
- Gold support: `unsupported` pseudo-localization-correct `False`
- Hunk `@@ -30,11 +30,11 @@   L=0.41478972*Xp+0.579999*Yp+0.0146480*Zp;` risk `0` safety `0` directions `direction_unclear`
- Removed: `  gamma=pow(L/white_luminance,Jzazbz_n); |   gamma=pow(M/white_luminance,Jzazbz_n); |   gamma=pow(S/white_luminance,Jzazbz_n);`
- Added: `  gamma=pow(L*PerceptibleReciprocal(white_luminance),Jzazbz_n); |   gamma=pow(M*PerceptibleReciprocal(white_luminance),Jzazbz_n); |   gamma=pow(S*PerceptibleReciprocal(white_lumina`

## Highest Risk-Support Hunks

### 197142::pairctx

- Project/CVE/CWE: `tensorflow` / `CVE-2021-37663` / `cwe-476`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.9951702952384949`
- Support: `supported` risk `74` safety `0` net `74`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -5,50 +5,7 @@ ` risk `74` safety `0` directions `candidate_removes_protection`
- Removed: `      OP_REQUIRES( |           ctx, input.dims() > axis_, |           errors::InvalidArgument( |               "Axis is on a zero-based index, so its value must always be less " | `

### 197761::pairctx

- Project/CVE/CWE: `tensorflow` / `CVE-2021-29547` / `cwe-369`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.9839785695075989`
- Support: `supported` risk `72` safety `0` net `72`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -60,33 +30,6 @@     OP_REQUIRES(context, gamma.dims() == 1,` risk `32` safety `0` directions `candidate_removes_protection`
- Removed: `    OP_REQUIRES(context, mean.NumElements() > 1, |                 errors::InvalidArgument("Must have at least a mean value", |                                         gamma.shape(`
- Hunk `@@ -1,49 +1,19 @@   void Compute(OpKernelContext* context) override {` risk `40` safety `0` directions `candidate_removes_protection`
- Removed: `    const auto& input_min_tensor = context->input(1); |     OP_REQUIRES(context, input_min_tensor.NumElements() == 1, |                 errors::InvalidArgument("input_min must have`
- Added: `    const float input_min = context->input(1).flat<float>()(0); |     const float input_max = context->input(2).flat<float>()(0); |     const float mean_min = context->input(4).fla`

### 212339::pairctx

- Project/CVE/CWE: `icecast-server` / `CVE-2018-18820` / `cwe-119`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.40922078490257263`
- Support: `supported` risk `43` safety `2` net `41`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -1,50 +1,32 @@ static size_t handle_returned_header (void *ptr, size_t size, size_t nmemb, void *stream)` risk `43` safety `2` directions `candidate_adds_protection, candidate_removes_protection, candidate_removes_risk`
- Removed: `    size_t len = size * nmemb; |     if (client) { |  |         if (url->auth_header && len >= url->auth_header_len && strncasecmp(ptr, url->auth_header, url->auth_header_len) == 0`
- Added: `    size_t bytes = size * nmemb; |     if (client) |     { |         if (strncasecmp (ptr, url->auth_header, url->auth_header_len) == 0) |         if (strncasecmp (ptr, url->timeli`

### 196893::pairctx

- Project/CVE/CWE: `envoy` / `CVE-2022-21654` / `cwe-362`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.9948603510856628`
- Support: `supported` risk `39` safety `0` net `39`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -30,33 +30,4 @@                               sizeof(std::remove_reference<decltype(hash)>::type::value_type));` risk `39` safety `0` directions `candidate_removes_protection`
- Removed: ` |   rc = EVP_DigestUpdate(md.get(), &verify_trusted_ca_, sizeof(verify_trusted_ca_)); |   RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or("")); |  |   if (config_ !`

### 207990::pairctx

- Project/CVE/CWE: `pcre2` / `CVE-2022-1587` / `cwe-703`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.9719393253326416`
- Support: `supported` risk `37` safety `0` net `37`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -63,55 +60,39 @@     case OP_SBRA:` risk `28` safety `0` directions `candidate_removes_protection`
- Removed: `    if (recurse_check_bit(common, PRIVATE_DATA(cc))) |       length++; |     offset = GET2(cc, 1 + LINK_SIZE); |     if (recurse_check_bit(common, OVECTOR(offset << 1))) |       { `
- Added: `    length++; |     length += 2; |     if (common->capture_last_ptr != 0) |       capture_last_found = TRUE; |     if (common->optimized_cbracket[GET2(cc, 1 + LINK_SIZE)] == 0) |  `
- Hunk `@@ -146,29 +119,20 @@     break;` risk `9` safety `0` directions `candidate_removes_protection`
- Removed: `    offset = PRIVATE_DATA(cc); |     if (offset != 0 && recurse_check_bit(common, offset)) |     offset = PRIVATE_DATA(cc); |     if (offset != 0 && recurse_check_bit(common, offse`
- Added: `    if (PRIVATE_DATA(cc) != 0) |     if (PRIVATE_DATA(cc) != 0) |       length += 2; |     if (PRIVATE_DATA(cc) != 0) |       length += 2;`

### 202689::pairctx

- Project/CVE/CWE: `ruby` / `CVE-2009-4124` / `cwe-119`
- Gold/Pred/Correct: `1` / `1` / `True`
- Probability: `0.837619960308075`
- Support: `supported` risk `34` safety `2` net `32`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -30,49 +30,44 @@     llen = (jflag == 'l') ? 0 : ((jflag == 'r') ? n : n/2);` risk `31` safety `2` directions `candidate_removes_protection, candidate_removes_risk`
- Removed: `    if (flen > 1) { |        llen2 = str_offset(f, f + flen, llen % fclen, enc, singlebyte); |        rlen2 = str_offset(f, f + flen, rlen % fclen, enc, singlebyte); |     } |     `
- Added: `    res = rb_str_new5(str, 0, RSTRING_LEN(str)+n*flen/fclen+2); |     while (llen) { | 	if (flen <= 1) { | 	    *p++ = *f; | 	    llen--; | 	}`
- Hunk `@@ -6,7 +6,7 @@     VALUE res;` risk `3` safety `0` directions `candidate_removes_protection`
- Removed: `    long n, size, llen, rlen, llen2 = 0, rlen2 = 0;`
- Added: `    long n, llen, rlen;`

## Highest Safety-Support Hunks

### 253970::pairctx

- Project/CVE/CWE: `tensorflow` / `CVE-2021-37663` / `cwe-476`
- Gold/Pred/Correct: `0` / `0` / `True`
- Probability: `0.02898062765598297`
- Support: `supported` risk `0` safety `74` net `-74`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -5,7 +5,50 @@ ` risk `0` safety `74` directions `candidate_adds_protection`
- Added: `      OP_REQUIRES( |           ctx, input.dims() > axis_, |           errors::InvalidArgument( |               "Axis is on a zero-based index, so its value must always be less " | `

### 263524::pairctx

- Project/CVE/CWE: `tensorflow` / `CVE-2021-29547` / `cwe-369`
- Gold/Pred/Correct: `0` / `0` / `True`
- Probability: `0.31573596596717834`
- Support: `supported` risk `0` safety `72` net `-72`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -30,6 +60,33 @@     OP_REQUIRES(context, gamma.dims() == 1,` risk `0` safety `32` directions `candidate_adds_protection`
- Added: `    OP_REQUIRES(context, mean.NumElements() > 1, |                 errors::InvalidArgument("Must have at least a mean value", |                                         gamma.shape(`
- Hunk `@@ -1,19 +1,49 @@   void Compute(OpKernelContext* context) override {` risk `0` safety `40` directions `candidate_adds_protection`
- Removed: `    const float input_min = context->input(1).flat<float>()(0); |     const float input_max = context->input(2).flat<float>()(0); |     const float mean_min = context->input(4).fla`
- Added: `    const auto& input_min_tensor = context->input(1); |     OP_REQUIRES(context, input_min_tensor.NumElements() == 1, |                 errors::InvalidArgument("input_min must have`

### 457772::pairctx

- Project/CVE/CWE: `icecast-server` / `CVE-2018-18820` / `cwe-119`
- Gold/Pred/Correct: `0` / `0` / `True`
- Probability: `0.1919327974319458`
- Support: `supported` risk `2` safety `43` net `-41`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -1,32 +1,50 @@ static size_t handle_returned_header (void *ptr, size_t size, size_t nmemb, void *stream)` risk `2` safety `43` directions `candidate_adds_protection, candidate_removes_protection, candidate_introduces_risk`
- Removed: `    size_t bytes = size * nmemb; |     if (client) |     { |         if (strncasecmp (ptr, url->auth_header, url->auth_header_len) == 0) |         if (strncasecmp (ptr, url->timeli`
- Added: `    size_t len = size * nmemb; |     if (client) { |  |         if (url->auth_header && len >= url->auth_header_len && strncasecmp(ptr, url->auth_header, url->auth_header_len) == 0`

### 247550::pairctx

- Project/CVE/CWE: `envoy` / `CVE-2022-21654` / `cwe-362`
- Gold/Pred/Correct: `0` / `0` / `True`
- Probability: `0.0384661927819252`
- Support: `supported` risk `0` safety `39` net `-39`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -30,4 +30,33 @@                               sizeof(std::remove_reference<decltype(hash)>::type::value_type));` risk `0` safety `39` directions `candidate_adds_protection`
- Added: ` |   rc = EVP_DigestUpdate(md.get(), &verify_trusted_ca_, sizeof(verify_trusted_ca_)); |   RELEASE_ASSERT(rc == 1, Utility::getLastCryptoError().value_or("")); |  |   if (config_ !`

### 404192::pairctx

- Project/CVE/CWE: `pcre2` / `CVE-2022-1587` / `cwe-703`
- Gold/Pred/Correct: `0` / `0` / `True`
- Probability: `0.3775406777858734`
- Support: `supported` risk `0` safety `37` net `-37`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -60,39 +63,55 @@     case OP_SBRA:` risk `0` safety `28` directions `candidate_adds_protection`
- Removed: `    length++; |     length += 2; |     if (common->capture_last_ptr != 0) |       capture_last_found = TRUE; |     if (common->optimized_cbracket[GET2(cc, 1 + LINK_SIZE)] == 0) |  `
- Added: `    if (recurse_check_bit(common, PRIVATE_DATA(cc))) |       length++; |     offset = GET2(cc, 1 + LINK_SIZE); |     if (recurse_check_bit(common, OVECTOR(offset << 1))) |       { `
- Hunk `@@ -119,20 +146,29 @@     break;` risk `0` safety `9` directions `candidate_adds_protection`
- Removed: `    if (PRIVATE_DATA(cc) != 0) |     if (PRIVATE_DATA(cc) != 0) |       length += 2; |     if (PRIVATE_DATA(cc) != 0) |       length += 2;`
- Added: `    offset = PRIVATE_DATA(cc); |     if (offset != 0 && recurse_check_bit(common, offset)) |     offset = PRIVATE_DATA(cc); |     if (offset != 0 && recurse_check_bit(common, offse`

### 337027::pairctx

- Project/CVE/CWE: `ruby` / `CVE-2009-4124` / `cwe-119`
- Gold/Pred/Correct: `0` / `0` / `True`
- Probability: `0.19930797815322876`
- Support: `supported` risk `2` safety `34` net `-32`
- Gold support: `supported` pseudo-localization-correct `True`
- Hunk `@@ -30,44 +30,49 @@     llen = (jflag == 'l') ? 0 : ((jflag == 'r') ? n : n/2);` risk `2` safety `31` directions `candidate_adds_protection, candidate_introduces_risk`
- Removed: `    res = rb_str_new5(str, 0, RSTRING_LEN(str)+n*flen/fclen+2); |     while (llen) { | 	if (flen <= 1) { | 	    *p++ = *f; | 	    llen--; | 	}`
- Added: `    if (flen > 1) { |        llen2 = str_offset(f, f + flen, llen % fclen, enc, singlebyte); |        rlen2 = str_offset(f, f + flen, rlen % fclen, enc, singlebyte); |     } |     `
- Hunk `@@ -6,7 +6,7 @@     VALUE res;` risk `0` safety `3` directions `candidate_adds_protection`
- Removed: `    long n, llen, rlen;`
- Added: `    long n, size, llen, rlen, llen2 = 0, rlen2 = 0;`
