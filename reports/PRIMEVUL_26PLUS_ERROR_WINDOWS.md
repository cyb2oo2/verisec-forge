# PrimeVul Large-Diff Error Window Analysis

This report mines high-scoring diff windows from `26+` bucket predictions.

## Summary

- Threshold: `0.3`
- Rows: `159`
- TP/TN/FP/FN: `65` / `53` / `28` / `13`

## Aggregate Signals

- FP top keywords: `[('len', 21), ('size', 21), ('valid', 12), ('mem', 10), ('check', 8), ('length', 7), ('alloc', 7), ('free', 4), ('copy', 3), ('bound', 1), ('strlen', 1)]`
- FN top keywords: `[('len', 15), ('size', 13), ('mem', 8), ('free', 5), ('length', 4), ('valid', 4), ('alloc', 4), ('check', 2), ('strlen', 1)]`
- FP top directions: `[('candidate_adds_protection', 24), ('candidate_removes_protection', 12), ('direction_unclear', 9), ('candidate_removes_risk', 5), ('candidate_introduces_risk', 5)]`
- FN top directions: `[('candidate_removes_protection', 12), ('candidate_adds_protection', 5), ('direction_unclear', 4), ('candidate_introduces_risk', 3), ('candidate_removes_risk', 2)]`
- FP top projects: `[('tensorflow', 4), ('nDPI', 2), ('linux', 2), ('pcre2', 1), ('LibRaw', 1), ('perl5', 1), ('squid', 1), ('openssh-portable', 1)]`
- FN top projects: `[('nDPI', 3), ('php-src', 2), ('gpac', 2), ('radare2', 1), ('linux', 1), ('jerryscript', 1), ('ImageMagick6', 1), ('mariadb-connector-c', 1)]`

## Top False Positives

### 241321::pairctx

- Project: `nDPI`
- CWE: `cwe-125`
- Gold/Pred/Prob: `0` / `1` / `0.9967`
- Hunk `@@ -54,22 +55,30 @@       hmac_size = check_pkid_and_detect_hmac_size(ovpn_payload);` score `[3, 36, 1739]` changed `36` keywords `len, mem, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `        alen = ovpn_payload[P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size)]; | 	  session_remote = ovpn_payload + P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size) + 1 + alen * 4; |           if(me`
- Added: `	u_int16_t offset = P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size); | 	   |         alen = ovpn_payload[offset]; | 	 | 	  offset += 1 + alen * 4; | 	  if((offset+8) <= ovpn_payload_len) {`
- Hunk `@@ -7,11 +7,12 @@   u_int8_t alen;` score `[1, 7, 429]` changed `7` keywords `len` directions `candidate_adds_protection` deltas `protection=3, risk=0, safer=0`
- Removed: ` |   if(packet->payload_packet_len >= 40) { |       ovpn_payload += 2;`
- Added: `  /* No u_ */int16_t ovpn_payload_len = packet->payload_packet_len; |    |   if(ovpn_payload_len >= 40) { |       ovpn_payload += 2, ovpn_payload_len -= 2;;`

### 404192::pairctx

- Project: `pcre2`
- CWE: `cwe-703`
- Gold/Pred/Prob: `0` / `1` / `0.9965`
- Hunk `@@ -60,39 +63,55 @@     case OP_SBRA:` score `[4, 36, 2143]` changed `36` keywords `check, len, length, size` directions `candidate_adds_protection` deltas `protection=28, risk=0, safer=0`
- Removed: `    length++; |     length += 2; |     if (common->capture_last_ptr != 0) |       capture_last_found = TRUE; |     if (common->optimized_cbracket[GET2(cc, 1 + LINK_SIZE)] == 0) |  `
- Added: `    if (recurse_check_bit(common, PRIVATE_DATA(cc))) |       length++; |     offset = GET2(cc, 1 + LINK_SIZE); |     if (recurse_check_bit(common, OVECTOR(offset << 1))) |       { `
- Hunk `@@ -119,20 +146,29 @@     break;` score `[4, 19, 901]` changed `19` keywords `check, len, length, size` directions `candidate_adds_protection` deltas `protection=9, risk=0, safer=0`
- Removed: `    if (PRIVATE_DATA(cc) != 0) |     if (PRIVATE_DATA(cc) != 0) |       length += 2; |     if (PRIVATE_DATA(cc) != 0) |       length += 2;`
- Added: `    offset = PRIVATE_DATA(cc); |     if (offset != 0 && recurse_check_bit(common, offset)) |     offset = PRIVATE_DATA(cc); |     if (offset != 0 && recurse_check_bit(common, offse`

### 394100::pairctx

- Project: `LibRaw`
- CWE: `cwe-125`
- Gold/Pred/Prob: `0` / `1` / `0.9728`
- Hunk `@@ -101,20 +103,22 @@   tag_offset = offset;` score `[2, 8, 1025]` changed `8` keywords `check, len` directions `candidate_adds_protection` deltas `protection=2, risk=0, safer=0`
- Removed: `    if (tiff_sget (save, srf_buf, len, |         icWBC[Sony_SRF_wb_list[nWB]][i] = sget4(srf_buf + tag_dataoffset); |         cam_mul[i] = sget4(srf_buf + tag_dataoffset);`
- Added: `	  if (tiff_sget(save, srf_buf, len, | 		CHECKBUFFER_SGET4(tag_dataoffset); | 		icWBC[Sony_SRF_wb_list[nWB]][i] = sget4(srf_buf + tag_dataoffset); | 		CHECKBUFFER_SGET4(tag_dataoff`
- Hunk `@@ -17,10 +17,10 @@   INT64 srf_offset, tag_offset, tag_data, tag_dataoffset;` score `[2, 4, 344]` changed `4` keywords `alloc, len` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `  short entries; |   srf_buf = (uchar *)malloc(len);`
- Added: `  ushort entries; |   srf_buf = (uchar *)malloc(len+64);`

### 486837::pairctx

- Project: `perl5`
- CWE: `cwe-120`
- Gold/Pred/Prob: `0` / `1` / `0.971`
- Hunk `@@ -262,9 +268,10 @@ 		    }` score `[0, 7, 411]` changed `7` keywords `none` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `                if (PERL_ENABLE_TRIE_OPTIMISATION && |                         OP( startbranch ) == BRANCH ) |                 {`
- Added: `                if (PERL_ENABLE_TRIE_OPTIMISATION |                     && OP(startbranch) == BRANCH |                     && mutate_ok |                 ) {`
- Hunk `@@ -884,8 +894,9 @@                     &&   isALPHA_A(* STRING(next))` score `[0, 5, 532]` changed `5` keywords `none` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `                            && ! HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE(* STRING(next))))) |                 {`
- Added: `                            && ! HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE(* STRING(next)))) |                     &&   mutate_ok |                 ) {`

### 430470::pairctx

- Project: `squid`
- CWE: `cwe-400`
- Gold/Pred/Prob: `0` / `1` / `0.9654`
- Hunk `@@ -327,12 +323,11 @@ ` score `[3, 5, 366]` changed `5` keywords `len, length, size` directions `candidate_adds_protection` deltas `protection=2, risk=0, safer=0`
- Removed: `    if (outbuf.size() > 0) { |         entry->append(outbuf.rawBuf(), outbuf.size()); |     outbuf.clean();`
- Added: `    if (outbuf.length() > 0) { |         entry->append(outbuf.rawContent(), outbuf.length());`
- Hunk `@@ -216,34 +214,34 @@                         break;` score `[2, 28, 3389]` changed `28` keywords `mem, size` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-5, risk=-1, safer=-5`
- Removed: `                    memset(tmpbuf, '\0', TEMP_BUF_SIZE); |  |                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%`
- Added: `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n", |                                            icon_url, escaped_`

### 400219::pairctx

- Project: `openssh-portable`
- CWE: `cwe-399`
- Gold/Pred/Prob: `0` / `1` / `0.8794`
- Hunk `@@ -28,63 +27,44 @@ 		case SSH_AGENT_CONSTRAIN_CONFIRM:` score `[2, 51, 1885]` changed `51` keywords `free, valid` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-22, risk=-3, safer=0`
- Removed: `				goto err; | 				goto err; | 				goto err; | 				goto err; | 				goto err; | 			if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {`
- Added: `				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out;`
- Hunk `@@ -4,23 +4,22 @@ 	u_char ctype;` score `[1, 9, 655]` changed `9` keywords `valid` directions `candidate_removes_protection` deltas `protection=-2, risk=0, safer=0`
- Removed: `	char *ext_name = NULL; | 	struct sshbuf *b = NULL; | 			goto err; | 				goto err; | 				goto err;`
- Added: `			goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				goto out;`

### 457772::pairctx

- Project: `icecast-server`
- CWE: `cwe-119`
- Gold/Pred/Prob: `0` / `1` / `0.8669`
- Hunk `@@ -1,32 +1,50 @@ static size_t handle_returned_header (void *ptr, size_t size, size_t nmemb, void *stream)` score `[6, 54, 2741]` changed `54` keywords `copy, len, length, mem, size, valid` directions `candidate_adds_protection, candidate_removes_protection, candidate_introduces_risk` deltas `protection=43, risk=1, safer=-1`
- Removed: `    size_t bytes = size * nmemb; |     if (client) |     { |         if (strncasecmp (ptr, url->auth_header, url->auth_header_len) == 0) |         if (strncasecmp (ptr, url->timeli`
- Added: `    size_t len = size * nmemb; |     if (client) { |  |         if (url->auth_header && len >= url->auth_header_len && strncasecmp(ptr, url->auth_header, url->auth_header_len) == 0`

### 295511::pairctx

- Project: `hermes`
- CWE: `cwe-703`
- Gold/Pred/Prob: `0` / `1` / `0.8592`
- Hunk `@@ -94,6 +94,16 @@   runtime->invalidateCurrentIP();` score `[1, 10, 536]` changed `10` keywords `alloc` directions `candidate_introduces_risk` deltas `protection=0, risk=3, safer=0`
- Added: ` | /// \def DONT_CAPTURE_IP(expr) | /// \param expr A call expression to a function external to the interpreter. The | ///   expression should not make any allocations and the IP s`
- Hunk `@@ -892,24 +902,17 @@       }` score `[0, 25, 1039]` changed `25` keywords `none` directions `candidate_removes_protection` deltas `protection=-2, risk=0, safer=0`
- Removed: `        nextIP = IPADD(ip->iSaveGenerator.op1); |         goto doSaveGen; |         nextIP = IPADD(ip->iSaveGeneratorLong.op1); |         goto doSaveGen; |       } | `
- Added: `        DONT_CAPTURE_IP( |             saveGenerator(runtime, frameRegs, IPADD(ip->iSaveGenerator.op1))); |         ip = NEXTINST(SaveGenerator); |         DISPATCH; |         DONT`

## Top False Negatives

### 207755::pairctx

- Project: `php-src`
- CWE: `cwe-200`
- Gold/Pred/Prob: `1` / `0` / `0.0017`
- Hunk `@@ -41,22 +27,35 @@ 		key = (unsigned char*)password;` score `[4, 27, 1664]` changed `27` keywords `free, len, length, valid` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=13, risk=1, safer=0`
- Removed: `	free_iv = php_openssl_validate_iv(&iv, &iv_len, EVP_CIPHER_iv_length(cipher_type) TSRMLS_CC); | 	EVP_DecryptInit(&cipher_ctx, cipher_type, NULL, NULL); | 	EVP_DecryptInit_ex(&ciph`
- Added: `	max_iv_len = EVP_CIPHER_iv_length(cipher_type); | 	if (iv_len <= 0 && max_iv_len > 0) { | 		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Using an empty Initialization Vector (iv) `
- Hunk `@@ -1,35 +1,21 @@-PHP_FUNCTION(openssl_decrypt)` score `[1, 21, 1353]` changed `21` keywords `len` directions `candidate_removes_protection` deltas `protection=-12, risk=0, safer=0`
- Removed: `	zend_bool raw_input = 0; | 	int data_len, method_len, password_len, iv_len = 0; | 	int base64_str_len; | 	char *base64_str = NULL; | 	if (zend_parse_parameters(ZEND_NUM_ARGS() TSR`
- Added: `PHP_FUNCTION(openssl_encrypt) | 	zend_bool raw_output = 0; | 	int data_len, method_len, password_len, iv_len = 0, max_iv_len; | 	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC`

### 198095::pairctx

- Project: `radare2`
- CWE: `cwe-78`
- Gold/Pred/Prob: `1` / `0` / `0.002`
- Hunk `@@ -1,73 +1,138 @@ static int download(struct SPDBDownloader *pd) {` score `[7, 137, 5815]` changed `137` keywords `alloc, check, free, len, mem, size, strlen` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=30, risk=17, safer=0`
- Removed: ` | 	char *abspath_to_file = r_str_newf ("%s%s%s%s%s%s%s", | 		opt->symbol_store_path, R_SYS_DIR, | 		opt->dbg_file, R_SYS_DIR, | 		opt->guid, R_SYS_DIR, | 		opt->dbg_file);`
- Added: `	char *curl_cmd = NULL; | 	char *extractor_cmd = NULL; | 	char *abspath_to_archive = NULL; | 	char *abspath_to_file = NULL; | 	char *archive_name = NULL; | 	size_t archive_name_len`

### 202069::pairctx

- Project: `linux`
- CWE: `cwe-665`
- Gold/Pred/Prob: `1` / `0` / `0.0039`
- Hunk `@@ -225,44 +193,75 @@ ` score `[4, 49, 1933]` changed `49` keywords `alloc, len, mem, size` directions `candidate_adds_protection, candidate_removes_risk` deltas `protection=21, risk=-3, safer=0`
- Removed: `			goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 		goto err_set_expr_alloc; | err_set_expr_alloc:`
- Added: `			goto err_set_alloc_name; | 				goto err_set_init; | 				goto err_set_init; | 				goto err_set_init; | 	udata = NULL; | 	if (udlen) {`
- Hunk `@@ -176,45 +176,13 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name);` score `[4, 36, 1152]` changed `36` keywords `alloc, len, mem, size` directions `candidate_removes_protection` deltas `protection=-20, risk=0, safer=0`
- Removed: `		goto err_set_name; |  | 	udata = NULL; | 	if (udlen) { | 		udata = set->data + size; | 		nla_memcpy(udata, nla[NFTA_SET_USERDATA], udlen);`
- Added: `		goto err_set_alloc_name; | 			goto err_set_alloc_name;`

### 206588::pairctx

- Project: `php-src`
- CWE: `cwe-119`
- Gold/Pred/Prob: `1` / `0` / `0.0368`
- Hunk `@@ -1,71 +1,84 @@-void gdImageFillToBorder (gdImagePtr im, int x, int y, int border, int color)` score `[0, 140, 3207]` changed `140` keywords `none` directions `candidate_removes_protection` deltas `protection=-1, risk=0, safer=0`
- Removed: `	int lastBorder; | 	/* Seek left */ | 	int leftLimit = -1, rightLimit; | 	int i; |  | 	if (border < 0) {`
- Added: `gdImageFillToBorder (gdImagePtr im, int x, int y, int border, int color) |   int lastBorder; |   /* Seek left */ |   int leftLimit, rightLimit; |   int i; |   leftLimit = (-1);`

### 196624::pairctx

- Project: `nDPI`
- CWE: `cwe-125`
- Gold/Pred/Prob: `1` / `0` / `0.0457`
- Hunk `@@ -55,30 +54,22 @@       hmac_size = check_pkid_and_detect_hmac_size(ovpn_payload);` score `[3, 36, 1739]` changed `36` keywords `len, mem, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `	u_int16_t offset = P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size); | 	   |         alen = ovpn_payload[offset]; | 	 | 	  offset += 1 + alen * 4; | 	  if((offset+8) <= ovpn_payload_len) {`
- Added: `        alen = ovpn_payload[P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size)]; | 	  session_remote = ovpn_payload + P_PACKET_ID_ARRAY_LEN_OFFSET(hmac_size) + 1 + alen * 4; |           if(me`
- Hunk `@@ -7,12 +7,11 @@   u_int8_t alen;` score `[1, 7, 429]` changed `7` keywords `len` directions `candidate_removes_protection` deltas `protection=-3, risk=0, safer=0`
- Removed: `  /* No u_ */int16_t ovpn_payload_len = packet->payload_packet_len; |    |   if(ovpn_payload_len >= 40) { |       ovpn_payload += 2, ovpn_payload_len -= 2;;`
- Added: ` |   if(packet->payload_packet_len >= 40) { |       ovpn_payload += 2;`

### 195820::pairctx

- Project: `nDPI`
- CWE: `cwe-787`
- Gold/Pred/Prob: `1` / `0` / `0.0462`
- Hunk `@@ -210,36 +210,34 @@ 	i += 4 + extension_len, offset += 4 + extension_len;` score `[2, 28, 2420]` changed `28` keywords `len, size` directions `candidate_removes_protection` deltas `protection=-11, risk=0, safer=0`
- Removed: `      ja3_str_len = snprintf(ja3_str, JA3_STR_LEN, "%u,", ja3.server.tls_handshake_version); |  |       for(i=0; (i<ja3.server.num_cipher) && (JA3_STR_LEN > ja3_str_len); i++) { | `
- Added: `      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.server.tls_handshake_version); |  |       for(i=0; i<ja3.server.num_cipher; i++) { | 	rc = snprintf(&ja3_str[ja3_s`
- Hunk `@@ -825,47 +823,47 @@ 	      int rc;` score `[2, 18, 2833]` changed `18` keywords `len, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `	      ja3_str_len = snprintf(ja3_str, JA3_STR_LEN, "%u,", ja3.client.tls_handshake_version); | 		rc = snprintf(&ja3_str[ja3_str_len], JA3_STR_LEN-ja3_str_len, "%s%u", | 	      rc `
- Added: `	      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.client.tls_handshake_version); | 		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", | 	 `

### 198440::pairctx

- Project: `jerryscript`
- CWE: `cwe-703`
- Gold/Pred/Prob: `1` / `0` / `0.0782`
- Hunk `@@ -910,41 +916,29 @@     }` score `[3, 44, 2216]` changed `44` keywords `alloc, mem, size` directions `candidate_removes_protection` deltas `protection=-24, risk=0, safer=0`
- Removed: `    if (JERRY_UNLIKELY (context_p->error != PARSER_ERR_OUT_OF_MEMORY)) |       /* Ignore the errors thrown by the lexer. */ |       context_p->error = PARSER_ERR_NO_ERROR; |  |    `
- Added: `    /* The following code may allocate memory, so it is enclosed in a try/catch. */ |     PARSER_TRY (context_p->try_buffer) | #if ENABLED (JERRY_ES2015) |       if (scanner_contex`
- Hunk `@@ -954,10 +948,12 @@         parser_list_free (&literal_pool_p->literal_pool);` score `[1, 8, 407]` changed `8` keywords `free` directions `candidate_adds_protection, candidate_removes_risk` deltas `protection=3, risk=-1, safer=0`
- Removed: ` |       parser_stack_free (context_p); |       return;`
- Added: `    PARSER_TRY_END |  | #if ENABLED (JERRY_ES2015) |     context_p->status_flags &= (uint32_t) ~PARSER_IS_GENERATOR_FUNCTION; | #endif /* ENABLED (JERRY_ES2015) */`

### 206422::pairctx

- Project: `ImageMagick6`
- CWE: `cwe-125`
- Gold/Pred/Prob: `1` / `0` / `0.0882`
- Hunk `@@ -217,29 +217,31 @@   else` score `[3, 46, 2165]` changed `46` keywords `free, mem, size` directions `candidate_adds_protection` deltas `protection=1, risk=0, safer=0`
- Removed: `    heif_chroma_420,decode_options); |     heif_decoding_options_free(decode_options); |   if (IsHeifSuccess(&error,image) == MagickFalse) |     { |       heif_image_handle_release`
- Added: `    heif_chroma_420,NULL); |   if (IsHeifSuccess(&error,image) == MagickFalse) |     { |       heif_image_handle_release(image_handle); |       heif_context_free(heif_context); |  `
