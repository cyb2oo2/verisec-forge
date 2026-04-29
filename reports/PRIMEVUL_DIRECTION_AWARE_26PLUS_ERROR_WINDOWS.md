# PrimeVul Large-Diff Error Window Analysis

This report mines high-scoring diff windows from `26+` bucket predictions.

## Summary

- Threshold: `0.4`
- Rows: `159`
- TP/TN/FP/FN: `54` / `69` / `12` / `24`

## Aggregate Signals

- FP top keywords: `[('len', 8), ('size', 7), ('valid', 6), ('free', 5), ('mem', 4), ('length', 4), ('alloc', 2), ('check', 2), ('strlen', 1), ('bound', 1)]`
- FN top keywords: `[('size', 24), ('mem', 15), ('len', 14), ('alloc', 10), ('valid', 9), ('free', 6), ('length', 6), ('copy', 4), ('strlen', 2), ('check', 2), ('strcat', 1)]`
- FP top directions: `[('candidate_removes_protection', 7), ('candidate_adds_protection', 7), ('direction_unclear', 5), ('candidate_removes_risk', 3), ('candidate_introduces_risk', 1)]`
- FN top directions: `[('candidate_adds_protection', 18), ('candidate_removes_protection', 12), ('direction_unclear', 10), ('candidate_introduces_risk', 9), ('candidate_removes_risk', 3)]`
- FP top projects: `[('ImageMagick', 1), ('cyrus-imapd', 1), ('radare2', 1), ('tensorflow', 1), ('linux', 1), ('php-src', 1), ('gpac', 1), ('libjpeg', 1)]`
- FN top projects: `[('tensorflow', 4), ('linux', 2), ('squid', 2), ('php-src', 2), ('openssh-portable', 1), ('libssh2', 1), ('libjpeg', 1), ('ImageMagick6', 1)]`

## Top False Positives

### 459319::pairctx

- Project: `ImageMagick`
- CWE: `cwe-125`
- Gold/Pred/Prob: `0` / `1` / `0.9033`
- Hunk `@@ -84,26 +84,24 @@     (void) SetImageProperty(image,"exif:Orientation","1",exception);` score `[2, 26, 1659]` changed `26` keywords `free, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `  if (decode_options != (struct heif_decoding_options *) NULL) |       /* |         Correct the width and height of the image. |       */ |       image->columns=(size_t) heif_image`
- Added: `  if (decode_options != (struct heif_decoding_options *) NULL) |     heif_decoding_options_free(decode_options); |   /* |     Correct the width and height of the image. |   */ |   `

### 463134::pairctx

- Project: `cyrus-imapd`
- CWE: `cwe-732`
- Gold/Pred/Prob: `0` / `1` / `0.7074`
- Hunk `@@ -25,24 +25,24 @@ ` score `[2, 26, 1233]` changed `26` keywords `len, mem` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `        struct annotate_metadata oldmdata; |         r = read_old_value(d, key, keylen, &oldval, &oldmdata); |         if (r) goto out; |  |         /* if the value is identical, d`
- Added: `    struct annotate_metadata oldmdata; |     r = read_old_value(d, key, keylen, &oldval, &oldmdata); |     if (r) goto out; |  |     /* if the value is identical, don't touch the m`

### 268829::pairctx

- Project: `radare2`
- CWE: `cwe-78`
- Gold/Pred/Prob: `0` / `1` / `0.6478`
- Hunk `@@ -1,138 +1,73 @@ static int download(struct SPDBDownloader *pd) {` score `[7, 137, 5815]` changed `137` keywords `alloc, check, free, len, mem, size, strlen` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-30, risk=-17, safer=0`
- Removed: `	char *curl_cmd = NULL; | 	char *extractor_cmd = NULL; | 	char *abspath_to_archive = NULL; | 	char *abspath_to_file = NULL; | 	char *archive_name = NULL; | 	size_t archive_name_len`
- Added: ` | 	char *abspath_to_file = r_str_newf ("%s%s%s%s%s%s%s", | 		opt->symbol_store_path, R_SYS_DIR, | 		opt->dbg_file, R_SYS_DIR, | 		opt->guid, R_SYS_DIR, | 		opt->dbg_file);`

### 220804::pairctx

- Project: `tensorflow`
- CWE: `cwe-787`
- Gold/Pred/Prob: `0` / `1` / `0.6095`
- Hunk `@@ -19,64 +14,40 @@               "; values shape: ", values.shape().DebugString()));` score `[2, 64, 3924]` changed `64` keywords `size, valid` directions `candidate_removes_protection` deltas `protection=-19, risk=0, safer=0`
- Removed: `    OP_REQUIRES(context, shape.NumElements() != 0, |                 errors::InvalidArgument( |                     "The shape argument requires at least one element.")); |  |     `
- Added: `    const auto splits_values = splits.flat<int64_t>(); |     const auto values_values = values.flat<T>(); |     const auto weight_values = weights.flat<W>(); |     int num_batches `
- Hunk `@@ -1,14 +1,9 @@   void Compute(OpKernelContext* context) override {` score `[1, 11, 719]` changed `11` keywords `valid` directions `candidate_removes_protection` deltas `protection=-4, risk=0, safer=0`
- Removed: `    const Tensor& indices = context->input(0); |     const Tensor& shape = context->input(2); |     const Tensor& weights = context->input(3); |  |     OP_REQUIRES(context, TensorS`
- Added: `    const Tensor& splits = context->input(0); |     const Tensor& weights = context->input(2); |     bool is_1d = false;`

### 328523::pairctx

- Project: `linux`
- CWE: `cwe-787`
- Gold/Pred/Prob: `0` / `1` / `0.5851`
- Hunk `@@ -1,34 +1,35 @@-static void scalar32_min_max_or(struct bpf_reg_state *dst_reg,` score `[1, 36, 2029]` changed `36` keywords `bound` directions `candidate_adds_protection, candidate_removes_protection` deltas `protection=2, risk=0, safer=-1`
- Removed: `				struct bpf_reg_state *src_reg) | 	bool src_known = tnum_subreg_is_const(src_reg->var_off); | 	bool dst_known = tnum_subreg_is_const(dst_reg->var_off); | 	struct tnum var32_off `
- Added: `static void scalar_min_max_or(struct bpf_reg_state *dst_reg, | 			      struct bpf_reg_state *src_reg) | 	bool src_known = tnum_is_const(src_reg->var_off); | 	bool dst_known = tnum`

### 400779::pairctx

- Project: `php-src`
- CWE: `cwe-200`
- Gold/Pred/Prob: `0` / `1` / `0.5622`
- Hunk `@@ -27,35 +41,22 @@ 		key = (unsigned char*)password;` score `[4, 27, 1664]` changed `27` keywords `free, len, length, valid` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-13, risk=-1, safer=0`
- Removed: `	max_iv_len = EVP_CIPHER_iv_length(cipher_type); | 	if (iv_len <= 0 && max_iv_len > 0) { | 		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Using an empty Initialization Vector (iv) `
- Added: `	free_iv = php_openssl_validate_iv(&iv, &iv_len, EVP_CIPHER_iv_length(cipher_type) TSRMLS_CC); | 	EVP_DecryptInit(&cipher_ctx, cipher_type, NULL, NULL); | 	EVP_DecryptInit_ex(&ciph`
- Hunk `@@ -1,21 +1,35 @@-PHP_FUNCTION(openssl_encrypt)` score `[1, 21, 1353]` changed `21` keywords `len` directions `candidate_adds_protection` deltas `protection=12, risk=0, safer=0`
- Removed: `	zend_bool raw_output = 0; | 	int data_len, method_len, password_len, iv_len = 0, max_iv_len; | 	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|bs", &data, &data_len, &m`
- Added: `PHP_FUNCTION(openssl_decrypt) | 	zend_bool raw_input = 0; | 	int data_len, method_len, password_len, iv_len = 0; | 	int base64_str_len; | 	char *base64_str = NULL; | 	if (zend_pars`

### 243213::pairctx

- Project: `gpac`
- CWE: `cwe-401`
- Gold/Pred/Prob: `0` / `1` / `0.5506`
- Hunk `@@ -522,23 +522,27 @@ 		fprintf(stderr, "\tAOM AV1 stream - Resolution %d x %d\n", w, h);` score `[2, 38, 2541]` changed `38` keywords `len, length` directions `candidate_adds_protection` deltas `protection=2, risk=0, safer=0`
- Removed: `		fprintf(stderr, "\tversion=%u, profile=%u, level_idx0=%u, tier=%u\n", (u32)av1c->version, (u32)av1c->seq_profile, (u32)av1c->seq_level_idx_0, (u32)av1c->seq_tier_0); | 		fprintf(`
- Added: `		if (!av1c) { | 			fprintf(stderr, "\tCorrupted av1 config\n"); | 		} else { | 			fprintf(stderr, "\tversion=%u, profile=%u, level_idx0=%u, tier=%u\n", (u32)av1c->version, (u32)av`

### 259619::pairctx

- Project: `libjpeg`
- CWE: `cwe-787`
- Gold/Pred/Prob: `0` / `1` / `0.5506`
- Hunk `@@ -1,35 +1,34 @@-void HierarchicalBitmapRequester::PrepareForDecoding(void)` score `[3, 34, 2144]` changed `34` keywords `alloc, mem, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: ` |   UBYTE i; |  |   if (m_ppDecodingMCU == NULL) { |     m_ppDecodingMCU = (struct Line **)m_pEnviron->AllocMem(sizeof(struct Line *) * m_ucCount*8); |     memset(m_ppDecodingMCU,`
- Added: `void HierarchicalBitmapRequester::PrepareForEncoding(void) |    |   if (m_ppEncodingMCU == NULL) { |     m_ppEncodingMCU = (struct Line **)m_pEnviron->AllocMem(sizeof(struct Line *`

## Top False Negatives

### 196800::pairctx

- Project: `tensorflow`
- CWE: `cwe-787`
- Gold/Pred/Prob: `1` / `0` / `0.0328`
- Hunk `@@ -1,18 +1,52 @@   void Compute(OpKernelContext* ctx) override {` score `[3, 58, 3335]` changed `58` keywords `alloc, size, valid` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=31, risk=2, safer=0`
- Removed: ` |     // One global scale. |     Tensor input_min_tensor(DataTypeToEnum<T>::value, TensorShape()); |     Tensor input_max_tensor(DataTypeToEnum<T>::value, TensorShape()); |     //`
- Added: `    const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_); |     Tensor input_min_tensor; |     Tensor input_max_tensor; |     if (range_given_) { |       input_min_tensor = `

### 207709::pairctx

- Project: `openssh-portable`
- CWE: `cwe-399`
- Gold/Pred/Prob: `1` / `0` / `0.0647`
- Hunk `@@ -27,44 +28,63 @@ 		case SSH_AGENT_CONSTRAIN_CONFIRM:` score `[2, 51, 1885]` changed `51` keywords `free, valid` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=22, risk=3, safer=0`
- Removed: `				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out;`
- Added: `				goto err; | 				goto err; | 				goto err; | 				goto err; | 				goto err; | 			if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {`
- Hunk `@@ -4,22 +4,23 @@ 	u_char ctype;` score `[1, 9, 655]` changed `9` keywords `valid` directions `candidate_adds_protection` deltas `protection=2, risk=0, safer=0`
- Removed: `			goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				goto out;`
- Added: `	char *ext_name = NULL; | 	struct sshbuf *b = NULL; | 			goto err; | 				goto err; | 				goto err;`

### 195648::pairctx

- Project: `libssh2`
- CWE: `cwe-703`
- Gold/Pred/Prob: `1` / `0` / `0.0693`
- Hunk `@@ -55,23 +55,33 @@ ` score `[2, 42, 2136]` changed `42` keywords `len, size` directions `candidate_adds_protection` deltas `protection=16, risk=0, safer=0`
- Removed: `                uint32_t reason = 0; |                 struct string_buf buf; |                 buf.data = (unsigned char *)data; |                 buf.dataptr = buf.data; |       `
- Added: `                size_t reason = _libssh2_ntohu32(data + 1); |  |                 if(datalen >= 9) { |                     message_len = _libssh2_ntohu32(data + 5); |  |            `
- Hunk `@@ -112,24 +122,24 @@                 int always_display = data[1];` score `[1, 30, 1747]` changed `30` keywords `len` directions `candidate_adds_protection` deltas `protection=8, risk=0, safer=0`
- Removed: `                    struct string_buf buf; |                     buf.data = (unsigned char *)data; |                     buf.dataptr = buf.data; |                     buf.len = dat`
- Added: `                    message_len = _libssh2_ntohu32(data + 2); |  |                     if(message_len <= (datalen - 10)) { |                         /* 6 = packet_type(1) + display`

### 197511::pairctx

- Project: `libjpeg`
- CWE: `cwe-787`
- Gold/Pred/Prob: `1` / `0` / `0.0737`
- Hunk `@@ -1,34 +1,35 @@-void HierarchicalBitmapRequester::PrepareForEncoding(void)` score `[3, 34, 2144]` changed `34` keywords `alloc, mem, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `   |   if (m_ppEncodingMCU == NULL) { |     m_ppEncodingMCU = (struct Line **)m_pEnviron->AllocMem(sizeof(struct Line *) * m_ucCount *8); |     memset(m_ppEncodingMCU,0,sizeof(stru`
- Added: `void HierarchicalBitmapRequester::PrepareForDecoding(void) |  |   UBYTE i; |  |   if (m_ppDecodingMCU == NULL) { |     m_ppDecodingMCU = (struct Line **)m_pEnviron->AllocMem(sizeof`

### 202069::pairctx

- Project: `linux`
- CWE: `cwe-665`
- Gold/Pred/Prob: `1` / `0` / `0.0947`
- Hunk `@@ -225,44 +193,75 @@ ` score `[4, 49, 1933]` changed `49` keywords `alloc, len, mem, size` directions `candidate_adds_protection, candidate_removes_risk` deltas `protection=21, risk=-3, safer=0`
- Removed: `			goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 		goto err_set_expr_alloc; | err_set_expr_alloc:`
- Added: `			goto err_set_alloc_name; | 				goto err_set_init; | 				goto err_set_init; | 				goto err_set_init; | 	udata = NULL; | 	if (udlen) {`
- Hunk `@@ -176,45 +176,13 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name);` score `[4, 36, 1152]` changed `36` keywords `alloc, len, mem, size` directions `candidate_removes_protection` deltas `protection=-20, risk=0, safer=0`
- Removed: `		goto err_set_name; |  | 	udata = NULL; | 	if (udlen) { | 		udata = set->data + size; | 		nla_memcpy(udata, nla[NFTA_SET_USERDATA], udlen);`
- Added: `		goto err_set_alloc_name; | 			goto err_set_alloc_name;`

### 206422::pairctx

- Project: `ImageMagick6`
- CWE: `cwe-125`
- Gold/Pred/Prob: `1` / `0` / `0.1136`
- Hunk `@@ -217,29 +217,31 @@   else` score `[3, 46, 2165]` changed `46` keywords `free, mem, size` directions `candidate_adds_protection` deltas `protection=1, risk=0, safer=0`
- Removed: `    heif_chroma_420,decode_options); |     heif_decoding_options_free(decode_options); |   if (IsHeifSuccess(&error,image) == MagickFalse) |     { |       heif_image_handle_release`
- Added: `    heif_chroma_420,NULL); |   if (IsHeifSuccess(&error,image) == MagickFalse) |     { |       heif_image_handle_release(image_handle); |       heif_context_free(heif_context); |  `

### 212425::pairctx

- Project: `ImageMagick`
- CWE: `cwe-125`
- Gold/Pred/Prob: `1` / `0` / `0.1251`
- Hunk `@@ -84,24 +84,26 @@     (void) SetImageProperty(image,"exif:Orientation","1",exception);` score `[2, 26, 1659]` changed `26` keywords `free, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `  if (decode_options != (struct heif_decoding_options *) NULL) |     heif_decoding_options_free(decode_options); |   /* |     Correct the width and height of the image. |   */ |   `
- Added: `  if (decode_options != (struct heif_decoding_options *) NULL) |       /* |         Correct the width and height of the image. |       */ |       image->columns=(size_t) heif_image`

### 203616::pairctx

- Project: `libssh-mirror`
- CWE: `cwe-476`
- Gold/Pred/Prob: `1` / `0` / `0.1403`
- Hunk `@@ -1,25 +1,25 @@-void *ssh_buffer_allocate(struct ssh_buffer_struct *buffer, uint32_t len)` score `[3, 39, 1084]` changed `39` keywords `alloc, len, mem` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=3, risk=1, safer=0`
- Removed: `    void *ptr; |     buffer_verify(buffer); |     if (buffer->used + len < len) { |         return NULL; |     if (buffer->allocated < (buffer->used + len)) { |         if (buffer-`
- Added: `int ssh_buffer_add_data(struct ssh_buffer_struct *buffer, const void *data, uint32_t len) |   buffer_verify(buffer); |   if (data == NULL) { |       return -1; |   } | `
