# PrimeVul Large-Diff Error Window Analysis

This report mines high-scoring diff windows from `26+` bucket predictions.

## Summary

- Threshold: `0.8`
- Rows: `159`
- TP/TN/FP/FN: `53` / `73` / `8` / `25`

## Aggregate Signals

- FP top keywords: `[('size', 7), ('len', 7), ('valid', 6), ('free', 5), ('mem', 4), ('alloc', 4), ('length', 1), ('check', 1), ('strlen', 1)]`
- FN top keywords: `[('size', 26), ('len', 21), ('mem', 12), ('alloc', 11), ('valid', 10), ('length', 8), ('free', 6), ('copy', 4), ('check', 3), ('strlen', 3), ('strcat', 1), ('sprintf', 1)]`
- FP top directions: `[('candidate_removes_protection', 11), ('candidate_removes_risk', 5), ('candidate_adds_protection', 3), ('candidate_introduces_risk', 2)]`
- FN top directions: `[('candidate_adds_protection', 18), ('candidate_removes_protection', 15), ('candidate_introduces_risk', 11), ('direction_unclear', 11), ('candidate_removes_risk', 2)]`
- FP top projects: `[('tensorflow', 2), ('php-src', 1), ('ImageMagick6', 1), ('radare2', 1), ('openssh-portable', 1), ('libssh2', 1), ('linux', 1)]`
- FN top projects: `[('tensorflow', 3), ('linux', 3), ('squid', 2), ('libssh-mirror', 1), ('ImageMagick', 1), ('libjpeg', 1), ('openssh-portable', 1), ('ImageMagick6', 1)]`

## Top False Positives

### 220804::pairctx

- Project: `tensorflow`
- CWE: `cwe-787`
- Gold/Pred/Prob: `0` / `1` / `0.9721`
- Hunk `@@ -19,64 +14,40 @@               "; values shape: ", values.shape().DebugString()));` score `[2, 64, 3924]` changed `64` keywords `size, valid` directions `candidate_removes_protection` deltas `protection=-19, risk=0, safer=0`
- Removed: `    OP_REQUIRES(context, shape.NumElements() != 0, |                 errors::InvalidArgument( |                     "The shape argument requires at least one element.")); |  |     `
- Added: `    const auto splits_values = splits.flat<int64_t>(); |     const auto values_values = values.flat<T>(); |     const auto weight_values = weights.flat<W>(); |     int num_batches `
- Hunk `@@ -1,14 +1,9 @@   void Compute(OpKernelContext* context) override {` score `[1, 11, 719]` changed `11` keywords `valid` directions `candidate_removes_protection` deltas `protection=-4, risk=0, safer=0`
- Removed: `    const Tensor& indices = context->input(0); |     const Tensor& shape = context->input(2); |     const Tensor& weights = context->input(3); |  |     OP_REQUIRES(context, TensorS`
- Added: `    const Tensor& splits = context->input(0); |     const Tensor& weights = context->input(2); |     bool is_1d = false;`

### 400779::pairctx

- Project: `php-src`
- CWE: `cwe-200`
- Gold/Pred/Prob: `0` / `1` / `0.9656`
- Hunk `@@ -27,35 +41,22 @@ 		key = (unsigned char*)password;` score `[4, 27, 1664]` changed `27` keywords `free, len, length, valid` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-13, risk=-1, safer=0`
- Removed: `	max_iv_len = EVP_CIPHER_iv_length(cipher_type); | 	if (iv_len <= 0 && max_iv_len > 0) { | 		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Using an empty Initialization Vector (iv) `
- Added: `	free_iv = php_openssl_validate_iv(&iv, &iv_len, EVP_CIPHER_iv_length(cipher_type) TSRMLS_CC); | 	EVP_DecryptInit(&cipher_ctx, cipher_type, NULL, NULL); | 	EVP_DecryptInit_ex(&ciph`
- Hunk `@@ -1,21 +1,35 @@-PHP_FUNCTION(openssl_encrypt)` score `[1, 21, 1353]` changed `21` keywords `len` directions `candidate_adds_protection` deltas `protection=12, risk=0, safer=0`
- Removed: `	zend_bool raw_output = 0; | 	int data_len, method_len, password_len, iv_len = 0, max_iv_len; | 	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|bs", &data, &data_len, &m`
- Added: `PHP_FUNCTION(openssl_decrypt) | 	zend_bool raw_input = 0; | 	int data_len, method_len, password_len, iv_len = 0; | 	int base64_str_len; | 	char *base64_str = NULL; | 	if (zend_pars`

### 381036::pairctx

- Project: `ImageMagick6`
- CWE: `cwe-125`
- Gold/Pred/Prob: `0` / `1` / `0.9225`
- Hunk `@@ -225,23 +227,19 @@       file_data=RelinquishMagickMemory(file_data);` score `[3, 30, 1516]` changed `30` keywords `free, mem, size` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-4, risk=-1, safer=0`
- Removed: `  if (decode_options != (struct heif_decoding_options *) NULL) |     { |       /* |         Correct the width and height of the image. |       */ |       image->columns=(size_t) he`
- Added: `  /* |     Correct the width and height of the image. |   */ |   image->columns=(size_t) heif_image_get_width(heif_image,heif_channel_Y); |   image->rows=(size_t) heif_image_get_he`
- Hunk `@@ -217,7 +217,9 @@   else` score `[1, 4, 446]` changed `4` keywords `free` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=3, risk=1, safer=0`
- Removed: `    heif_chroma_420,NULL);`
- Added: `    heif_chroma_420,decode_options); |   if (decode_options != (struct heif_decoding_options *) NULL) |     heif_decoding_options_free(decode_options);`

### 268829::pairctx

- Project: `radare2`
- CWE: `cwe-78`
- Gold/Pred/Prob: `0` / `1` / `0.9185`
- Hunk `@@ -1,138 +1,73 @@ static int download(struct SPDBDownloader *pd) {` score `[7, 137, 5815]` changed `137` keywords `alloc, check, free, len, mem, size, strlen` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-30, risk=-17, safer=0`
- Removed: `	char *curl_cmd = NULL; | 	char *extractor_cmd = NULL; | 	char *abspath_to_archive = NULL; | 	char *abspath_to_file = NULL; | 	char *archive_name = NULL; | 	size_t archive_name_len`
- Added: ` | 	char *abspath_to_file = r_str_newf ("%s%s%s%s%s%s%s", | 		opt->symbol_store_path, R_SYS_DIR, | 		opt->dbg_file, R_SYS_DIR, | 		opt->guid, R_SYS_DIR, | 		opt->dbg_file);`

### 400219::pairctx

- Project: `openssh-portable`
- CWE: `cwe-399`
- Gold/Pred/Prob: `0` / `1` / `0.9137`
- Hunk `@@ -28,63 +27,44 @@ 		case SSH_AGENT_CONSTRAIN_CONFIRM:` score `[2, 51, 1885]` changed `51` keywords `free, valid` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-22, risk=-3, safer=0`
- Removed: `				goto err; | 				goto err; | 				goto err; | 				goto err; | 				goto err; | 			if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {`
- Added: `				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out;`
- Hunk `@@ -4,23 +4,22 @@ 	u_char ctype;` score `[1, 9, 655]` changed `9` keywords `valid` directions `candidate_removes_protection` deltas `protection=-2, risk=0, safer=0`
- Removed: `	char *ext_name = NULL; | 	struct sshbuf *b = NULL; | 			goto err; | 				goto err; | 				goto err;`
- Added: `			goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				goto out;`

### 229853::pairctx

- Project: `libssh2`
- CWE: `cwe-703`
- Gold/Pred/Prob: `0` / `1` / `0.9093`
- Hunk `@@ -55,33 +55,23 @@ ` score `[2, 42, 2136]` changed `42` keywords `len, size` directions `candidate_removes_protection` deltas `protection=-16, risk=0, safer=0`
- Removed: `                size_t reason = _libssh2_ntohu32(data + 1); |  |                 if(datalen >= 9) { |                     message_len = _libssh2_ntohu32(data + 5); |  |            `
- Added: `                uint32_t reason = 0; |                 struct string_buf buf; |                 buf.data = (unsigned char *)data; |                 buf.dataptr = buf.data; |       `
- Hunk `@@ -122,24 +112,24 @@                 int always_display = data[1];` score `[1, 30, 1747]` changed `30` keywords `len` directions `candidate_removes_protection` deltas `protection=-8, risk=0, safer=0`
- Removed: `                    message_len = _libssh2_ntohu32(data + 2); |  |                     if(message_len <= (datalen - 10)) { |                         /* 6 = packet_type(1) + display`
- Added: `                    struct string_buf buf; |                     buf.data = (unsigned char *)data; |                     buf.dataptr = buf.data; |                     buf.len = dat`

### 245427::pairctx

- Project: `tensorflow`
- CWE: `cwe-787`
- Gold/Pred/Prob: `0` / `1` / `0.8791`
- Hunk `@@ -1,52 +1,18 @@   void Compute(OpKernelContext* ctx) override {` score `[3, 58, 3335]` changed `58` keywords `alloc, size, valid` directions `candidate_removes_protection, candidate_removes_risk` deltas `protection=-31, risk=-2, safer=0`
- Removed: `    const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_); |     Tensor input_min_tensor; |     Tensor input_max_tensor; |     if (range_given_) { |       input_min_tensor = `
- Added: ` |     // One global scale. |     Tensor input_min_tensor(DataTypeToEnum<T>::value, TensorShape()); |     Tensor input_max_tensor(DataTypeToEnum<T>::value, TensorShape()); |     //`

### 328360::pairctx

- Project: `linux`
- CWE: `cwe-665`
- Gold/Pred/Prob: `0` / `1` / `0.8549`
- Hunk `@@ -193,75 +225,44 @@ ` score `[4, 49, 1978]` changed `49` keywords `alloc, len, mem, size` directions `candidate_removes_protection, candidate_introduces_risk` deltas `protection=-21, risk=3, safer=0`
- Removed: `			goto err_set_alloc_name; | 				goto err_set_init; | 				goto err_set_init; | 				goto err_set_init; | 	udata = NULL; | 	if (udlen) {`
- Added: `			goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 				goto err_set_expr_alloc; | 		goto err_set_expr_alloc; | err_set_expr_alloc:`
- Hunk `@@ -176,13 +176,45 @@ 	err = nf_tables_set_alloc_name(&ctx, set, name);` score `[4, 36, 1152]` changed `36` keywords `alloc, len, mem, size` directions `candidate_adds_protection` deltas `protection=20, risk=0, safer=0`
- Removed: `		goto err_set_alloc_name; | 			goto err_set_alloc_name;`
- Added: `		goto err_set_name; |  | 	udata = NULL; | 	if (udlen) { | 		udata = set->data + size; | 		nla_memcpy(udata, nla[NFTA_SET_USERDATA], udlen);`

## Top False Negatives

### 203616::pairctx

- Project: `libssh-mirror`
- CWE: `cwe-476`
- Gold/Pred/Prob: `1` / `0` / `0.1152`
- Hunk `@@ -1,25 +1,25 @@-void *ssh_buffer_allocate(struct ssh_buffer_struct *buffer, uint32_t len)` score `[3, 39, 1084]` changed `39` keywords `alloc, len, mem` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=3, risk=1, safer=0`
- Removed: `    void *ptr; |     buffer_verify(buffer); |     if (buffer->used + len < len) { |         return NULL; |     if (buffer->allocated < (buffer->used + len)) { |         if (buffer-`
- Added: `int ssh_buffer_add_data(struct ssh_buffer_struct *buffer, const void *data, uint32_t len) |   buffer_verify(buffer); |   if (data == NULL) { |       return -1; |   } | `

### 212425::pairctx

- Project: `ImageMagick`
- CWE: `cwe-125`
- Gold/Pred/Prob: `1` / `0` / `0.1152`
- Hunk `@@ -84,24 +84,26 @@     (void) SetImageProperty(image,"exif:Orientation","1",exception);` score `[2, 26, 1659]` changed `26` keywords `free, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `  if (decode_options != (struct heif_decoding_options *) NULL) |     heif_decoding_options_free(decode_options); |   /* |     Correct the width and height of the image. |   */ |   `
- Added: `  if (decode_options != (struct heif_decoding_options *) NULL) |       /* |         Correct the width and height of the image. |       */ |       image->columns=(size_t) heif_image`

### 197511::pairctx

- Project: `libjpeg`
- CWE: `cwe-787`
- Gold/Pred/Prob: `1` / `0` / `0.1285`
- Hunk `@@ -1,34 +1,35 @@-void HierarchicalBitmapRequester::PrepareForEncoding(void)` score `[3, 34, 2144]` changed `34` keywords `alloc, mem, size` directions `direction_unclear` deltas `protection=0, risk=0, safer=0`
- Removed: `   |   if (m_ppEncodingMCU == NULL) { |     m_ppEncodingMCU = (struct Line **)m_pEnviron->AllocMem(sizeof(struct Line *) * m_ucCount *8); |     memset(m_ppEncodingMCU,0,sizeof(stru`
- Added: `void HierarchicalBitmapRequester::PrepareForDecoding(void) |  |   UBYTE i; |  |   if (m_ppDecodingMCU == NULL) { |     m_ppDecodingMCU = (struct Line **)m_pEnviron->AllocMem(sizeof`

### 207709::pairctx

- Project: `openssh-portable`
- CWE: `cwe-399`
- Gold/Pred/Prob: `1` / `0` / `0.1422`
- Hunk `@@ -27,44 +28,63 @@ 		case SSH_AGENT_CONSTRAIN_CONFIRM:` score `[2, 51, 1885]` changed `51` keywords `free, valid` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=22, risk=3, safer=0`
- Removed: `				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out;`
- Added: `				goto err; | 				goto err; | 				goto err; | 				goto err; | 				goto err; | 			if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {`
- Hunk `@@ -4,22 +4,23 @@ 	u_char ctype;` score `[1, 9, 655]` changed `9` keywords `valid` directions `candidate_adds_protection` deltas `protection=2, risk=0, safer=0`
- Removed: `			goto out; | 				r = SSH_ERR_INVALID_FORMAT; | 				goto out; | 				goto out;`
- Added: `	char *ext_name = NULL; | 	struct sshbuf *b = NULL; | 			goto err; | 				goto err; | 				goto err;`

### 206422::pairctx

- Project: `ImageMagick6`
- CWE: `cwe-125`
- Gold/Pred/Prob: `1` / `0` / `0.1767`
- Hunk `@@ -217,29 +217,31 @@   else` score `[3, 46, 2165]` changed `46` keywords `free, mem, size` directions `candidate_adds_protection` deltas `protection=1, risk=0, safer=0`
- Removed: `    heif_chroma_420,decode_options); |     heif_decoding_options_free(decode_options); |   if (IsHeifSuccess(&error,image) == MagickFalse) |     { |       heif_image_handle_release`
- Added: `    heif_chroma_420,NULL); |   if (IsHeifSuccess(&error,image) == MagickFalse) |     { |       heif_image_handle_release(image_handle); |       heif_context_free(heif_context); |  `

### 196800::pairctx

- Project: `tensorflow`
- CWE: `cwe-787`
- Gold/Pred/Prob: `1` / `0` / `0.2082`
- Hunk `@@ -1,18 +1,52 @@   void Compute(OpKernelContext* ctx) override {` score `[3, 58, 3335]` changed `58` keywords `alloc, size, valid` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=31, risk=2, safer=0`
- Removed: ` |     // One global scale. |     Tensor input_min_tensor(DataTypeToEnum<T>::value, TensorShape()); |     Tensor input_max_tensor(DataTypeToEnum<T>::value, TensorShape()); |     //`
- Added: `    const int depth = (axis_ == -1) ? 1 : input.dim_size(axis_); |     Tensor input_min_tensor; |     Tensor input_max_tensor; |     if (range_given_) { |       input_min_tensor = `

### 210206::pairctx

- Project: `squid`
- CWE: `cwe-400`
- Gold/Pred/Prob: `1` / `0` / `0.3346`
- Hunk `@@ -323,11 +327,12 @@ ` score `[3, 5, 366]` changed `5` keywords `len, length, size` directions `candidate_removes_protection` deltas `protection=-2, risk=0, safer=0`
- Removed: `    if (outbuf.length() > 0) { |         entry->append(outbuf.rawContent(), outbuf.length());`
- Added: `    if (outbuf.size() > 0) { |         entry->append(outbuf.rawBuf(), outbuf.size()); |     outbuf.clean();`
- Hunk `@@ -214,34 +216,34 @@                         break;` score `[2, 28, 3389]` changed `28` keywords `mem, size` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=5, risk=1, safer=5`
- Removed: `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n", |                                            icon_url, escaped_`
- Added: `                    memset(tmpbuf, '\0', TEMP_BUF_SIZE); |  |                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%`

### 195309::pairctx

- Project: `squid`
- CWE: `cwe-400`
- Gold/Pred/Prob: `1` / `0` / `0.3576`
- Hunk `@@ -328,11 +335,12 @@ ` score `[3, 5, 366]` changed `5` keywords `len, length, size` directions `candidate_removes_protection` deltas `protection=-2, risk=0, safer=0`
- Removed: `    if (outbuf.length() > 0) { |         entry->append(outbuf.rawContent(), outbuf.length());`
- Added: `    if (outbuf.size() > 0) { |         entry->append(outbuf.rawBuf(), outbuf.size()); |     outbuf.clean();`
- Hunk `@@ -219,34 +221,37 @@                         break;` score `[2, 15, 2924]` changed `15` keywords `mem, size` directions `candidate_adds_protection, candidate_introduces_risk` deltas `protection=7, risk=1, safer=6`
- Removed: `                            outbuf.appendf("<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%s/\">%s</A>\n", |                             outbuf.appendf("<IMG border=\"0\"`
- Added: `                    memset(tmpbuf, '\0', TEMP_BUF_SIZE); |  |                             snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG border=\"0\" SRC=\"%s\"> <A HREF=\"telnet://%s@%s%s%`
