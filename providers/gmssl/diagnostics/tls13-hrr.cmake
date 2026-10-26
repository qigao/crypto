# Test-only, fail-closed TLS 1.3 HelloRetryRequest parser stages.
# Applies ONLY after the frozen original 40 source changes and Crypto's
# five separate security hardening edits. Never release this instrumentation.
# No TLS payload, session ID, random, extension data, certificate or keys.
set(_crypto_tls13 "${SOURCE_PATH}/src/tls13.c")

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[int tls13_recv_client_hello_again(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;]==]
[==[int tls13_recv_client_hello_again(TLS_CONNECT *conn)
{
	int ret;
	uint8_t *record = conn->record;
	fprintf(stderr, "CRYPTO_TLS_PRIVATE_HRR_STAGE step=enter state=%d group=%d\n",
		conn->handshake_state, conn->key_exchange_group);]==])

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[	if(conn->verbose) tls_trace("recv ClientHello again\n");
	if(conn->verbose) tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);]==]
[==[	fprintf(stderr,
		"CRYPTO_TLS_PRIVATE_HRR_STAGE step=record_received bytes=%zu"
		" record_type=%u\n", conn->recordlen,
		conn->recordlen ? (unsigned)conn->record[0] : 0u);
	if(conn->verbose) tls_trace("recv ClientHello again\n");
	if(conn->verbose) tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);]==])

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[	// ClientHello1
	if (tls_record_get_handshake_client_hello(conn->plain_record,]==]
[==[	fprintf(stderr,
		"CRYPTO_TLS_PRIVATE_HRR_STAGE step=clienthello2_parsed"
		" session_len=%zu ciphers_len=%zu exts_len=%zu\n",
		legacy_session_id_len, cipher_suites_len, extslen);
	// ClientHello1
	if (tls_record_get_handshake_client_hello(conn->plain_record,]==])

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[	// update client_server
	memcpy(conn->client_random, random, 32);]==]
[==[	fprintf(stderr,
		"CRYPTO_TLS_PRIVATE_HRR_STAGE step=original_ch_comparison_passed\n");
	// update client_server
	memcpy(conn->client_random, random, 32);]==])

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[	// ClientHello2 must not drop any ClientHello1 extension except early_data.
]==]
[==[	fprintf(stderr,
		"CRYPTO_TLS_PRIVATE_HRR_STAGE step=clienthello2_exts_verified\n");
	// ClientHello2 must not drop any ClientHello1 extension except early_data.
]==])

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[	// client must echo ClientHello1.cookie
]==]
[==[	fprintf(stderr,
		"CRYPTO_TLS_PRIVATE_HRR_STAGE step=clienthello1_exts_verified\n");
	// client must echo ClientHello1.cookie
]==])

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[	// key_share
	if (tls13_process_key_share_client_hello_again(key_share, key_share_len,]==]
[==[	fprintf(stderr,
		"CRYPTO_TLS_PRIVATE_HRR_STAGE step=key_share_start"
		" encoded_len=%zu group=%d\n", key_share_len,
		conn->key_exchange_group);
	// key_share
	if (tls13_process_key_share_client_hello_again(key_share, key_share_len,]==])

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[		if (!matching_ext_found) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}]==]
[==[		if (!matching_ext_found) {
			fprintf(stderr,
				"CRYPTO_TLS_PRIVATE_HRR_STAGE step=missing_original_extension type=%d\n",
				ext_type);
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}]==])

crypto_gmssl_harden_once("${_crypto_tls13}"
[==[		if (!found) {
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}]==]
[==[		if (!found) {
			fprintf(stderr,
				"CRYPTO_TLS_PRIVATE_HRR_STAGE step=missing_second_extension type=%d\n",
				_ext_type);
			error_print();
			tls13_send_alert(conn, TLS_alert_illegal_parameter);
			return -1;
		}]==])
unset(_crypto_tls13)
