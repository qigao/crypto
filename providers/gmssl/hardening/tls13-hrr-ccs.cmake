# Security-reviewed Crypto-only post-import TLS 1.3 HelloRetryRequest fix.
# Keep 92 original blobs, 40 historic patches and initial five UB fixes
# immutable; fail closed when the pinned GmSSL source anchors drift.
#
# RFC 8446 section 5 / appendix D.4: a middlebox-mode client may emit one
# syntactically valid dummy CCS (record type 20, 1 byte 0x01) immediately
# before its second ClientHello after HRR. Ignore ONLY that record for the
# handshake transcript. Do not skip/ignore arbitrary TLS alerts or messages.
#
# TLS_CONNECT is private to the ONE shared Crypto Provider; no public C11
# Crypto ABI or separately installed GmSSL header exposes this new field.

crypto_gmssl_harden_once(
  "${SOURCE_PATH}/include/gmssl/tls.h"
  [==[	// HelloRetryRequest
	int hello_retry_request;
]==]
  [==[	// HelloRetryRequest
	int hello_retry_request;
	int hrr_dummy_ccs_seen; // one admitted CCS before ClientHello2 only
]==])

crypto_gmssl_harden_once(
  "${SOURCE_PATH}/src/tls13.c"
  [==[	if(conn->verbose) tls_trace("recv ClientHello again\n");
	if(conn->verbose) tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);
]==]
  [==[	/* A TLS 1.3 middlebox-mode peer is permitted to send a dummy
	 * ChangeCipherSpec before ClientHello2. Consume at most one, and ONLY
	 * if its complete TLSPlaintext is exactly 14 03 03 00 01 01.
	 * A second dummy CCS or any malformed CCS is an error.
	 *
	 * This is intentionally scoped to the existing HRR/ClientHello2 state.
	 * We must never add CCS bytes to the handshake transcript, and must
	 * continue to parse/validate ClientHello2 and Finished normally.
	 */
	if (tls_record_type(conn->record) == TLS_record_change_cipher_spec) {
		if (conn->hrr_dummy_ccs_seen
			|| conn->recordlen != TLS_RECORD_HEADER_SIZE + 1u
			|| tls_record_protocol(conn->record) != TLS_protocol_tls12
			|| tls_record_data_length(conn->record) != 1u
			|| conn->record[TLS_RECORD_HEADER_SIZE] != 0x01u) {
			error_print();
			tls13_send_alert(conn, TLS_alert_unexpected_message);
			return -1;
		}
		conn->hrr_dummy_ccs_seen = 1;
		tls_clean_record(conn);
		if ((ret = tls_recv_record(conn)) != 1) {
			if (ret != TLS_ERROR_RECV_AGAIN) error_print();
			return ret;
		}
	}
	if(conn->verbose) tls_trace("recv ClientHello again\n");
	if(conn->verbose) tls13_record_print(stderr, 0, 0, conn->record, conn->recordlen);
]==])
message(STATUS "Applied Crypto private TLS 1.3 HRR dummy CCS hardening (2 source edits)")
