# Test-only TLS 1.2 ClientKeyExchange record shape diagnostic.
# Source provenance and the 40 frozen patches stay unchanged. When this
# optional module is disabled, no diagnostic code enters the native backend.
# Only record type/versions/lengths and handshake message IDs are printed.
gmssl_replace_once(
  "${SOURCE_PATH}/src/tls12.c"
  [==[	if (tls12_record_get_handshake_client_key_exchange(conn->record,
		&point_octets, &point_octets_len) != 1) {
]==]
  [==[	if (tls12_record_get_handshake_client_key_exchange(conn->record,
		&point_octets, &point_octets_len) != 1) {
		/* No bytes, nonces, transcript, certificate or secret may be printed. */
		size_t record_payload = 0u;
		size_t advertised = 0u;
		unsigned record_type = 0u, message_type = 0u, protocol = 0u;
		if (conn->recordlen >= 5u && conn->recordlen <= sizeof(conn->record)) {
			record_type = conn->record[0];
			protocol = ((unsigned)conn->record[1] << 8) | conn->record[2];
			record_payload = ((size_t)conn->record[3] << 8) | conn->record[4];
			if (conn->recordlen >= 9u) {
				message_type = conn->record[5];
				advertised = ((size_t)conn->record[6] << 16)
					| ((size_t)conn->record[7] << 8) | conn->record[8];
			}
		}
		fprintf(stderr,
			"CRYPTO_TLS_PRIVATE_CKE_DIAG state=%d record_type=%u protocol=%u "
			"record_len=%zu payload=%zu handshake_type=%u declared_body=%zu "
			"available_body=%zu\n",
			conn->handshake_state, record_type, protocol, conn->recordlen,
			record_payload, message_type, advertised,
			conn->recordlen >= 9u ? conn->recordlen - 9u : 0u);
]==]
)

# Distinguish pre-CKE record read errors from CKE parser/cryptographic
# failures. A peer alert is never silently treated as a valid handshake.
gmssl_replace_once(
  "${SOURCE_PATH}/src/tls12.c"
  [==[int tls_recv_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *point_octets;
	size_t point_octets_len;

	if ((ret = tls_recv_record(conn)) != 1) {
]==]
  [==[int tls_recv_client_key_exchange(TLS_CONNECT *conn)
{
	int ret;
	const uint8_t *point_octets;
	size_t point_octets_len;

	if ((ret = tls_recv_record(conn)) != 1) {
		if (ret != TLS_ERROR_RECV_AGAIN) {
			fprintf(stderr,
				"CRYPTO_TLS_PRIVATE_CKE_RECV ret=%d state=%d recordlen=%zu "
				"record_offset=%zu\n",
				ret, conn->handshake_state, conn->recordlen,
				conn->record_offset);
		}
]==]
)

gmssl_replace_once(
  "${SOURCE_PATH}/src/tls12.c"
  [==[	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	memcpy(conn->peer_key_exchange, point_octets, point_octets_len);
	conn->peer_key_exchange_len = point_octets_len;

	if (tls_derive_pre_master_secret(conn) != 1
		|| tls_derive_master_secret(conn) != 1
		|| tls_derive_key_block(conn) != 1
		|| tls_init_application_keys(conn) != 1) {
]==]
  [==[	fprintf(stderr,
		"CRYPTO_TLS_PRIVATE_CKE_PARSED state=%d point_len=%zu\n",
		conn->handshake_state, point_octets_len);
	if (point_octets_len != 65) {
		error_print();
		return -1;
	}
	memcpy(conn->peer_key_exchange, point_octets, point_octets_len);
	conn->peer_key_exchange_len = point_octets_len;

	int crypto_private_key_stage = 0;
	if ((crypto_private_key_stage = 1, tls_derive_pre_master_secret(conn) != 1)
		|| (crypto_private_key_stage = 2, tls_derive_master_secret(conn) != 1)
		|| (crypto_private_key_stage = 3, tls_derive_key_block(conn) != 1)
		|| (crypto_private_key_stage = 4, tls_init_application_keys(conn) != 1)) {
		fprintf(stderr,
			"CRYPTO_TLS_PRIVATE_CKE_DERIVE stage=%d state=%d\n",
			crypto_private_key_stage, conn->handshake_state);
]==]
)
