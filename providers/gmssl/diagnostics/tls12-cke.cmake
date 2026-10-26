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
			"available_body=%zu\\n",
			conn->handshake_state, record_type, protocol, conn->recordlen,
			record_payload, message_type, advertised,
			conn->recordlen >= 9u ? conn->recordlen - 9u : 0u);
]==]
)
