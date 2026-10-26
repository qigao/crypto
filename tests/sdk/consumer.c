/* Installed SDK consumer. NO GmSSL header, linker target, or source access. */
#include <crypto/tls.h>
#include <crypto/tls_ext.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SDK_CA_FILE
#error SDK_CA_FILE is required
#endif
#ifndef SDK_SERVER_CERT_FILE
#error SDK_SERVER_CERT_FILE is required
#endif
#ifndef SDK_SERVER_KEY_FILE
#error SDK_SERVER_KEY_FILE is required
#endif

enum { PIPE_LIMIT = 1024, MAX_DRIVES = 200000 };
typedef struct pipe {
    uint8_t data[PIPE_LIMIT];
    size_t length;
} pipe;
typedef struct channel {
    pipe *send_to;
    pipe *receive_from;
    size_t partial_send;
    size_t partial_recv;
    size_t retry_send;
    size_t retry_recv;
} channel;

static size_t min_size(size_t a, size_t b) { return a < b ? a : b; }

static int64_t on_send(void *user, const uint8_t *data, size_t len)
{
    channel *c = (channel *)user;
    size_t space = PIPE_LIMIT - c->send_to->length;
    size_t n;
    if (!space) {
        c->retry_send++;
        return CRYPTO_TLS_IO_AGAIN;
    }
    n = min_size(len, min_size(space, 73u));
    if (n < len) c->partial_send++;
    memcpy(c->send_to->data + c->send_to->length, data, n);
    c->send_to->length += n;
    return (int64_t)n;
}

static int64_t on_recv(void *user, uint8_t *data, size_t len)
{
    channel *c = (channel *)user;
    size_t n = min_size(len, min_size(41u, c->receive_from->length));
    if (!n) {
        c->retry_recv++;
        return CRYPTO_TLS_IO_AGAIN;
    }
    if (n < len) c->partial_recv++;
    memcpy(data, c->receive_from->data, n);
    c->receive_from->length -= n;
    if (c->receive_from->length)
        memmove(c->receive_from->data,
                c->receive_from->data + n, c->receive_from->length);
    return (int64_t)n;
}

static int acceptable(crypto_tls_result r)
{
    return r == CRYPTO_TLS_OK || r == CRYPTO_TLS_AGAIN;
}

static int test_protocol(crypto_tls_provider *provider, uint32_t protocol,
                         int configure_alpn)
{
    pipe cs = {{0},0u}, sc = {{0},0u};
    channel client_channel = {&cs,&sc,0,0,0,0};
    channel server_channel = {&sc,&cs,0,0,0,0};
    crypto_tls_io ci = {sizeof(ci),0,&client_channel,on_send,on_recv};
    crypto_tls_io si = {sizeof(si),0,&server_channel,on_send,on_recv};
    crypto_tls_session_options client_options = {
        sizeof(client_options),protocol,CRYPTO_TLS_CLIENT,4,
        "localhost",SDK_CA_FILE,NULL,NULL,NULL,0
    };
    crypto_tls_session_options server_options = {
        sizeof(server_options),protocol,CRYPTO_TLS_SERVER,4,
        NULL,NULL,SDK_SERVER_CERT_FILE,SDK_SERVER_KEY_FILE,"",0
    };
    crypto_tls_session *client = NULL, *server = NULL;
    static const char *client_names[] = {"http/1.1", "h2"};
    static const char *server_names[] = {"h2", "http/1.1"};
    crypto_tls_session_info_v1_1 client_info, server_info, untouched;
    static const char *invalid_names[] = {"", "h2"};
    char too_long_name[CRYPTO_TLS_ALPN_MAX_NAME_BYTES + 2u];
    const char *too_long[] = {too_long_name};
    uint32_t sessions = 0;
    const uint8_t sent[] = "Crypto shared C11 TLS opaque session real record";
    uint8_t received[sizeof(sent)] = {0};
    size_t received_count = 0;
    size_t sent_count = 0;
    int client_ready = 0, server_ready = 0, sent_done = 0;
    int client_closed = 0, server_closed = 0;
    int step = 0, rc = 1;
    crypto_tls_result result;

    if (crypto_tls_session_create(provider,&client_options,&ci,&client) != CRYPTO_TLS_OK
        || crypto_tls_session_create(provider,&server_options,&si,&server) != CRYPTO_TLS_OK)
        goto cleanup;
    if (crypto_tls_provider_session_count(provider,&sessions) != CRYPTO_TLS_OK
        || sessions != 2) goto cleanup;

    memset(&client_info, 0xA5, sizeof(client_info));
    client_info.struct_size = sizeof(client_info);
    untouched = client_info;
    if (crypto_tls_session_get_info_v1_1(client, &client_info)
            != CRYPTO_TLS_AGAIN
        || memcmp(&client_info, &untouched, sizeof(client_info)) != 0)
        goto cleanup;

    if (configure_alpn) {
        memset(too_long_name, 'a', sizeof(too_long_name));
        too_long_name[sizeof(too_long_name)-1] = '\0';
        if (crypto_tls_session_set_alpn_v1_1(client, invalid_names, 2)
                != CRYPTO_TLS_INVALID_ARGUMENT
            || crypto_tls_session_set_alpn_v1_1(client, too_long, 1)
                != CRYPTO_TLS_INVALID_ARGUMENT
            || crypto_tls_session_set_alpn_v1_1(client, client_names, 2)
                != CRYPTO_TLS_OK
            || crypto_tls_session_set_alpn_v1_1(server, server_names, 2)
                != CRYPTO_TLS_OK
            || crypto_tls_session_set_alpn_v1_1(client, client_names, 2)
                != CRYPTO_TLS_INVALID_ARGUMENT)
            goto cleanup;
    }

    {
        crypto_tls_provider *borrowed = provider;
        if (crypto_tls_provider_destroy(&borrowed) != CRYPTO_TLS_BUSY
            || borrowed != provider) goto cleanup;
    }
    for (step=0;step<MAX_DRIVES;step++) {
        if (!client_ready) {
            result = crypto_tls_session_handshake(client);
            if (!acceptable(result)) goto cleanup;
            client_ready = result == CRYPTO_TLS_OK;
        }
        if (!server_ready) {
            result = crypto_tls_session_handshake(server);
            if (!acceptable(result)) goto cleanup;
            server_ready = result == CRYPTO_TLS_OK;
        }
        if (client_ready && server_ready) break;
    }
    if (!client_ready || !server_ready) goto cleanup;

    client_info.struct_size = sizeof(client_info);
    memset(&server_info, 0, sizeof(server_info));
    server_info.struct_size = sizeof(server_info);
    if (crypto_tls_session_get_info_v1_1(client, &client_info) != CRYPTO_TLS_OK
        || crypto_tls_session_get_info_v1_1(server, &server_info)
            != CRYPTO_TLS_OK
        || client_info.protocol != protocol
        || server_info.protocol != protocol
        || !client_info.cipher_suite || !server_info.cipher_suite
        || client_info.cipher_suite != server_info.cipher_suite
        || !client_info.cipher_name[0] || !server_info.cipher_name[0]
        || strcmp(client_info.cipher_name, server_info.cipher_name) != 0
        || crypto_tls_session_set_alpn_v1_1(client, client_names, 2)
            != CRYPTO_TLS_INVALID_ARGUMENT)
        goto cleanup;
    if (configure_alpn) {
        if (client_info.alpn_size != 2u || server_info.alpn_size != 2u
            || strcmp(client_info.alpn, "h2") != 0
            || strcmp(server_info.alpn, "h2") != 0)
            goto cleanup;
    } else if (client_info.alpn_size || server_info.alpn_size
               || client_info.alpn[0] || server_info.alpn[0])
        goto cleanup;

    for (step=0;step<MAX_DRIVES;step++) {
        if (!sent_done) {
            result = crypto_tls_session_send(client,sent,sizeof(sent),&sent_count);
            if (!acceptable(result)) goto cleanup;
            if (result == CRYPTO_TLS_OK) {
                if (sent_count != sizeof(sent)) goto cleanup;
                sent_done = 1;
            }
        }
        if (received_count < sizeof(received)) {
            size_t count = 0;
            result = crypto_tls_session_receive(server,
                received + received_count,
                sizeof(received) - received_count,&count);
            if (!acceptable(result)) goto cleanup;
            if (result == CRYPTO_TLS_OK) {
                if (!count || count > sizeof(received)-received_count)
                    goto cleanup;
                received_count += count;
            }
        }
        if (sent_done && received_count == sizeof(received)) break;
    }
    if (!sent_done || received_count != sizeof(received)
        || memcmp(sent,received,sizeof(sent)) != 0)
        goto cleanup;
    for (step=0;step<MAX_DRIVES;step++) {
        if (!client_closed) {
            result = crypto_tls_session_shutdown(client);
            if (!acceptable(result)) goto cleanup;
            client_closed = result == CRYPTO_TLS_OK;
        }
        if (!server_closed) {
            result = crypto_tls_session_shutdown(server);
            if (!acceptable(result)) goto cleanup;
            server_closed = result == CRYPTO_TLS_OK;
        }
        if (client_closed && server_closed) break;
    }
    if (!client_closed || !server_closed) goto cleanup;
    if (!client_channel.partial_send || !client_channel.partial_recv
        || !server_channel.partial_send || !server_channel.partial_recv
        || !client_channel.retry_recv || !server_channel.retry_recv
        || cs.length || sc.length)
        goto cleanup;
    rc = 0;
cleanup:
    if (server && crypto_tls_session_destroy(&server) != CRYPTO_TLS_OK) rc = 1;
    if (client && crypto_tls_session_destroy(&client) != CRYPTO_TLS_OK) rc = 1;
    if (rc) fprintf(stderr,"Crypto shared TLS 0x%04x smoke FAILED step=%d handshake=%d/%d sent=%d recv=%zu close=%d/%d\n",
        protocol,step,client_ready,server_ready,sent_done,received_count,client_closed,server_closed);
    return rc;
}

int main(void)
{
    crypto_tls_provider *provider = NULL;
    crypto_tls_session *s = NULL;
    crypto_tls_session_options bad = {sizeof(bad),CRYPTO_TLS_1_3,CRYPTO_TLS_CLIENT,0,
                                     "localhost",NULL,NULL,NULL,NULL,0};
    pipe out = {{0},0}, in = {{0},0};
    channel ch = {&out,&in,0,0,0,0};
    crypto_tls_io io = {sizeof(io),0,&ch,on_send,on_recv};
    uint32_t count = UINT32_MAX;
    int rc = 1;
    uint64_t features = 0u;
    const uint64_t required_features =
        CRYPTO_TLS_FEATURE_TLS12_ECDHE_RSA |
        CRYPTO_TLS_FEATURE_TLS13_RSA_PSS |
        CRYPTO_TLS_FEATURE_EXPLICIT_CA_FILE |
        CRYPTO_TLS_FEATURE_DNS_SAN |
        CRYPTO_TLS_FEATURE_TEXT_ALPN |
        CRYPTO_TLS_FEATURE_SESSION_INFO;

    if (crypto_tls_abi_version() != CRYPTO_TLS_ABI_VERSION
        || crypto_tls_extension_abi_version()
            != CRYPTO_TLS_EXTENSION_ABI_VERSION
        || crypto_tls_get_features_v1_1(&features) != CRYPTO_TLS_OK
        || features != required_features
        || crypto_tls_get_features_v1_1(NULL) != CRYPTO_TLS_INVALID_ARGUMENT)
        return 1;
    if (crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION+1,&provider)
        != CRYPTO_TLS_INVALID_ARGUMENT || provider) return 2;
    if (crypto_tls_provider_create(CRYPTO_TLS_ABI_VERSION,&provider)
        != CRYPTO_TLS_OK || !provider) return 3;
    if (crypto_tls_session_create(provider,&bad,&io,&s)
        != CRYPTO_TLS_INVALID_ARGUMENT || s) goto done;

    if (test_protocol(provider,CRYPTO_TLS_1_2,0) != 0
        || test_protocol(provider,CRYPTO_TLS_1_3,0) != 0
        || test_protocol(provider,CRYPTO_TLS_1_2,1) != 0
        || test_protocol(provider,CRYPTO_TLS_1_3,1) != 0)
        goto done;

    bad.ca_file = SDK_CA_FILE;
    if (crypto_tls_session_create(provider,&bad,&io,&s) != CRYPTO_TLS_OK)
        goto done;
    if (crypto_tls_session_cancel(s) != CRYPTO_TLS_OK
        || crypto_tls_session_handshake(s) != CRYPTO_TLS_CANCELLED
        || crypto_tls_session_destroy(&s) != CRYPTO_TLS_OK || s)
        goto done;

    if (crypto_tls_provider_session_count(provider,&count) != CRYPTO_TLS_OK || count)
        goto done;
    rc = 0;
done:
    if (s) (void)crypto_tls_session_destroy(&s);
    if (provider && crypto_tls_provider_destroy(&provider) != CRYPTO_TLS_OK)
        rc = 1;
    if (!rc) puts("Crypto installed C11 TLS1.2/1.3 handshake, ALPN, cipher info, data, cancel and shutdown: PASS");
    return rc;
}
