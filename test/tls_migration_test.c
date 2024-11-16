#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "testutil.h"
#include "helpers/ssltestlib.h"

static char *cert = NULL;
static char *privkey = NULL;

static int test_tls_migration(void)
{
    SSL_CTX *server_ctx = NULL, *client_ctx = NULL;
    SSL *server_ssl = NULL, *client_ssl = NULL;
    BIO *client_to_server = NULL, *server_to_client = NULL;
    int ret = 0;

    /* Create server and client SSL contexts */
    if (!create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
                             TLS1_VERSION, 0,
                             &server_ctx, &client_ctx, cert, privkey))
    {
        TEST_error("Failed to create SSL_CTX pair");
        goto err;
    }

    /* Create server and client SSL objects */
    if (!create_ssl_objects(server_ctx, client_ctx, &server_ssl, &client_ssl,
                            NULL, NULL))
    {
        TEST_error("Failed to create SSL objects");
        goto err;
    }

    /* Create a BIO pair to simulate network connection */
    if (!BIO_new_bio_pair(&server_to_client, 0, &client_to_server, 0))
    {
        TEST_error("Failed to create BIO pair");
        goto err;
    }

    /* Attach the BIOs to the SSL objects */
    SSL_set_bio(server_ssl, server_to_client, server_to_client);
    SSL_set_bio(client_ssl, client_to_server, client_to_server);

    /* Perform the handshake */
    if (!create_ssl_connection(server_ssl, client_ssl, SSL_ERROR_NONE))
    {
        TEST_error("Failed to establish SSL connection");
        goto err;
    }

    /* Send data */
    const char *msg = "Hello, OpenSSL!";
    int msg_len = strlen(msg);
    int client_write_ret;

    client_write_ret = SSL_write(client_ssl, msg, msg_len);
    if (client_write_ret <= 0)
    {
        int err = SSL_get_error(client_ssl, client_write_ret);
        TEST_error("SSL_write failed with error %d", err);
        goto err;
    }

    /* Receive data */
    char buf[256];
    int server_read_ret;

    server_read_ret = SSL_read(server_ssl, buf, sizeof(buf) - 1);
    if (server_read_ret <= 0)
    {
        int err = SSL_get_error(server_ssl, server_read_ret);
        TEST_error("SSL_read failed with error %d", err);
        goto err;
    }
    buf[server_read_ret] = '\0';

    /* Compare sent and received data */
    if (strcmp(msg, buf) != 0)
    {
        TEST_error("Received message does not match the sent message");
        goto err;
    }

    ret = 1;

err:
    SSL_free(server_ssl);
    SSL_free(client_ssl);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(cert = test_get_argument(0)) || !TEST_ptr(privkey = test_get_argument(1)))
    {
        return 0;
    }

    ADD_TEST(test_tls_migration);
    return 1;
}

void cleanup_tests(void)
{
}