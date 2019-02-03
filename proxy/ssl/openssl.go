package ssl

import (
	"fmt"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/bio"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/crypto"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/ssl"
)

type SSL struct {
	ctx  ssl.SSL_CTX
	rbio bio.BIO
	wbio bio.BIO
}

func InitSSL() *SSL {
	var err error
	sslInstance := &SSL{}

	sslInstance.ctx, err = ctxInit("", ssl.SSLv23_client_method())

	// ctx = SSL_CTX_new(SSLv3_client_method())
	// SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL)

	// ssl = SSL_new(ctx)
	// rbio = BIO_new(BIO_s_mem())
	// wbio = BIO_new(BIO_s_mem())

	// SSL_set_bio(ssl, rbio, wbio)
	// SSL_set_connect_state(ssl)

	// SSL_do_handshake(ssl) // This will return -1 (error) as the handshake is not finished, we can ignore it.
	return sslInstance
}

func ctxInit(config string, method ssl.SSL_METHOD) (ssl.SSL_CTX, error) {
	ssl.SSL_load_error_strings()
	if ssl.SSL_library_init() != 1 {
		return nil, fmt.Errorf("Unable to initialize libssl")
	}
	crypto.OPENSSL_config(config)

	ctx := ssl.SSL_CTX_new(method)
	if ctx == nil {
		return nil, fmt.Errorf("Unable to initialize SSL context")
	}

	ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_NONE, nil)
	ssl.SSL_CTX_set_verify_depth(ctx, 4)

	return ctx, nil
}
