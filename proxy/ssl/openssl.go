package ssl

import (
	"fmt"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/bio"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/crypto"
	"github.com/IBM-Bluemix/golang-openssl-wrapper/ssl"
	"github.com/crunchydata/crunchy-proxy/util/log"
)

const (
	SSL_ST_OK = 0x03

	SSL_ERROR_NONE             = 0
	SSL_ERROR_SSL              = 1
	SSL_ERROR_WANT_READ        = 2
	SSL_ERROR_WANT_WRITE       = 3
	SSL_ERROR_WANT_X509_LOOKUP = 4
	SSL_ERROR_SYSCALL          = 5 /* look at error stack/return value/errno */
	SSL_ERROR_ZERO_RETURN      = 6
	SSL_ERROR_WANT_CONNECT     = 7
	SSL_ERROR_WANT_ACCEPT      = 8

	SSLSTATUS_OK      = 0
	SSLSTATUS_WANT_IO = 1
	SSLSTATUS_FAIL    = 2
)

type SSL struct {
	ctx  ssl.SSL_CTX
	ssl  ssl.SSL
	rbio bio.BIO /* SSL reads from, we write to. */
	wbio bio.BIO /* SSL writes to, we read from. */
}

/*
  +------+                                    +-----+
  |......|--> read(fd) --> BIO_write(rbio) -->|.....|--> SSL_read(ssl)  --> IN
  |......|                                    |.....|
  |.sock.|                                    |.SSL.|
  |......|                                    |.....|
  |......|<-- write(fd) <-- BIO_read(wbio) <--|.....|<-- SSL_write(ssl) <-- OUT
  +------+                                    +-----+
*/

func NewSSL() *SSL {
	sslInstance := &SSL{}
	return sslInstance
}

func (s *SSL) InitCTX() (err error) {
	s.ctx, err = ctxInit("", ssl.SSLv23_server_method())
	return err

}

func (s *SSL) InitConnection() {
	s.rbio = bio.BIO_new(bio.BIO_s_mem())
	s.wbio = bio.BIO_new(bio.BIO_s_mem())

	s.ssl = ssl.SSL_new(s.ctx)

	ssl.SSL_set_accept_state(s.ssl)
	ssl.SSL_set_bio(s.ssl, s.rbio, s.wbio)
}

func (s *SSL) DestroyConnection() {
	ssl.SSL_free(s.ssl)
}

func (s *SSL) DestroyCTX() {
	ssl.SSL_CTX_free(s.ctx)
}

func ctxInit(config string, method ssl.SSL_METHOD) (ssl.SSL_CTX, error) {
	ssl.SSL_load_error_strings()

	if ssl.SSL_library_init() != 1 {
		return nil, fmt.Errorf("Unable to initialize openssl")
	}
	crypto.OPENSSL_config(config)

	ctx := ssl.SSL_CTX_new(method)
	if ctx == nil {
		return nil, fmt.Errorf("Unable to initialize SSL context")
	}

	ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_NONE, nil)
	ssl.SSL_CTX_set_verify_depth(ctx, 4)

	errno := ssl.SSL_CTX_use_certificate_chain_file(ctx, "cert_test/server.crt")
	if errno != 1 {
		return nil, fmt.Errorf("SSL_CTX_use_certificate_chain_file: %d %v", errno, opensslError())
	}
	errno = ssl.SSL_CTX_use_PrivateKey_file(ctx, "cert_test/server.key", 1)
	if errno != 1 {
		return nil, fmt.Errorf("SSL_CTX_use_certificate_chain_file: %d %v", errno, opensslError())
	}
	errno = ssl.SSL_CTX_use_certificate_file(ctx, "cert_test/server.crt", 1)
	if errno != 1 {
		return nil, fmt.Errorf("SSL_CTX_use_certificate_chain_file: %d %v", errno, opensslError())
	}
	ssl.SSL_CTX_set_options(ctx, 0x80000BFF|0x01000000|0x02000000)

	return ctx, nil
}

func (s *SSL) WriteEncrypted(src []byte, length int) int {

	for length > 0 {
		n := bio.BIO_write(s.rbio, string(src[:length]), length)

		if n <= 0 {
			return -1 /* if BIO write fails, assume unrecoverable */
		}

		length -= n

		if !s.SSL_is_init_finished() {
			n := ssl.SSL_accept(s.ssl)
			status := s.SSLStatus(n)

			/* Did SSL request to write bytes? */
			if status == SSLSTATUS_WANT_IO {
				return -2
			}
			if status == SSLSTATUS_FAIL {
				log.Errorf("SSL: Status fail: %s", opensslError())
				return -1
			}
			if !s.SSL_is_init_finished() {
				return 0
			}
		}
	}

	return len(src) - length
}

func (s *SSL) ReadEncrypted(len int) ([]byte, int) {
	buf := make([]byte, len)
	len = bio.BIO_read(s.wbio, buf, len)
	return buf, len
}

func (s *SSL) WriteDecrypted(src []byte) int {
	return ssl.SSL_write(s.ssl, src, len(src))
}

func (s *SSL) ReadDecrypted(len int) ([]byte, int) {
	buf := make([]byte, len)
	len = ssl.SSL_read(s.ssl, buf, len)
	return buf, len
}

func (s *SSL) SSL_is_init_finished() bool {
	status := ssl.SSL_state(s.ssl)
	switch status {
	case 0x1000:
		log.Debugf("SSL_state: SSL_ST_CONNECT")
	case 0x2000:
		log.Debugf("SSL_state: SSL_ST_ACCEPT")
	case 0x0FFF:
		log.Debugf("SSL_state: SSL_ST_MASK")
	case (0x1000 | 0x2000):
		log.Debugf("SSL_state: SSL_ST_INIT")
	case 0x4000:
		log.Debugf("SSL_state: SSL_ST_BEFORE")
	case 0x03:
		log.Debugf("SSL_state: SSL_ST_OK")
	case (0x04 | (0x1000 | 0x2000)):
		log.Debugf("SSL_state: SSL_ST_RENEGOTIATE")
	case (0x05 | (0x1000 | 0x2000)):
		log.Debugf("SSL_state: SSL_ST_ERR")
	default:
		log.Debugf("SSL_state: Unkown status '%d'", status)
	}

	return (ssl.SSL_state(s.ssl) == SSL_ST_OK)
}

func (s *SSL) SSLStatus(n int) int {
	switch ssl.SSL_get_error(s.ssl, n) {
	case SSL_ERROR_NONE:
		return SSLSTATUS_OK
	case SSL_ERROR_WANT_WRITE:
		return SSLSTATUS_WANT_IO
	case SSL_ERROR_WANT_READ:
		return SSLSTATUS_WANT_IO
	case SSL_ERROR_ZERO_RETURN:
		return SSLSTATUS_FAIL
	case SSL_ERROR_SYSCALL:
		return SSLSTATUS_FAIL
	default:
		return SSLSTATUS_FAIL
	}
}

func opensslError() string {
	var ret string
	return bio.ERR_error_string(bio.ERR_get_error(), ret)
}
