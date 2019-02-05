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

	SSL_OP_ALL      = 0x80000BFF
	SSL_OP_NO_SSLv2 = 0x01000000
	SSL_OP_NO_SSLv3 = 0x02000000
)

type SSL_CTX ssl.SSL_CTX

type SSL struct {
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

func NewServerCTX(certPEMFile, keyPEMFile string) (SSL_CTX, error) {
	return ctxInit(ssl.SSLv23_server_method(), "", certPEMFile, keyPEMFile)
}

func (s *SSL) InitConnection(ctx SSL_CTX) error {
	s.rbio = bio.BIO_new(bio.BIO_s_mem())
	if s.rbio == nil {
		return fmt.Errorf("BIO_new for rbio failed: %s", opensslError())
	}

	s.wbio = bio.BIO_new(bio.BIO_s_mem())
	if s.wbio == nil {
		bio.BIO_free(s.rbio)
		return fmt.Errorf("BIO_new for wbio failed: %s", opensslError())
	}

	s.ssl = ssl.SSL_new(ctx)
	if s.ssl == nil {
		bio.BIO_free(s.rbio)
		bio.BIO_free(s.wbio)
		return fmt.Errorf("SSL_new failed: %s", opensslError())
	}

	ssl.SSL_set_accept_state(s.ssl)
	ssl.SSL_set_bio(s.ssl, s.rbio, s.wbio)
	return nil
}

func (s *SSL) DestroyConnection() {
	ssl.SSL_free(s.ssl)
}

func DestroyCTX(ctx SSL_CTX) {
	ssl.SSL_CTX_free(ctx)
}

func ctxInit(method ssl.SSL_METHOD, opensslConfig, certPEMFile, keyPEMFile string) (ssl.SSL_CTX, error) {

	ssl.SSL_load_error_strings()

	if ssl.SSL_library_init() != 1 {
		return nil, fmt.Errorf("Unable to initialize openssl")
	}
	crypto.OPENSSL_config(opensslConfig)

	ctx := ssl.SSL_CTX_new(method)
	if ctx == nil {
		return nil, fmt.Errorf("Unable to initialize SSL context")
	}

	ssl.SSL_CTX_set_verify(ctx, ssl.SSL_VERIFY_NONE, nil)
	ssl.SSL_CTX_set_verify_depth(ctx, 4)

	errno := ssl.SSL_CTX_use_certificate_chain_file(ctx, certPEMFile)
	if errno != 1 {
		return nil, fmt.Errorf("SSL_CTX_use_certificate_chain_file: %d %v", errno, opensslError())
	}
	errno = ssl.SSL_CTX_use_PrivateKey_file(ctx, keyPEMFile, ssl.SSL_FILETYPE_PEM)
	if errno != 1 {
		return nil, fmt.Errorf("SSL_CTX_use_certificate_chain_file: %d %v", errno, opensslError())
	}
	errno = ssl.SSL_CTX_use_certificate_file(ctx, certPEMFile, ssl.SSL_FILETYPE_PEM)
	if errno != 1 {
		return nil, fmt.Errorf("SSL_CTX_use_certificate_chain_file: %d %v", errno, opensslError())
	}
	ssl.SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3)

	return ctx, nil
}

func (s *SSL) WriteEncrypted(src []byte, length int) int {
	bytesLeft := length
	for bytesLeft > 0 {
		n := bio.BIO_write(s.rbio, string(src[:bytesLeft]), bytesLeft)

		if n <= 0 {
			return -1 /* if BIO write fails, assume unrecoverable */
		}

		bytesLeft -= n

		if !s.HandshakeFinished() {
			n := ssl.SSL_accept(s.ssl)
			status := s.SSLStatus(n)

			/* Did SSL request to write bytes? */
			if status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE {
				return -2
			}
			if status == SSL_ERROR_SSL {
				log.Errorf("SSL: Status fail: %s", opensslError())
				return -1
			}
			if !s.HandshakeFinished() {
				return -100
			}
		}
	}

	return length
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

func (s *SSL) HandshakeFinished() bool {
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

func (s *SSL) DoHandshake(buf []byte, n int) ([]byte, int, bool) {
	writeStatus := s.WriteEncrypted(buf, n)
	if writeStatus == -2 {
		buf, n = s.ReadEncrypted(4096)
		return buf, n, false
	} else if writeStatus == 0 {
		return nil, 0, true
	}
	return nil, 0, false
}

func (s *SSL) SSLStatus(n int) int {
	return ssl.SSL_get_error(s.ssl, n)
}

func opensslError() string {
	var ret string
	return bio.ERR_error_string(bio.ERR_get_error(), ret)
}
