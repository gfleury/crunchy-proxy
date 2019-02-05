package ssl

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/check.v1"
	"net"
	"testing"
	"time"

	"github.com/IBM-Bluemix/golang-openssl-wrapper/ssl"

	"github.com/crunchydata/crunchy-proxy/util/log"
)

var _ = check.Suite(&S{})

type S struct {
	ctx SSL_CTX
}

func Test(t *testing.T) { check.TestingT(t) }

func (s *S) SetUpSuite(c *check.C) {
	var err error
	s.ctx, err = NewServerCTX("cert_test/server.crt", "cert_test/server.key")
	c.Check(err, check.IsNil)

	log.SetLevel("debug")
}

func (s *S) TestBasicOpensslConnection(c *check.C) {
	sslConn := NewSSL()

	// listen on all interfaces
	ln, err := net.Listen("tcp", "127.0.0.1:8281")
	c.Check(err, check.IsNil)

	// run loop
	go func() {

		for err == nil {
			// accept connection on port
			conn, err := ln.Accept()
			c.Check(err, check.IsNil)

			sslConn.InitConnection(s.ctx)

			n := 0
			ourBuf := make([]byte, 4096)
			hasDone := false

			var sslBuf []byte

			// SSL Handshake
			for n, _ = conn.Read(ourBuf); ; n, _ = conn.Read(ourBuf) {
				sslBuf, n, hasDone = sslConn.DoHandshake(ourBuf, n)
				if n > 0 {
					conn.Write(sslBuf[:n])
				}
				if hasDone {
					break
				}
				conn.SetReadDeadline(time.Now().Add(time.Second * 1))
			}

			// Normal Connection Loop
			for {
				conn.SetReadDeadline(time.Now().Add(time.Second * 1))
				n, _ = conn.Read(ourBuf)

				sslConn.WriteEncrypted(ourBuf, n)

				sslBuf, n = sslConn.ReadDecrypted(4096)

				// output message received
				if n > 0 {
					fmt.Print("Message Received: ", string(sslBuf[:n]))
					break
				}
				for {
					sslBuf, n = sslConn.ReadEncrypted(4096)
					if n < 0 {
						break
					}
					n, err = conn.Write(sslBuf[:n])
					c.Check(err, check.IsNil)
				}
			}

			c.Check(string(sslBuf[:n]), check.Equals, "hello\n")

			// Write a response
			sslConn.WriteDecrypted([]byte("hello back foreigner!\n"))
			for {
				sslBuf, n = sslConn.ReadEncrypted(4096)
				if n < 0 {
					break
				}
				n, err = conn.Write(sslBuf[:n])
				c.Check(err, check.IsNil)
			}

			conn.Close()
			sslConn.DestroyConnection()
			sslConn = nil
			break
		}
	}()

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "127.0.0.1:8281", conf)
	c.Check(err, check.IsNil)

	defer conn.Close()

	_, err = conn.Write([]byte("hello\n"))
	c.Check(err, check.IsNil)

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	c.Check(err, check.IsNil)
	c.Check(buf[:n], check.DeepEquals, []byte("hello back foreigner!\n"))
	ssl.SSL_CTX_free(s.ctx)
}
