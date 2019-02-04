package ssl

import (
	"crypto/tls"
	"fmt"
	"github.com/crunchydata/crunchy-proxy/util/log"
	"net"
	"testing"
	"time"

	"gopkg.in/check.v1"
)

var _ = check.Suite(&S{})

type S struct {
	s *SSL
}

func Test(t *testing.T) { check.TestingT(t) }

func (s *S) SetUpSuite(c *check.C) {
	s.s = NewSSL()
	err := s.s.InitCTX()
	c.Check(err, check.IsNil)

	log.SetLevel("debug")
}

func (s *S) TestOpenssl(c *check.C) {
	// listen on all interfaces
	ln, err := net.Listen("tcp", "127.0.0.1:8281")
	c.Check(err, check.IsNil)

	// run loop
	go func() {

		for err == nil {
			// accept connection on port
			conn, err := ln.Accept()
			c.Check(err, check.IsNil)

			s.s.InitConnection()
			buf := make([]byte, 4096)

			for {

				n, err := conn.Read(buf)
				c.Check(err, check.IsNil)

				if s.s.WriteEncrypted(buf, n) == -2 {
					for {
						buff, nn := s.s.ReadEncrypted(4096)
						if nn < 0 {
							break
						}
						xx, err := conn.Write(buff[:nn])
						c.Check(err, check.IsNil)
						fmt.Printf("Wrote %d\n", xx)
					}
				}
				if s.s.SSL_is_init_finished() {
					break
				}
			}
			SSLReply, xx := s.s.ReadDecrypted(4096)
			for {
				conn.SetReadDeadline(time.Now().Add(time.Second * 1))
				n, _ := conn.Read(buf)

				s.s.WriteEncrypted(buf, n)
				SSLReply, xx = s.s.ReadDecrypted(4096)
				// output message received
				if xx > 0 {
					break
				}
				for {
					buff, nn := s.s.ReadEncrypted(4096)
					if nn < 0 {
						break
					}
					xx, err := conn.Write(buff[:nn])
					c.Check(err, check.IsNil)
					fmt.Printf("Wrote %d\n", xx)
				}
			}
			fmt.Print("Message Received: ", string(SSLReply[:xx]))

			conn.Close()
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
	_, err = conn.Read(buf)
	c.Check(err, check.ErrorMatches, "EOF")

}
