package server

import (
	"github.com/akutz/memconn"
	"sync"

	"testing"

	"gopkg.in/check.v1"
)

var _ = check.Suite(&S{})

const (
	address = "server:10000"
)

type S struct {
	s Server
}

func Test(t *testing.T) { check.TestingT(t) }

func (s *S) SetUpSuite(c *check.C) {
	s.s.waitGroup = &sync.WaitGroup{}

	s.s.admin = NewAdminServer(&s.s)
	s.s.proxy = NewProxyServer(&s.s)

	adminListener, err := memconn.Listen("memu", address)
	c.Check(err, check.IsNil)

	go s.s.admin.Serve(adminListener)
}

func (s *S) TearDownSuite(c *check.C) {
}

func (s *S) SetUpTest(c *check.C) {
}

func (s *S) TestStatus(c *check.C) {

}
