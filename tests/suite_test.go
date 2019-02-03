/*
Copyright 2016 Crunchy Data Solutions, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package tests

import (
	"flag"
	"github.com/crunchydata/crunchy-proxy/config"
	"strings"
	"testing"

	"gopkg.in/check.v1"

	"github.com/crunchydata/crunchy-proxy/server"
)

const (
	testConfig = `server:
  proxy:
    hostport: 0.0.0.0:5433
  admin:
    hostport: 127.0.0.1:8000

nodes:
  master:
    hostport: 127.0.0.1:5432
    role: master
    metadata: {}

credentials:
  username: postgres
  database: postgres
  password: 
  options:
  ssl:
    enable: false
    sslmode: disable

pool:
  capacity: 2

healthcheck:
  delay: 60
  query: select now();`
)

var HostPort, DatabaseUrl string
var rows, userid, password, database string

var _ = check.Suite(&S{})

type S struct {
	s *server.Server
}

func Test(t *testing.T) { check.TestingT(t) }

func (s *S) SetUpSuite(c *check.C) {
	flag.StringVar(&rows, "rows", "onerow", "onerow or tworows")
	flag.StringVar(&HostPort, "hostport", "localhost:5433", "host:port")
	flag.StringVar(&DatabaseUrl, "databaseUrl", "localhost:5432", "host:port")
	flag.StringVar(&userid, "userid", "postgres", "postgres userid")
	flag.StringVar(&password, "password", "", "postgres password")
	flag.StringVar(&database, "database", "postgres", "database")
	flag.Parse()

	configLoad()
	s.s = server.NewServer()

	go func() {
		s.s.Start()
	}()
}

func (s *S) TearDownSuite(c *check.C) {
}

func (s *S) SetUpTest(c *check.C) {
}

func configLoad() {
	config.ParseConfig(strings.NewReader(testConfig))
}
