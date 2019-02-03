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
	"database/sql"
	"gopkg.in/check.v1"
	"log"
	"time"
)

func (s *S) TestOverhead(c *check.C) {
	var proxyconn, conn *sql.DB
	var err error

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("TestOverhead was called")
	proxyconn, err = Connect()
	c.Check(err, check.IsNil)

	HostPort = "localhost:5432"
	conn, err = Connect()
	c.Check(err, check.IsNil)

	log.Println("")
	log.Println("Overhead (no annotation)")
	log.Println("")

	var timestamp string
	var proxyStartTime = time.Now()
	err = proxyconn.QueryRow("select now()").Scan(&timestamp)
	c.Check(err, check.IsNil)

	proxyDuration := time.Since(proxyStartTime)
	log.Printf("Proxy Duration (no annotation) %s\n", proxyDuration)

	noProxyStartTime := time.Now()
	err = conn.QueryRow("select now()").Scan(&timestamp)
	c.Check(err, check.IsNil)

	noProxyDuration := time.Since(noProxyStartTime)
	log.Printf("No Proxy Duration (no annotation) %s\n", noProxyDuration)

	log.Printf("Proxy Overhead (no annotation) %s\n", proxyDuration-noProxyDuration)
	proxyStartTime = time.Now()
	err = proxyconn.QueryRow("/* read */select now()").Scan(&timestamp)
	c.Check(err, check.IsNil)

	log.Println("")
	log.Println("Overhead (annotation is supplied)")
	log.Println("")

	proxyDuration = time.Since(proxyStartTime)
	log.Printf("Proxy Duration (annotation) %s\n", proxyDuration)

	noProxyStartTime = time.Now()
	err = conn.QueryRow("/* read */select now()").Scan(&timestamp)
	c.Check(err, check.IsNil)

	noProxyDuration = time.Since(noProxyStartTime)
	log.Printf("No Proxy Duration (annotation) %s\n", noProxyDuration)
	log.Printf("Proxy Overhead (annotation) %s\n", proxyDuration-noProxyDuration)

	proxyconn.Close()
	conn.Close()

}
