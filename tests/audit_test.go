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
	// "bytes"
	"gopkg.in/check.v1"
	// "io/ioutil"
	"log"
	"time"
)

func (s *S) TestAudit(c *check.C) {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("TestAudit was called")
	var startTime = time.Now()
	conn, err := Connect()
	defer conn.Close()
	c.Check(err, check.IsNil)

	var timestamp string
	err = conn.QueryRow("/* read */ select text(now())").Scan(&timestamp)
	c.Check(err, check.IsNil)

	log.Println(timestamp + " was returned")

	// // dat, err := ioutil.ReadFile("/tmp/audit.log")
	// // c.Check(err, check.IsNil)

	// if bytes.Contains(dat, []byte("msg")) {
	// 	log.Println("audit records were found")
	// } else {
	// 	log.Println("audit records were not found")
	// }

	var endTime = time.Since(startTime)
	log.Printf("Duration %s\n", endTime)

}
