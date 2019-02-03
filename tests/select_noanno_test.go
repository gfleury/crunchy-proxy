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
	"gopkg.in/check.v1"
	"log"
	"time"
)

func (s *S) TestSelectNoAnno(c *check.C) {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("TestSelect was called")
	var startTime = time.Now()
	conn, err := Connect()
	c.Check(err, check.IsNil)
	defer conn.Close()

	var timestamp string
	err = conn.QueryRow("select text(now())").Scan(&timestamp)
	c.Check(err, check.IsNil)

	var endTime = time.Since(startTime)
	log.Printf("Duration %s\n", endTime)

}
