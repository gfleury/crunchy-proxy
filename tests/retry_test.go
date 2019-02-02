/*
Copyright 2017 Crunchy Data Solutions, Inc.
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
	"bytes"
	"database/sql"
	"gopkg.in/check.v1"
	"log"
	"net/http"
	"os/exec"
	"time"
)

func (s *S) TestRetry(c *check.C) {
	const SLEEP_TIME = 6
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("TestRetry was called")
	var startTime = time.Now()
	conn, err := Connect()
	defer conn.Close()
	c.Check(err, check.IsNil)

	//read the proxy event stream which equates to a healthcheck
	//has just been performed...after which we will have a retry test
	//window
	_, err = http.Get("http://localhost:10000/api/stream")
	c.Check(err, check.IsNil)

	log.Println("after the GET")

	//shut down the replica
	var cmdStdout, cmdStderr bytes.Buffer
	var cmd *exec.Cmd
	cmd = exec.Command("docker", "stop", "replica")
	cmd.Stdout = &cmdStdout
	cmd.Stderr = &cmdStderr
	err = cmd.Run()
	c.Check(err, check.IsNil)

	log.Println("docker stop stdout=" + cmdStdout.String())

	//sleep a bit to give the replica time to stop
	log.Println("sleeping to let replica shutdown")
	time.Sleep(time.Duration(SLEEP_TIME) * time.Second)

	var timestamp string
	log.Println("performing a read query with replica down but with hc showing up")
	err = conn.QueryRow("/* read */ select text(now())").Scan(&timestamp)
	c.Check(err, check.IsNil)

	var endTime = time.Since(startTime)

	log.Println("before starting docker..")
	cmd = exec.Command("docker", "start", "replica")
	err = cmd.Run()
	c.Check(err, check.IsNil)

	log.Println("docker start stdout=" + cmdStdout.String())
	//sleep a bit to give the replica time to restart
	log.Println("sleeping to let replica restart")
	time.Sleep(time.Duration(SLEEP_TIME) * time.Second)

	log.Printf("Duration %s\n", endTime)

}
