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

package pool

import (
	"github.com/crunchydata/crunchy-proxy/util/log"
	"net"
	"time"
)

type Pool struct {
	connections chan net.Conn
	Name        string
	Capacity    int
}

func NewPool(name string, capacity int) *Pool {
	return &Pool{
		connections: make(chan net.Conn, capacity),
		Name:        name,
		Capacity:    capacity,
	}
}

func (p *Pool) Add(connection net.Conn) {
	p.connections <- connection
}

func (p *Pool) Next() (net.Conn, bool) {
	select {
	case res := <-p.connections:
		return res, true
	case <-time.After(100 * time.Millisecond):
		log.Infof("Client: No connection available on the selected Pool, putting the connection on hold")
		return nil, false
	}
}

func (p *Pool) Return(connection net.Conn) {
	p.connections <- connection
}

func (p *Pool) Len() int {
	return len(p.connections)
}
