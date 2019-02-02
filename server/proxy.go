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

package server

import (
	"net"

	"github.com/crunchydata/crunchy-proxy/proxy"
)

type ProxyServer struct {
	ch       chan bool
	server   *Server
	p        *proxy.Proxy
	listener net.Listener
}

func NewProxyServer(s *Server) *ProxyServer {
	proxyServer := &ProxyServer{}
	proxyServer.ch = make(chan bool)
	proxyServer.server = s

	proxyServer.p = proxy.NewProxy()

	return proxyServer
}

func (s *ProxyServer) Stats() map[string]int32 {
	return s.p.Stats
}

func (s *ProxyServer) Stop() {
	s.listener.Close()
	close(s.ch)
}
