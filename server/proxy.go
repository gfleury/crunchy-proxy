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
	"fmt"
	"github.com/crunchydata/crunchy-proxy/connect"
	"github.com/tidwall/evio"
	"io"
	"net"

	"github.com/crunchydata/crunchy-proxy/config"
	"github.com/crunchydata/crunchy-proxy/pool"
	"github.com/crunchydata/crunchy-proxy/protocol"
	"github.com/crunchydata/crunchy-proxy/proxy"
	"github.com/crunchydata/crunchy-proxy/util/log"
)

type ProxyServer struct {
	ch       chan bool
	server   *Server
	p        *proxy.Proxy
	listener net.Listener
	events   evio.Events
}

type connectionPhase int

const (
	INIT               connectionPhase = 0
	UPGRADESSL         connectionPhase = 1
	VALIDATECLIENT     connectionPhase = 2
	AUTHENTICATED      connectionPhase = 3
	READINGLONGMESSAGE connectionPhase = 4
	RELEASEBACKEND     connectionPhase = 5
)

type conn struct {
	is                      evio.InputStream
	addr                    string
	phase                   connectionPhase
	master                  net.Conn
	actualConnection        *poolConnection
	longMessageRemaingBytes int32
}

type poolConnection struct {
	/* Process the client messages for the life of the connection. */
	statementBlock bool
	cp             *pool.Pool // The connection pool in use
	backend        net.Conn   // The backend connection in use
	read           bool
	end            bool
	nodeName       string

	done bool // for message processing loop.
}

func NewProxyServer(s *Server) *ProxyServer {
	proxyServer := &ProxyServer{}
	proxyServer.ch = make(chan bool)
	proxyServer.server = s

	proxyServer.events.Data = proxyServer.Data
	proxyServer.events.Serving = proxyServer.Serving
	proxyServer.events.Opened = proxyServer.Opened
	proxyServer.events.Closed = proxyServer.Closed

	proxyServer.p = proxy.NewProxy()

	return proxyServer
}

func (s *ProxyServer) Serve(l net.Listener) error {
	log.Infof("Proxy Server listening on: %s", l.Addr())
	defer s.server.waitGroup.Done()
	s.listener = l

	s.p = proxy.NewProxy()

	for {

		select {
		case <-s.ch:
			return nil
		default:
		}

		conn, err := l.Accept()

		if err != nil {
			continue
		}

		go s.p.HandleConnection(conn)
	}
}

func (s *ProxyServer) Stats() map[string]int32 {
	return s.p.Stats
}

func (s *ProxyServer) Stop() {
	s.listener.Close()
	close(s.ch)
}

// ASync
func (s *ProxyServer) Data(c evio.Conn, in []byte) (out []byte, action evio.Action) {
	stayHere := true

	log.Info(fmt.Sprintf("Doing Something For %s", c.RemoteAddr()))

	if in == nil {
		log.Info(fmt.Sprintf("wake from %s", c.RemoteAddr()))
		//return nil, evio.Close
	}

	pc := c.Context().(*conn)
	data := pc.is.Begin(in)
	// var n int
	// var complete bool
	// var err error
	for stayHere {
		switch pc.phase {
		case INIT:
			/* Get the protocol from the startup message.*/
			version := protocol.GetVersion(data)

			/* Handle the case where the startup message was an SSL request. */
			if version == protocol.SSLRequestCode {
				sslResponse := protocol.NewMessageBuffer([]byte{})

				/* Determine which SSL response to send to client. */
				creds := config.GetCredentials()
				if creds.SSL.Enable {
					sslResponse.WriteByte(protocol.SSLAllowed)
				} else {
					sslResponse.WriteByte(protocol.SSLNotAllowed)
				}

				/*
				 * Send the SSL response back to the client and wait for it to send the
				 * regular startup packet.
				 */
				// out = sslResponse.Bytes()
				// pc.phase = UPGRADESSL
				pc.phase = VALIDATECLIENT
			} else {
				pc.phase = VALIDATECLIENT
			}
			break
		case UPGRADESSL:
			/* Upgrade the client connection if required. */
			//client = connect.UpgradeServerConnection(client)
			pc.phase = VALIDATECLIENT
			//data = []byte{}
			break

		/*
		 * Validate that the client username and database are the same as that
		 * which is configured for the proxy connections.
		 *
		 * If the the client cannot be validated then send an appropriate PG error
		 * message back to the client.
		 */
		case VALIDATECLIENT:
			stayHere = false
			var err error

			if pc.master == nil {
				/* Authenticate the client against the appropriate backend. */
				log.Infof("Client: %s - authenticating", c.RemoteAddr())

				nodes := config.GetNodes()

				node := nodes["master"]

				if !connect.ValidateClient(data) {
					pgError := protocol.Error{
						Severity: protocol.ErrorSeverityFatal,
						Code:     protocol.ErrorCodeInvalidAuthorizationSpecification,
						Message:  "could not validate user/database",
					}

					out = pgError.GetMessage()
					log.Errorf("Could not validate client %s", c.RemoteAddr())
					data = []byte{}
					action = evio.Close
					break
				}

				/* Establish a connection with the master node. */
				log.Info("client auth: connecting to 'master' node")

				pc.master, err = connect.Connect(node.HostPort)

				if err != nil {
					log.Error("An error occurred connecting to the master node")
					log.Errorf("Error %s", err.Error())
					data = []byte{}
					action = evio.Close
					break
				}

				/* Relay the startup message to master node. */
				log.Infof("client auth: relay startup message to 'master' node")
				_, err = pc.master.Write(data)

				/* Receive startup response. */
				log.Infof("client auth: receiving startup response from 'master' node")
				message, length, err := connect.Receive(pc.master)

				if err != nil {
					log.Error("An error occurred receiving startup response.")
					log.Errorf("Error %s", err.Error())
					data = []byte{}
					action = evio.Close
					pc.master.Close()
					break
				}

				messageType := protocol.GetMessageType(message)

				if protocol.IsAuthenticationOk(message) &&
					(messageType != protocol.ErrorMessageType) {
					log.Infof("client auth: checking authentication response")
					termMsg := protocol.GetTerminateMessage()
					connect.Send(pc.master, termMsg)
					pc.phase = AUTHENTICATED
				}
				out = message[:length]
				data = []byte{}
				break
			} else {
				_, err := connect.Send(pc.master, data)

				if (err != nil) && (err == io.EOF) {
					log.Info("The master closed the connection.")
					data = []byte{}
					action = evio.Close
					break
				}

				message, length, err := connect.Receive(pc.master)

				if (err != nil) && (err == io.EOF) {
					log.Info("The master closed the connection.")
					log.Info("If the client is 'psql' and the authentication method " +
						"was 'password', then this behavior is expected.")
					data = []byte{}
					action = evio.Close
					break
				}

				if protocol.IsAuthenticationOk(message) {
					log.Info("client auth: checking authentication response")
					termMsg := protocol.GetTerminateMessage()
					connect.Send(pc.master, termMsg)
					pc.phase = AUTHENTICATED
					log.Infof("Client: %s - authentication successful", c.RemoteAddr())
				} else if protocol.GetMessageType(data) == protocol.ErrorMessageType {
					err := protocol.ParseError(data)
					log.Error("Error occurred on client startup.")
					log.Errorf("Error: %s", err.Error())
				} else if protocol.GetMessageType(data) == protocol.PasswordMessageType {
					log.Error("Authentication with master failed.")
				} else {
					log.Error("Unknown error occurred on client startup.")
				}

				out = message[:length]
				data = []byte{}
			}
		case AUTHENTICATED:
			stayHere = false

			if len(data) > 0 {
				messageType := protocol.GetMessageType(data)

				/*
				 * If the message is a simple query, then it can have read/write
				 * annotations attached to it. Therefore, we need to process it and
				 * determine which backend we need to send it to.
				 */
				if messageType == protocol.TerminateMessageType {
					log.Infof("Client: %s - disconnected", c.RemoteAddr())
					data = []byte{}
					action = evio.Close
					break
				} else if messageType == protocol.QueryMessageType && pc.actualConnection == nil {
					log.Infof("Client: Allocating connection from pool to client %s", c.RemoteAddr())
					pc.actualConnection = &poolConnection{}

					annotations := getAnnotations(data)

					if annotations[StartAnnotation] {
						pc.actualConnection.statementBlock = true
					} else if annotations[EndAnnotation] {
						pc.actualConnection.end = true
						pc.actualConnection.statementBlock = false
					}

					pc.actualConnection.read = annotations[ReadAnnotation]

					/*
					 * If not in a statement block or if the pool or backend are not already
					 * set, then fetch a new backend to receive the message.
					 */
					if !pc.actualConnection.statementBlock && !pc.actualConnection.end || pc.actualConnection.cp == nil || pc.actualConnection.backend == nil {
						pc.actualConnection.cp = s.p.GetPool(pc.actualConnection.read)
						pc.actualConnection.backend = pc.actualConnection.cp.Next()
						pc.actualConnection.nodeName = pc.actualConnection.cp.Name
						s.p.ReturnPool(pc.actualConnection.cp, pc.actualConnection.read)
					}

					/* Update the query count for the node being used. */
					// s.p.lock.Lock()
					s.p.Stats[pc.actualConnection.nodeName] += 1
					// s.p.lock.Unlock()

				}
				/* Relay message to client and backend */
				if _, err := connect.Send(pc.actualConnection.backend, data); err != nil {
					log.Infof("Error sending message to backend %s", pc.actualConnection.backend.RemoteAddr())
					log.Infof("Error: %s", err.Error())
				}
			}
			/*
			 * Continue to read from the backend until a 'ReadyForQuery' message is
			 * is found.
			 */

			message, length, err := connect.Receive(pc.actualConnection.backend)
			if err != nil {
				log.Debugf("Error receiving response from backend %s", pc.actualConnection.backend.RemoteAddr())
				log.Debugf("Error: %s", err.Error())
				pc.actualConnection.done = true
			}

			messageType := protocol.GetMessageType(message[:length])
			// totalSize := 0
			/*
			 * Examine all of the messages in the buffer and determine if any of
			 * them are a ReadyForQuery message.
			 */
			for start := 0; start < length; {
				messageType = protocol.GetMessageType(message[start:])
				if start+5 >= length {
					newMessage, newLength, err := connect.Read(pc.actualConnection.backend, (start+5)-length)
					if err != nil {
						log.Debugf("Error receiving response from backend %s", pc.actualConnection.backend.RemoteAddr())
						log.Debugf("Error: %s", err.Error())
						pc.actualConnection.done = true
					}
					message = append(message, newMessage...)
					length += newLength
				}
				messageLength := protocol.GetMessageLength(message[start:])
				if messageLength > 30000 && VALID_LONG_MESSAGE_TYPE(messageType) {
					pc.phase = READINGLONGMESSAGE
					pc.longMessageRemaingBytes = messageLength
					break
				} else if start+int(messageLength) >= length {
					newMessage, newLength, err := connect.Read(pc.actualConnection.backend, (start+int(messageLength)+1)-length)
					if err != nil {
						log.Debugf("Error receiving response from backend %s", pc.actualConnection.backend.RemoteAddr())
						log.Debugf("Error: %s", err.Error())
						pc.actualConnection.done = true
					}
					message = append(message, newMessage...)
					length += newLength
				}
				/*
				 * Calculate the next start position, add '1' to the message
				 * length to account for the message type.
				 */
				start = (start + int(messageLength) + 1)
				// totalSize += int(messageLength) + 1
				// fmt.Printf("\nType: %d\n", messageType)
				// fmt.Printf("MessageLength: %d\n", int(messageLength))
				// fmt.Printf("RealMessageLength: %d\n", len(message))
				// fmt.Printf("TotalSize: %d\n", totalSize)
				// fmt.Printf("Start: %d\n", start)
				// fmt.Printf("Length: %d\n", length)
			}

			out = message[:length]

			pc.actualConnection.done = (messageType == protocol.ReadyForQueryMessageType)
			if pc.actualConnection.done {
				stayHere = true
				pc.phase = RELEASEBACKEND
			} else {
				go c.Wake()
			}
			data = []byte{}
		case READINGLONGMESSAGE:
			stayHere = false
			log.Debugf("Client: reading long messaging from %s, remaining bytes %d", pc.actualConnection.backend.RemoteAddr(), pc.longMessageRemaingBytes)

			message, length, err := connect.Receive(pc.actualConnection.backend)
			if err != nil {
				log.Debugf("Error receiving response from backend %s", pc.actualConnection.backend.RemoteAddr())
				log.Debugf("Error: %s", err.Error())
				pc.phase = RELEASEBACKEND
			}

			out = message[:length]
			pc.longMessageRemaingBytes -= int32(length)

			if pc.longMessageRemaingBytes == 0 {
				pc.phase = AUTHENTICATED
			}
			go c.Wake()
		case RELEASEBACKEND:
			stayHere = false
			pc.phase = AUTHENTICATED
			/*
			 * If at the end of a statement block or not part of statment block,
			 * then return the connection to the pool.
			 */
			if !pc.actualConnection.statementBlock {
				/*
				 * Toggle 'end' such that a new connection will be fetched on the
				 * next query.
				 */
				if pc.actualConnection.end {
					pc.actualConnection.end = false
				}

				/* Return the backend to the pool it belongs to. */
				log.Infof("Client: Releasing pool to client %s", c.RemoteAddr())
				pc.actualConnection.cp.Return(pc.actualConnection.backend)
				pc.actualConnection = nil
			}
		}
	}
	pc.is.End(data)

	log.Infof("Client: Leaving something %s", c.RemoteAddr())
	return
}

func (s *ProxyServer) Serving(srv evio.Server) (action evio.Action) {
	log.Info(fmt.Sprintf("Proxy server started on %s (loops: %d)", srv.Addrs[0].String(), srv.NumLoops))

	return
}

func (s *ProxyServer) Opened(c evio.Conn) (out []byte, opts evio.Options, action evio.Action) {
	log.Info(fmt.Sprintf("opened: %v", c.RemoteAddr()))
	c.SetContext(&conn{
		phase:                   INIT,
		longMessageRemaingBytes: 0,
	})
	return
}

func (s *ProxyServer) Closed(c evio.Conn, err error) (action evio.Action) {
	log.Info(fmt.Sprintf("closed: %v", c.RemoteAddr()))
	return
}

func VALID_LONG_MESSAGE_TYPE(id byte) bool {
	return ((id) == 'T' || (id) == 'D' || (id) == 'd' || (id) == 'V' || (id) == 'E' || (id) == 'N' || (id) == 'A')
}
