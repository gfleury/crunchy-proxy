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
	"github.com/tidwall/evio"
	"io"
	"net"
	"time"

	"github.com/crunchydata/crunchy-proxy/config"
	"github.com/crunchydata/crunchy-proxy/connect"
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
	transactionBlock bool
	cp               *pool.Pool // The connection pool in use
	backend          net.Conn   // The backend connection in use
	read             bool
	nodeName         string

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

	proxyServer.events.NumLoops = -1

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

	log.Debugf("Doing Something For %s", c.RemoteAddr())

	if in == nil {
		log.Debugf("wake from %s", c.RemoteAddr())
	}

	pc := c.Context().(*conn)
	data := pc.is.Begin(in)

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
		/*
		 * Try to upgrade connection to TLS, not implemented yet.
		 */
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
					action = evio.Close
					break
				}

				/* Establish a connection with the master node. */
				log.Info("client auth: connecting to 'master' node")

				pc.master, err = connect.Connect(node.HostPort)

				if err != nil {
					log.Error("An error occurred connecting to the master node")
					log.Errorf("Error %s", err.Error())
					action = evio.Close
					break
				}

				/* Relay the startup message to master node. */
				log.Debugf("client auth: relay startup message to 'master' node")
				_, err = pc.master.Write(data)

				if err != nil {
					log.Error("An error occurred writing the authentication to master node.")
					log.Errorf("Error %s", err.Error())
					action = evio.Close
					pc.master.Close()
					break
				}

				/* Receive startup response. */
				log.Infof("client auth: receiving startup response from 'master' node")
				message, length, err := connect.Receive(pc.master)

				if err != nil {
					log.Error("An error occurred receiving startup response.")
					log.Errorf("Error %s", err.Error())
					action = evio.Close
					pc.master.Close()
					break
				}

				messageType := protocol.GetMessageType(message)

				if protocol.IsAuthenticationOk(message) &&
					(messageType != protocol.ErrorResponseMessageType) {
					log.Debugf("client auth: checking authentication response")
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
					log.Errorf("The master closed the connection.")
					action = evio.Close
					break
				}

				message, length, err := connect.Receive(pc.master)

				if (err != nil) && (err == io.EOF) {
					log.Errorf("The master closed the connection.")
					log.Errorf("If the client is 'psql' and the authentication method " +
						"was 'password', then this behavior is expected.")
					action = evio.Close
					break
				}

				if protocol.IsAuthenticationOk(message) {
					log.Debugf("client auth: checking authentication response")
					termMsg := protocol.GetTerminateMessage()
					connect.Send(pc.master, termMsg)
					pc.phase = AUTHENTICATED
					log.Infof("Client: %s - authentication successful", c.RemoteAddr())
				} else if protocol.GetMessageType(data) == protocol.ErrorResponseMessageType {
					err := protocol.ParseError(data)
					log.Error("Error occurred on client startup.")
					log.Errorf("Error: %s", err.Error())
					action = evio.Close
				} else if protocol.GetMessageType(data) == protocol.PasswordMessageMessageType {
					log.Error("Authentication with master failed.")
					action = evio.Close
				} else {
					log.Error("Unknown error occurred on client startup.")
					action = evio.Close
				}

				out = message[:length]
				data = []byte{}

				/* Defer close master authentication connection */
				defer pc.master.Close()
				pc.master = nil
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
					action = evio.Close
					break
				} else if messageType == protocol.QueryMessageType && pc.actualConnection == nil {
					log.Infof("Client: Allocating connection from pool to client %s", c.RemoteAddr())
					pc.actualConnection = &poolConnection{}

					annotations := getAnnotations(data)

					// if annotations[StartAnnotation] {
					// 	pc.actualConnection.transactionBlock = true
					// } else if annotations[EndAnnotation] {
					// 	pc.actualConnection.transactionBlock = false
					// }

					pc.actualConnection.transactionBlock = false
					pc.actualConnection.read = annotations[ReadAnnotation]

					/*
					 * If not in a statement block or if the pool or backend are not already
					 * set, then fetch a new backend to receive the message.
					 */
					if !pc.actualConnection.transactionBlock || pc.actualConnection.cp == nil || pc.actualConnection.backend == nil {
						pc.actualConnection.cp = s.p.GetPool(pc.actualConnection.read)
						pc.actualConnection.backend = pc.actualConnection.cp.Next()
						pc.actualConnection.nodeName = pc.actualConnection.cp.Name
						s.p.ReturnPool(pc.actualConnection.cp, pc.actualConnection.read)
					}

					/* Update the query count for the node being used. */
					// s.p.lock.Lock()
					//s.p.Stats[pc.actualConnection.nodeName] += 1
					// s.p.lock.Unlock()

				}
				/* Relay message to client and backend */
				if _, err := connect.Send(pc.actualConnection.backend, data); err != nil {
					log.Errorf("Error sending message to backend %s", pc.actualConnection.backend.RemoteAddr())
					log.Errorf("Error: %s", err.Error())
					pc.ReleaseBackend()
					action = evio.Close
					break
				}
			}

			/*
			 * Read first 5 bytes
			 * 1   - MessageType
			 * 2-5 - MessageLength
			 */
			message, length, err := connect.Read(pc.actualConnection.backend, 5)
			for err == nil && length < 5 {
				var restPiece []byte
				var newLength int
				restPiece, newLength, err = connect.Read(pc.actualConnection.backend, 5-length)
				message = append(message, restPiece...)
				length += newLength
			}
			if err != nil {
				log.Errorf("Error receiving response from backend %s", pc.actualConnection.backend.RemoteAddr())
				log.Errorf("Length: %d, %s", length, err.Error())
				pc.ReleaseBackend()
				action = evio.Close
				break
			}

			/*
			 * Handle the message by first getting the Message Type
			 */
			messageType := protocol.GetMessageType(message[:length])
			messageLength := protocol.GetMessageLength(message[:length])

			/* Validate if message is a valid backed message. If not handle sync loss */
			if !protocol.ValidBackendMessage(messageType) {
				log.Errorf("Not a valid backend message type, lost synchronization with server: got message type \"%c\", length %d",
					messageType, messageLength)
				pc.ReleaseBackend()
				action = evio.Close
				break
			}

			/* Validate Big Message and handle it properly */
			if messageLength > 30000 && protocol.ValidLongMessage(messageType) {
				pc.phase = READINGLONGMESSAGE
				pc.longMessageRemaingBytes = messageLength
			} else if messageLength > 30000 && !protocol.ValidLongMessage(messageType) {
				log.Errorf("Message too big for his kind, lost synchronization with server: got message type \"%c\", length %d",
					messageType, messageLength)
				pc.ReleaseBackend()
				action = evio.Close
				break
			} else {
				/* Handle normal sized messages and weird sized (non expected to be big) */
				var messageBody []byte
				bodyLength := 0
				for length < int(messageLength)+1 {
					messageBody, bodyLength, err = connect.Read(pc.actualConnection.backend, (int(messageLength)+1)-length)
					if err != nil {
						log.Errorf("Error receiving response from backend %s", pc.actualConnection.backend.RemoteAddr())
						log.Errorf("Error: %s", err.Error())
						pc.ReleaseBackend()
						action = evio.Close
						return
					}
					message = append(message, messageBody...)
					length += bodyLength
				}
				if length != int(messageLength)+1 {
					log.Errorf("Error receiving response from backend %s, different sizes of msgSize %d and expect %d", pc.actualConnection.backend.RemoteAddr(), length, messageLength+1)
					pc.ReleaseBackend()
					action = evio.Close
					return
				}
			}

			log.Debugf("Client: %s MSG type=%c length=%d readLength=%d", c.RemoteAddr(), messageType, messageLength, length)

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
				log.Errorf("Error receiving response from backend %s", pc.actualConnection.backend.RemoteAddr())
				log.Errorf("Error: %s", err.Error())
				pc.ReleaseBackend()
				action = evio.Close
				break
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
			pc.ReleaseBackend()
		}
	}
	pc.is.End(data)

	log.Debugf("Client: Leaving something %s", c.RemoteAddr())
	return
}

func (s *ProxyServer) Serving(srv evio.Server) (action evio.Action) {
	log.Infof("Proxy server started on %s (loops: %d)", srv.Addrs[0].String(), srv.NumLoops)

	return
}

func (s *ProxyServer) Opened(c evio.Conn) (out []byte, opts evio.Options, action evio.Action) {
	log.Infof("opened: %v", c.RemoteAddr())
	c.SetContext(&conn{
		phase:                   INIT,
		longMessageRemaingBytes: 0,
		addr:                    c.RemoteAddr().String(),
	})

	opts.TCPKeepAlive = 20 * time.Second

	return
}

func (s *ProxyServer) Closed(c evio.Conn, err error) (action evio.Action) {
	log.Infof("closed: %v", c.RemoteAddr())
	return
}

func (pc *conn) ReleaseBackend() {
	/*
	 * If at the end of a statement block or not part of statment block,
	 * then return the connection to the pool.
	 */
	if !pc.actualConnection.transactionBlock {
		var err error

		/* Flushing the remaning data in the connection */
		for err == nil {
			err = connect.Flush(pc.actualConnection.backend)
		}

		/* Return the backend to the pool it belongs to. */
		log.Infof("Client: Releasing pool to client %s", pc.addr)
		pc.actualConnection.cp.Return(pc.actualConnection.backend)
		pc.actualConnection = nil
	}
}
