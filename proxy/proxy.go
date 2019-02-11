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

package proxy

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/evio"

	"github.com/crunchydata/crunchy-proxy/common"
	"github.com/crunchydata/crunchy-proxy/config"
	"github.com/crunchydata/crunchy-proxy/connect"
	"github.com/crunchydata/crunchy-proxy/pool"
	"github.com/crunchydata/crunchy-proxy/protocol"
	"github.com/crunchydata/crunchy-proxy/util/log"
)

type connectionPhase int

const (
	INIT               connectionPhase = 0
	UPGRADESSL         connectionPhase = 1
	VALIDATECLIENT     connectionPhase = 2
	AUTHENTICATED      connectionPhase = 3
	READINGLONGMESSAGE connectionPhase = 4
	RELEASEBACKEND     connectionPhase = 5
)

type Proxy struct {
	writePools chan *pool.Pool
	readPools  chan *pool.Pool
	stats      map[string]int32
	lock       *sync.Mutex
	events     evio.Events
}

func NewProxy(el int) *Proxy {
	p := &Proxy{
		stats: make(map[string]int32),
		lock:  &sync.Mutex{},
	}

	p.events.Data = p.Data
	p.events.Serving = p.Serving
	p.events.Opened = p.Opened
	p.events.Closed = p.Closed

	p.events.NumLoops = el

	p.setupPools()

	return p
}

func (p *Proxy) setupPools() {
	nodes := config.GetNodes()
	capacity := config.GetPoolCapacity()

	/* Initialize pool structures */
	numNodes := len(nodes)
	p.writePools = make(chan *pool.Pool, numNodes)
	p.readPools = make(chan *pool.Pool, numNodes)

	for name, node := range nodes {
		/* Create Pool for Node */
		newPool := pool.NewPool(name, capacity)

		if node.Role == common.NODE_ROLE_MASTER {
			p.writePools <- newPool
		} else {
			p.readPools <- newPool
		}

		/* Create connections and add to pool. */
		for i := 0; i < capacity; i++ {
			/* Connect and authenticate */
			log.Infof("Pool: Connecting to node '%s' at %s...", name, node.HostPort)
			connection, err := connect.Connect(node.HostPort)

			if err != nil {
				log.Fatal(err.Error())
			}

			username := config.GetString("credentials.username")
			database := config.GetString("credentials.database")
			options := config.GetStringMapString("credentials.options")

			startupMessage, err := protocol.CreateStartupMessage(username, database, options)
			if err != nil {
				log.Errorf("Pool: Unable to generate startup message to node %s", name)
				log.Fatal(err.Error())
			}

			_, err = connection.Write(startupMessage)
			if err != nil {
				log.Errorf("Pool: Unable to write startup message to node %s", name)
				log.Fatal(err.Error())
			}

			response := make([]byte, 4096)
			buffer := make([]byte, 4096)
			_, err = connection.Read(response)
			if err != nil {
				log.Errorf("Pool: Unable to read startup response from node %s", name)
				log.Fatal(err.Error())
			}

			authenticated := connect.HandleAuthenticationRequest(connection, buffer, response)

			if !authenticated {
				log.Error("Pool: Authentication failed")
			}

			if err != nil {
				log.Errorf("Pool: Error establishing connection to node '%s'", name)
				log.Errorf("Error: %s", err.Error())
			} else {
				log.Infof("Pool: Successfully connected to '%s' at '%s'", name, node.HostPort)
				newPool.Add(connection)
			}
		}
	}
}

// Get the next pool. If read is set to true, then a 'read-only' pool will be
// returned. Otherwise, a 'read-write' pool will be returned.
func (p *Proxy) getPool(read bool) (*pool.Pool, bool) {
	if read {
		select {
		case res := <-p.readPools:
			return res, read
		case <-time.After(100 * time.Millisecond):
			log.Errorf("Pool: No read Pool available, trying to move foward with write pool")
			read = !read
		}
	}
	select {
	case res := <-p.writePools:
		return res, read
	case <-time.After(100 * time.Millisecond):
		log.Errorf("!!!!! Pool: No write Pool available, trying to move foward without pool, kkkk")
	}
	return <-p.writePools, read
}

// Return the pool. If read is 'true' then, the pool will be returned to the
// 'read-only' collection of pools. Otherwise, it will be returned to the
// 'read-write' collection of pools.
func (p *Proxy) returnPool(pl *pool.Pool, read bool) {
	if read {
		p.readPools <- pl
	} else {
		p.writePools <- pl
	}
}

// ASync
func (s *Proxy) Data(c evio.Conn, in []byte) (out []byte, action evio.Action) {
	stayHere := true

	remoteAddr := c.RemoteAddr()

	log.Debugf("Client: %s, received some data", remoteAddr)

	// if in == nil {
	// 	log.Debugf("Client: %s, is just a wake", remoteAddr)
	// }

	client := c.Context().(*Client)
	clientMessage := client.inputStream.Begin(in)

	for stayHere {
		switch client.phase {
		case INIT:
			/* Get the protocol from the startup message.*/
			version, err := protocol.GetVersion(clientMessage)
			if err != nil {
				log.Errorf("Client: %s, Could not read protocol version", remoteAddr)
				action = evio.Close
				break
			}

			/* Handle the case where the startup message was an SSL request. */
			if version == protocol.SSLRequestCode {
				sslResponse := protocol.NewMessageBuffer([]byte{})

				/* Determine which SSL response to send to client. */
				creds := config.GetCredentials()
				if creds.SSL.Enable {
					err = sslResponse.WriteByte(protocol.SSLAllowed)
				} else {
					err = sslResponse.WriteByte(protocol.SSLNotAllowed)
				}
				if err != nil {
					log.Errorf("Client: %s, Could not write SSL response", remoteAddr)
					action = evio.Close
					break
				}
				/*
				 * Send the SSL response back to the client and wait for it to send the
				 * regular startup packet.
				 */
				// out = sslResponse.Bytes()
				// client.phase = UPGRADESSL
				client.phase = VALIDATECLIENT
			} else {
				client.phase = VALIDATECLIENT
			}

		/*
		 * Try to upgrade connection to TLS, not implemented yet.
		 */
		case UPGRADESSL:
			/* Upgrade the client connection if required. */
			//client = connect.UpgradeServerConnection(client)
			client.phase = VALIDATECLIENT
			//data = []byte{}

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

			if client.masterConnection == nil {
				/* Authenticate the client against the appropriate backend. */
				log.Infof("Client: %s, authenticating", remoteAddr)

				client.receivingBuffer = make([]byte, 64*1024)

				nodes := config.GetNodes()

				node := nodes["master"]

				if !connect.ValidateClient(clientMessage) {
					pgError := protocol.Error{
						Severity: protocol.ErrorSeverityFatal,
						Code:     protocol.ErrorCodeInvalidAuthorizationSpecification,
						Message:  "could not validate user/database",
					}

					out = pgError.GetMessage()
					log.Errorf("Client: %s, Could not validate client", remoteAddr)
					action = evio.Close
					break
				}

				// if response, ok := connect.CacheAuth(clientMessage); ok {
				// 	log.Errorf("Found cached!!!")
				// 	client.phase = AUTHENTICATED
				// 	clientMessage = []byte{}

				// 	// message := protocol.NewMessageBuffer([]byte{})
				// 	// message.WriteByte(protocol.AuthenticationMessageType)
				// 	// message.WriteInt32(0)
				// 	// message.WriteInt32(protocol.AuthenticationOk)

				// 	// message.ResetLength(protocol.PGMessageLengthOffset)

				// 	// out = message.Bytes()
				// 	out = response
				// 	break
				// }

				/* Establish a connection with the master node. */
				log.Infof("Client: %s, auth connecting to 'master' node", remoteAddr)

				client.masterConnection, err = connect.Connect(node.HostPort)

				if err != nil {
					log.Errorf("Client: %s, an error occurred connecting to the master node", remoteAddr)
					log.Errorf("Error %s", err.Error())
					action = evio.Close
					break
				}

				/* Relay the startup message to master node. */
				log.Debugf("Client: %s, auth relay startup message to 'master' node", remoteAddr)
				_, err = client.masterConnection.Write(clientMessage)

				if err != nil {
					log.Errorf("Client: %s, an error occurred writing the authentication to master node", remoteAddr)
					log.Errorf("Error %s", err.Error())
					action = evio.Close
					client.masterConnection.Close()
					break
				}

				/* Receive startup response. */
				log.Infof("Client: %s, auth receiving startup response from 'master' node", remoteAddr)
				message, length, err := connect.Receive(client.masterConnection, client.receivingBuffer, 1000)

				if err != nil {
					log.Errorf("Client: %s, an error occurred receiving startup response", remoteAddr)
					log.Errorf("Error %s", err.Error())
					action = evio.Close
					client.masterConnection.Close()
					break
				}

				messageType := protocol.GetMessageType(message)

				if protocol.IsAuthenticationOk(message) &&
					(messageType != protocol.ErrorResponseMessageType) {
					log.Debugf("Client: %s, auth checking authentication response", remoteAddr)
					termMsg := protocol.GetTerminateMessage()
					_, err = connect.Send(client.masterConnection, termMsg)
					if err != nil {
						log.Errorf("Client: %s, failed to write to master termination message to %s, doesn't matter right now, continuing anyway.", remoteAddr, client.masterConnection.RemoteAddr())
					}
					client.phase = AUTHENTICATED
					// connect.AddCacheAuth(clientMessage, message[:length])
				}
				out = message[:length]
				clientMessage = []byte{}
				/* Close master authentication connection */
				client.masterConnection.Close()
				client.masterConnection = nil

				break
			}

		case AUTHENTICATED:
			stayHere = false

			if len(clientMessage) > 0 {
				messageType := protocol.GetMessageType(clientMessage)

				/*
				 * If the message is a simple query, then it can have read/write
				 * annotations attached to it. Therefore, we need to process it and
				 * determine which backend we need to send it to.
				 */
				if messageType == protocol.TerminateMessageType {
					log.Infof("Client: %s, disconnected", remoteAddr)
					action = evio.Close
					break
				} else if messageType == protocol.QueryMessageType && client.poolConnection == nil {
					log.Infof("Client: %s, allocating connection from pool", remoteAddr)
					client.poolConnection = &poolConnection{
						messageMissingBytes: 0,
						transactionBlock:    false,
					}

					// annotations, err := getAnnotations(clientMessage)
					// if err != nil {
					// 	log.Errorf("Client: %s, failed to get annotations from connection: %s", remoteAddr, err.Error())
					// 	action = evio.Close
					// 	break
					// }

					// client.poolConnection.read = annotations[ReadAnnotation]
					client.poolConnection.read = false

					/*
					 * If not in a statement block or if the pool or backend are not already
					 * set, then fetch a new backend to receive the message.
					 */
					var hasConnection bool
					client.poolConnection.cp, client.poolConnection.read = s.getPool(client.poolConnection.read)
					s.returnPool(client.poolConnection.cp, client.poolConnection.read)
					client.poolConnection.backend, hasConnection = client.poolConnection.cp.Next()
					if !hasConnection {
						client.poolConnection = nil
						log.Infof("Client: %s, unable to get a connection from the pool", remoteAddr)
						// Wakeup the thread in 1000 millisecond to try again
						go func() {
							time.Sleep(100 * time.Millisecond)
							c.Wake()
						}()
						break
					}
					client.poolConnection.nodeName = client.poolConnection.cp.Name

					msgFirstBytes := strings.ToUpper(string(clientMessage[5:10]))
					if msgFirstBytes == "BEGIN" {
						client.poolConnection.transactionBlock = true
					}

					/* Update the query count for the node being used. */
					// s.p.lock.Lock()
					//s.p.Stats[client.poolConnection.nodeName] += 1
					// s.p.lock.Unlock()

				} else if messageType == protocol.QueryMessageType {
					msgFirstBytes := strings.ToUpper(string(clientMessage[5:10]))
					if msgFirstBytes == "COMMI" || msgFirstBytes[:3] == "END" {
						client.poolConnection.transactionBlock = false
					}
				}

				/* Relay message from client to backend */
				if _, err := connect.Send(client.poolConnection.backend, clientMessage); err != nil {
					log.Errorf("Client: %s, error sending message to backend %s", remoteAddr, client.poolConnection.backend.RemoteAddr())
					log.Errorf("Error: %s", err.Error())
					client.ReleaseBackend()
					action = evio.Close
					break
				}
			}

			/*
			 * Try to read 4096 bytes
			 * 1   - MessageType
			 * 2-5 - MessageLength
			 */
			message, length, err := connect.Receive(client.poolConnection.backend, client.receivingBuffer, 10)
			for err == nil && length < 5 {
				log.Infof("Client: %s, trying to read up to 5 bytes on first read", remoteAddr)
				var restPiece []byte
				var newLength int
				restPiece, newLength, err = connect.Read(client.poolConnection.backend, 5-length)
				message = append(message, restPiece...)
				length += newLength
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				clientMessage = []byte{}
				log.Infof("Client: %s, timing out, already read %d", remoteAddr, length)
				// Wakeup the thread in 1000 millisecond to try again
				go func() {
					time.Sleep(50 * time.Millisecond)
					c.Wake()
				}()
				break
			} else if err != nil {
				log.Errorf("Client: %s, error receiving response from backend %s - LINE455", remoteAddr, client.poolConnection.backend.LocalAddr())
				log.Errorf("Length: %d, %s", length, err.Error())
				for err == nil {
					err = connect.Flush(client.poolConnection.backend)
				}
				client.ReleaseBackend()
				action = evio.Close
				break
			}

			/*
			 * Handle the message by first getting the Message Type
			 */
			var messageType byte
			var messageLength int32
			var start int

			for start = int(client.poolConnection.messageMissingBytes); start < length; {
				messageType = protocol.GetMessageType(message[start:])
				if (length - start) < 5 {
					log.Infof("Client: %s, trying to read up to 5 bytes", remoteAddr)
					piecedMessage, newLength, err := connect.Read(client.poolConnection.backend, 6-(length-start))
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						log.Infof("Client: %s, timing out, still read %d", remoteAddr, newLength)
						continue
					} else if err != nil {
						log.Errorf("Client: %s, error receiving response from backend %s - LINE473", remoteAddr, client.poolConnection.backend.RemoteAddr())
						log.Errorf("Length: %d, %s", length, err.Error())
						client.ReleaseBackend()
						action = evio.Close
						break
					}
					message = append(message[:length], piecedMessage[:newLength]...)
					length += newLength
					log.Infof("Client: %s, read %d and summed to %d, start %d, tried to read 5-%d", remoteAddr, newLength, length, start, (length - start))
				}
				messageLength, err = protocol.GetMessageLength(message[start:])
				if err != nil {
					log.Errorf("Client: %s, error unable to get message length from backend %s", remoteAddr, client.poolConnection.backend.RemoteAddr())
					client.ReleaseBackend()
					action = evio.Close
					break
				}

				if !protocol.ValidBackendMessage(messageType) {
					log.Errorf("Client: %s, not a valid backend message type, lost synchronization with server: got message type \"%c\", messageLength %d, start %d, length %d",
						remoteAddr, messageType, messageLength, start, length)
					client.ReleaseBackend()
					action = evio.Close
					return
				} else if messageLength > 30000 && protocol.ValidLongMessage(messageType) {
					client.phase = READINGLONGMESSAGE
				}

				/*
				 * Calculate the next start position, add '1' to the message
				 * length to account for the message type.
				 */
				client.poolConnection.messageMissingBytes = (messageLength - int32(length-start)) + 1
				log.Debugf("Client: %s, MSG type=%c length=%d start=%d readLength=%d missingBytes=%d", remoteAddr, messageType, messageLength, start, length, client.poolConnection.messageMissingBytes)
				start = (start + int(messageLength) + 1)
			}
			if client.poolConnection.messageMissingBytes < 0 {
				client.poolConnection.messageMissingBytes = 0
			} else {
				log.Infof("Client: %s, Leaving %d bytes to read afterwards, start: %d, length: %d, messageLength: %d", remoteAddr, client.poolConnection.messageMissingBytes, start, length, messageLength)
			}

			out = message[:length]

			client.poolConnection.done = (messageType == protocol.ReadyForQueryMessageType)
			if client.poolConnection.done {
				stayHere = true
				client.phase = RELEASEBACKEND
			} else {
				go c.Wake()
			}
			clientMessage = []byte{}

		case READINGLONGMESSAGE:
			stayHere = false
			log.Infof("Client: %s, reading long messaging from %s, remaining bytes %d", remoteAddr, client.poolConnection.backend.RemoteAddr(), client.poolConnection.messageMissingBytes)

			message, length, err := connect.Receive(client.poolConnection.backend, client.receivingBuffer, 10)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				clientMessage = []byte{}
				log.Infof("Client: %s, timing out, still read %d", remoteAddr, length)
				break
			} else if err != nil {
				log.Errorf("Client: %s, error receiving response from backend %s - READINGLONGMESSAGE", remoteAddr, client.poolConnection.backend.RemoteAddr())
				log.Errorf("Error: %s", err.Error())
				client.ReleaseBackend()
				action = evio.Close
				break
			}

			out = message[:length]
			client.poolConnection.messageMissingBytes -= int32(length)

			if client.poolConnection.messageMissingBytes == 0 {
				client.phase = AUTHENTICATED
			}
			go c.Wake()

		case RELEASEBACKEND:
			stayHere = false
			client.phase = AUTHENTICATED
			client.ReleaseBackend()
		}
	}
	client.inputStream.End(clientMessage)

	log.Debugf("Client: %s, leaving something", remoteAddr)
	return
}

func (s *Proxy) Serving(srv evio.Server) (action evio.Action) {
	log.Infof("Proxy server started on %s (loops: %d)", srv.Addrs[0].String(), srv.NumLoops)

	return
}

func (s *Proxy) Opened(c evio.Conn) (out []byte, opts evio.Options, action evio.Action) {
	log.Infof("opened: %v", c.RemoteAddr())
	c.SetContext(&Client{
		phase: INIT,
		addr:  c.RemoteAddr().String(),
	})

	opts.TCPKeepAlive = 20 * time.Second

	return
}

func (s *Proxy) Closed(c evio.Conn, err error) (action evio.Action) {
	log.Infof("closed: %v", c.RemoteAddr())
	return
}

func (s *Proxy) Serve(listenUrl string) error {
	err := evio.Serve(s.events, fmt.Sprintf("tcp-net://%s", listenUrl))
	return err
}

func (s *Proxy) Stop() (err error) {
	return err
}

func (s *Proxy) Stats() map[string]int32 {
	return s.stats
}
