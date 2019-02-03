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

package connect

import (
	"net"
	"time"

	"github.com/crunchydata/crunchy-proxy/config"
	"github.com/crunchydata/crunchy-proxy/protocol"
	"github.com/crunchydata/crunchy-proxy/util/log"
)

func Send(connection net.Conn, message []byte) (int, error) {
	err := connection.SetWriteDeadline(time.Now().Add(5000 * time.Millisecond))
	if err != nil {
		return 0, err
	}
	return connection.Write(message)
}

func Read(connection net.Conn, size int) ([]byte, int, error) {
	buffer := make([]byte, size)
	err := connection.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	if err != nil {
		return buffer, 0, err
	}
	length, err := connection.Read(buffer)
	return buffer, length, err
}

/*
 * We try to send at least 8K at a time, which is the usual size of pipe
 * buffers on Unix systems.  That way, when we are sending a large amount
 * of data, we avoid incurring extra kernel context swaps for partial
 * bufferloads.  The output buffer is initially made 16K in size, and we
 * try to dump it after accumulating 8K.
 *
 * With the same goal of minimizing context swaps, the input buffer will
 * be enlarged anytime it has less than 8K free, so we initially allocate
 * twice that.
 */
func Receive(connection net.Conn) ([]byte, int, error) {
	buffer := make([]byte, 8*1024)
	err := connection.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	if err != nil {
		return buffer, 0, err
	}
	length, err := connection.Read(buffer)
	return buffer, length, err
}

func Flush(connection net.Conn) error {
	var err error

	/* Flushing the remaning data in the connection */
	for err == nil {
		buffer := make([]byte, 8*1024)
		err = connection.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if err != nil {
			return err
		}
		_, err = connection.Read(buffer)
	}
	return err
}

func Connect(host string) (net.Conn, error) {
	connection, err := net.Dial("tcp", host)

	if err != nil {
		return nil, err
	}

	if config.GetBool("credentials.ssl.enable") {
		log.Info("SSL connections are enabled.")

		/*
		 * First determine if SSL is allowed by the backend. To do this, send an
		 * SSL request. The response from the backend will be a single byte
		 * message. If the value is 'S', then SSL connections are allowed and an
		 * upgrade to the connection should be attempted. If the value is 'N',
		 * then the backend does not support SSL connections.
		 */

		/* Create the SSL request message. */
		message := protocol.NewMessageBuffer([]byte{})
		_, err = message.WriteInt32(8)
		if err != nil {
			return nil, err
		}
		_, err = message.WriteInt32(protocol.SSLRequestCode)
		if err != nil {
			return nil, err
		}

		/* Send the SSL request message. */
		_, err := connection.Write(message.Bytes())

		if err != nil {
			log.Error("Error sending SSL request to backend.")
			log.Errorf("Error: %s", err.Error())
			return nil, err
		}

		/* Receive SSL response message. */
		response := make([]byte, 4096)
		_, err = connection.Read(response)

		if err != nil {
			log.Error("Error receiving SSL response from backend.")
			log.Errorf("Error: %s", err.Error())
			return nil, err
		}

		/*
		 * If SSL is not allowed by the backend then close the connection and
		 * throw an error.
		 */
		if len(response) > 0 && response[0] != 'S' {
			log.Error("The backend does not allow SSL connections.")
			connection.Close()
		} else {
			log.Debug("SSL connections are allowed by PostgreSQL.")
			log.Debug("Attempting to upgrade connection.")
			connection = UpgradeClientConnection(host, connection)
			log.Debug("Connection successfully upgraded.")
		}
	}

	return connection, nil
}
