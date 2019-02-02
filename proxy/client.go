package proxy

import (
	"github.com/crunchydata/crunchy-proxy/connect"
	"github.com/crunchydata/crunchy-proxy/util/log"
	"net"

	"github.com/tidwall/evio"

	"github.com/crunchydata/crunchy-proxy/pool"
)

/*
 * Represents a client
 */
type Client struct {
	inputStream      evio.InputStream
	addr             string
	phase            connectionPhase
	masterConnection net.Conn
	poolConnection   *poolConnection
}

/*
 * Pool connection information used by a client
 * Process the client messages for the life of the query/Transaction.
 */
type poolConnection struct {
	messageMissingBytes int32
	transactionBlock    bool
	cp                  *pool.Pool // The connection pool in use
	backend             net.Conn   // The backend connection in use
	read                bool
	nodeName            string
	done                bool // for message processing loop.
}

func (client *Client) ReleaseBackend() {
	/*
	 * If at the end of a statement block or not part of statment block,
	 * then return the connection to the pool.
	 */
	if !client.poolConnection.transactionBlock {
		var err error

		/* Flushing the remaning data in the connection */
		for err == nil {
			err = connect.Flush(client.poolConnection.backend)
		}

		/* Return the backend to the pool it belongs to. */
		log.Infof("Client: Releasing pool to client %s", client.addr)
		client.poolConnection.cp.Return(client.poolConnection.backend)
		client.poolConnection = nil
	}
}
