package server

import (
	"context"
	"encoding/json"
	"google.golang.org/grpc"
	"net"
	"time"

	"github.com/akutz/memconn"

	pb "github.com/crunchydata/crunchy-proxy/server/serverpb"

	"gopkg.in/check.v1"
)

func (s *S) TestStatistics(c *check.C) {
	dialOptions := []grpc.DialOption{
		grpc.WithDialer(adminServerDialer),
		grpc.WithInsecure(),
	}

	conn, err := grpc.Dial(address, dialOptions...)

	c.Check(err, check.IsNil)

	defer conn.Close()

	cGrpc := pb.NewAdminClient(conn)

	response, err := cGrpc.Statistics(context.Background(), &pb.StatisticsRequest{})

	c.Check(err, check.IsNil)

	queries := response.GetQueries()

	_, err = json.Marshal(queries)
	c.Check(err, check.IsNil)

}

func (s *S) TestVersion(c *check.C) {
	dialOptions := []grpc.DialOption{
		grpc.WithDialer(adminServerDialer),
		grpc.WithInsecure(),
	}

	conn, err := grpc.Dial(address, dialOptions...)

	c.Check(err, check.IsNil)

	defer conn.Close()

	cGrpc := pb.NewAdminClient(conn)

	response, err := cGrpc.Version(context.Background(), &pb.VersionRequest{})

	c.Check(err, check.IsNil)

	c.Check(response.Version, check.Equals, "1.0.0beta")

}

func (s *S) TestNode(c *check.C) {
	dialOptions := []grpc.DialOption{
		grpc.WithDialer(adminServerDialer),
		grpc.WithInsecure(),
	}

	conn, err := grpc.Dial(address, dialOptions...)

	c.Check(err, check.IsNil)

	defer conn.Close()

	cGrpc := pb.NewAdminClient(conn)

	response, err := cGrpc.Nodes(context.Background(), &pb.NodeRequest{})

	c.Check(err, check.IsNil)

	queries := response.GetNodes()

	jsonResponse, err := json.Marshal(queries)
	c.Check(err, check.IsNil)
	c.Check(jsonResponse, check.NotNil)

}

func (s *S) TestHealth(c *check.C) {
	dialOptions := []grpc.DialOption{
		grpc.WithDialer(adminServerDialer),
		grpc.WithInsecure(),
	}

	conn, err := grpc.Dial(address, dialOptions...)

	c.Check(err, check.IsNil)

	defer conn.Close()

	cGrpc := pb.NewAdminClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	response, err := cGrpc.Health(ctx, &pb.HealthRequest{})

	c.Check(err, check.IsNil)

	queries := response.GetHealth()

	_, err = json.Marshal(queries)
	c.Check(err, check.IsNil)

}

func adminServerDialer(address string, timeout time.Duration) (net.Conn, error) {
	return memconn.Dial("memu", address)
}
