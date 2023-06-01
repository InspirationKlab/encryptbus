package client

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"github.com/inspirationklab/encryptbus/connector/reactor"
	"github.com/inspirationklab/encryptbus/crypto_io"
	"github.com/inspirationklab/encryptbus/event"
	"log"
	"net"
	"os"
)

type Client struct {
	reactor.EventReactor
	logger *log.Logger
	Id     []byte
}

func (c *Client) Connect(addr string, ctx context.Context) (chan<- event.OutgoingEvent, error) {
	conn, err := net.Dial("tcp", addr)
	c.logger = log.New(os.Stdout, "[Client Event Bus] ", log.LstdFlags)
	if err != nil {
		return nil, err
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	reader, writer, err := crypto_io.PerformECDH(conn, key)
	if err != nil {
		return nil, err
	}
	_, err = writer.Write(c.Id)
	if err != nil {
		return nil, err
	}
	outC := c.ServeManagedPipe(ctx, &reader, &writer, c.logger)
	return outC, nil
}
