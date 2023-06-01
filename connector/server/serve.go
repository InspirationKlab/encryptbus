package server

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/inspirationklab/encryptbus/connector/identity"
	"github.com/inspirationklab/encryptbus/connector/reactor"
	"github.com/inspirationklab/encryptbus/crypto_io"
	"log"
	"net"
	"os"
)

type EventDispatcher struct {
	filter    func(conn net.Conn) bool
	validator func(identity identity.SignedId) bool
	reactor.EventReactor
	logger *log.Logger
}

func (e *EventDispatcher) Validate(validator func(identity identity.SignedId) bool) {
	e.validator = validator
}

func (e *EventDispatcher) Filter(filterFn func(conn net.Conn) bool) {
	e.filter = filterFn
}

func (e *EventDispatcher) Listen(addr string, ctx context.Context) error {
	l, err := net.Listen("tcp", addr)
	e.logger = log.New(os.Stdout, "[Event Bus Server] ", log.LstdFlags)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		select {
		case <-ctx.Done():
			return err
		default:
			conn, err := l.Accept()
			if err != nil {
				e.logger.Printf("Error accepting: %v\n", err)
				continue
			}
			go func() {
				err := e.serveConn(conn, ctx)
				if err != nil {
					e.logger.Printf("Error serving: %v\n", err)
				}
			}()
		}
	}
}

func (e *EventDispatcher) serveConn(n net.Conn, ctx context.Context) error {
	if e.filter != nil && !e.filter(n) {
		return fmt.Errorf("filter for %v not passed", n.RemoteAddr())
	}

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	reader, writer, err := crypto_io.PerformECDH(n, key)

	if err != nil {
		return err
	}

	var signedId identity.SignedId
	err = identity.ReadSignedIdentityPack(&reader, &signedId)
	if err != nil {
		return err
	}

	if e.validator != nil {
		isValid := e.validator(signedId)
		if !isValid {
			return errors.New("invalid identity")
		}
	}

	e.ServeManagedPipe(ctx, &reader, &writer, e.logger)

	return nil
}
