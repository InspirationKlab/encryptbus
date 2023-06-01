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
	"github.com/inspirationklab/encryptbus/event"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type EventDispatcher struct {
	reactor.EventReactor

	filter    func(conn net.Conn) bool
	validator func(identity identity.SignedId) bool

	sendQueue map[string][]event.OutgoingEvent
	sendLock  sync.Mutex

	logger *log.Logger
}

func (e *EventDispatcher) dequeue(target string) (event.OutgoingEvent, bool) {
	e.sendLock.Lock()
	defer e.sendLock.Unlock()
	slice := e.sendQueue[target]
	if len(slice) == 0 {
		return event.OutgoingEvent{}, false
	}
	e.sendQueue[target] = e.sendQueue[target][1:]
	return slice[0], true
}

func (e *EventDispatcher) Enqueue(target string, ev event.OutgoingEvent) {
	e.sendLock.Lock()
	defer e.sendLock.Unlock()

	if e.sendQueue == nil {
		e.sendQueue = map[string][]event.OutgoingEvent{}
	}

	e.sendQueue[target] = append(e.sendQueue[target], ev)
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

	outC := e.ServeManagedPipe(ctx, &reader, &writer, e.logger)
	go func() {
		dequeueT := time.NewTicker(time.Millisecond * 50)
		defer dequeueT.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-dequeueT.C:
				outgoingEvent, hasEvent := e.dequeue(string(signedId.Id))
				if !hasEvent {
					continue
				}
				outC <- outgoingEvent
				break
			}
		}
	}()
	return nil
}
