package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/inspirationklab/encryptbus/connector/client"
	"github.com/inspirationklab/encryptbus/connector/identity"
	"github.com/inspirationklab/encryptbus/connector/reactor"
	"github.com/inspirationklab/encryptbus/connector/server"
	"github.com/inspirationklab/encryptbus/event"
	"log"
	rand2 "math/rand"
	"os"
	"os/signal"
	"sync"
	"testing"
	"time"
)

type identityData struct {
	Name string `json:"name"`
}

func runServer(t *testing.T, acceptingKey *ecdsa.PublicKey) {
	serv := &server.EventDispatcher{}

	serv.Validate(func(identity identity.SignedId) bool {
		err := identity.Verify(acceptingKey)
		if err != nil {
			log.Printf("Declined user %s\n", identity.Id)
			return false
		}

		log.Printf("Accepted user %s\n", identity.Id)

		return true
	})

	serv.On("value increment", func(cxt *reactor.EventBusContext) error {
		var value int64
		err := cxt.ParseContent(&value)
		if err != nil {
			return err
		}

		t.Logf("Received %v\n", value)

		time.Sleep(time.Second)

		cxt.Send(event.OutgoingEvent{
			Name:    "ev-from-server",
			Content: value + 1,
		})

		return nil
	})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	idBytes, _ := json.Marshal(identityData{Name: "some-client-correct"})

	serv.Enqueue(string(idBytes), event.OutgoingEvent{Name: "server-initialized", Content: 3})

	err := serv.Listen(":6775", ctx)
	log.Println(err)
}

func TestClientServer(t *testing.T) {
	ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// transferred somehow to server (authenticated)
	ecdsaPublic := ecdsaPrivate.PublicKey
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		runServer(t, &ecdsaPublic)
	}()

	rawId, _ := json.Marshal(identityData{Name: "some-client-correct"})

	id, err := identity.SignIdentityPacked(ecdsaPrivate, rawId)
	if err != nil {
		t.Fatal(err)
	}

	eventClient := client.Client{
		Id: id,
	}

	eventClient.On("ev-from-server", func(cxt *reactor.EventBusContext) error {
		var payload int64
		err := cxt.ParseContent(&payload)
		if err != nil {
			return err
		}
		log.Printf("Received event from server: %v\n", payload)
		return nil
	})

	eventClient.On("server-initialized", func(cxt *reactor.EventBusContext) error {
		var payload int64
		err := cxt.ParseContent(&payload)
		if err != nil {
			return err
		}
		log.Printf("Received event from server {initialized}: %v\n", payload)
		return nil
	})

	conn, err := eventClient.Connect(":6775", context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn <- event.OutgoingEvent{
			Name:    "value increment",
			Content: rand2.Int63(),
		}
		time.Sleep(time.Second)
		conn <- event.OutgoingEvent{
			Name:    "value increment",
			Content: rand2.Int63(),
		}
	}()
	wg.Wait()
}
