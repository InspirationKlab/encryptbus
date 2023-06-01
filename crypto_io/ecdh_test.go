package crypto_io

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

type MergedRW struct {
	io.Reader
	io.Writer
}

func TestPerformECDH(t *testing.T) {

	aKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("unix", "t.sock")
	defer ln.Close()
	if err != nil {
		t.Error(err)
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()

		conn, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		aReader, aWriter, err := PerformECDH(conn, aKey)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = aWriter.Write([]byte("Message from A"))
		if err != nil {
			t.Error(err)
			return
		}
		goal := "Message from B"
		rdBuf := make([]byte, len(goal))
		_, err = io.ReadFull(&aReader, rdBuf)
		if err != nil {
			t.Error(err)
			return
		}
		t.Logf("A wanted to receive \"%s\", received \"%s\" (%v)\n", goal, rdBuf, bytes.Equal([]byte(goal), rdBuf))

	}()
	go func() {
		defer wg.Done()
		conn, err := net.Dial("unix", "t.sock")
		if err != nil {
			t.Error(err)
			return
		}
		bReader, bWriter, err := PerformECDH(conn, bKey)
		if err != nil {
			t.Error(err)
			return
		}
		goal := "Message from A"
		rdBuf := make([]byte, len(goal))
		_, err = io.ReadFull(&bReader, rdBuf)
		if err != nil {
			t.Error(err)
			return
		}
		t.Logf("B wanted to receive \"%s\", received \"%s\" (%v)\n", goal, rdBuf, bytes.Equal([]byte(goal), rdBuf))
		_, err = bWriter.Write([]byte("Message from B"))
		if err != nil {
			t.Error(err)
			return
		}
	}()
	wg.Wait()
}
