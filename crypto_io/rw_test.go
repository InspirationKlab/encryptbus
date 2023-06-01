package crypto_io

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"testing"
)

func TestReadWrite(t *testing.T) {
	var key [32]byte

	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}

	buff := bytes.Buffer{}

	writer := Writer{
		block: block,
		w:     &buff,
	}
	msg := []byte("ABCDEFGH")
	_, err = writer.Write(msg)
	if err != nil {
		t.Fatal(err)
	}

	reader := Reader{
		r:     &buff,
		block: block,
		buf:   nil,
	}
	result, err := io.ReadAll(&reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wanted %s, received %s\n", msg, result)

}
