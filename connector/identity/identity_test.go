package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestSignedId_Verify(t *testing.T) {
	ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// transferred somehow to server (authenticated)
	ecdsaPublic := ecdsaPrivate.PublicKey
	id := SimpleIdentity{Name: "ABCDE001"}
	signed, err := id.SignAndPack(ecdsaPrivate)
	if err != nil {
		t.Fatal(err)
	}
	buff := bytes.NewReader(signed)

	var signedId SignedId
	err = ReadSignedIdentityPack(buff, &signedId)
	if err != nil {
		t.Fatal(err)
	}
	err = signedId.Verify(&ecdsaPublic)
	if err != nil {
		t.Fatal(err)
	}
}
