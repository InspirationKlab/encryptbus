package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/sha3"
	"io"
)

type SimpleIdentity struct {
	Name string `json:"name"`
}

func (s SimpleIdentity) SignAndPack(key *ecdsa.PrivateKey) ([]byte, error) {
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return SignIdentityPacked(key, bytes)
}

type SerializedIdentity []byte

func WriteByteArray(w io.Writer, p []byte) error {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(p)))
	_, err := w.Write(lenBuf[:])
	if err != nil {
		return err
	}
	_, err = w.Write(p)
	return err
}

func ReadByteArray(r io.Reader, out *[]byte) error {
	var lenBuf [4]byte
	_, err := io.ReadFull(r, lenBuf[:])
	if err != nil {
		return err
	}
	length := binary.LittleEndian.Uint32(lenBuf[:])
	*out = make([]byte, length)
	_, err = io.ReadFull(r, *out)
	return err
}

func SignIdentityPacked(key *ecdsa.PrivateKey, id SerializedIdentity) ([]byte, error) {
	hash := sha3.Sum512(id)
	digest, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return nil, err
	}
	var resultWriter bytes.Buffer
	_ = WriteByteArray(&resultWriter, id)
	_ = WriteByteArray(&resultWriter, digest)
	return resultWriter.Bytes(), nil
}

type SignedId struct {
	Id        SerializedIdentity
	Signature []byte
}

func (s SignedId) ExtractJSON(v any) error {
	return json.Unmarshal(s.Signature, v)
}

// Verify returns error that represents non-integrate data. Nil if signature is correct
func (s SignedId) Verify(key *ecdsa.PublicKey) error {
	hash := sha3.Sum512(s.Id)
	isValid := ecdsa.VerifyASN1(key, hash[:], s.Signature)
	if isValid {
		return nil
	}
	return errors.New("incorrect signature")
}

func ReadSignedIdentityPack(r io.Reader, out *SignedId) error {
	err := ReadByteArray(r, (*[]byte)(&out.Id))
	if err != nil {
		return err
	}
	return ReadByteArray(r, &out.Signature)
}
