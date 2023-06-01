package crypto_io

import (
	"crypto/aes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/binary"
	"io"
)

func PerformECDH(rw io.ReadWriter, key *ecdh.PrivateKey) (Reader, Writer, error) {

	pkix, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return Reader{}, Writer{}, err
	}
	var keyLengthBuf [4]byte

	binary.LittleEndian.PutUint32(keyLengthBuf[:], uint32(len(pkix)))
	_, err = rw.Write(append(keyLengthBuf[:], pkix...))
	if err != nil {
		return Reader{}, Writer{}, err
	}
	_, err = io.ReadFull(rw, keyLengthBuf[:])
	if err != nil {
		return Reader{}, Writer{}, err
	}
	l := binary.LittleEndian.Uint32(keyLengthBuf[:])
	buf := make([]byte, l)
	_, err = io.ReadFull(rw, buf)
	if err != nil {
		return Reader{}, Writer{}, err
	}
	remoteKey, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return Reader{}, Writer{}, err
	}
	secret, err := key.ECDH(remoteKey.(*ecdh.PublicKey))

	if err != nil {
		return Reader{}, Writer{}, err
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return Reader{}, Writer{}, err
	}
	return Reader{
			r:     rw,
			block: block,
			buf:   nil,
		}, Writer{
			block: block,
			w:     rw,
		}, nil
}
