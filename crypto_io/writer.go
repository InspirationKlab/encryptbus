package crypto_io

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
)

type Writer struct {
	block cipher.Block
	w     io.Writer
}

func padAndCopy(p []byte) []byte {
	cp := make([]byte, ((len(p)+aes.BlockSize-1)/aes.BlockSize)*aes.BlockSize)
	copy(cp, p)
	return cp
}

func (w *Writer) Write(p []byte) (n int, err error) {
	padded := padAndCopy(p)
	var iv [aes.BlockSize]byte
	_, _ = rand.Read(iv[:])
	cbc := cipher.NewCBCEncrypter(w.block, iv[:])
	cipherText := make([]byte, len(padded))
	cbc.CryptBlocks(cipherText, padded)
	result := make([]byte, 4+aes.BlockSize+len(padded))
	binary.LittleEndian.PutUint32(result, uint32(len(p)))
	copy(result[4:], iv[:])
	copy(result[4+aes.BlockSize:], cipherText)
	return w.w.Write(result)
}
