package crypto_io

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
)

type Reader struct {
	r     io.Reader
	block cipher.Block
	buf   []byte
}

func (r *Reader) requestNewFrame() (n int, err error) {
	var preamble = make([]byte, 4+aes.BlockSize)
	n, err = io.ReadFull(r.r, preamble[:])
	if err != nil {
		return
	}
	length := int(binary.LittleEndian.Uint32(preamble[:4]))
	iv := preamble[4:]
	decryptor := cipher.NewCBCDecrypter(r.block, iv)
	paddedLength := ((length + r.block.BlockSize() - 1) / r.block.BlockSize()) * r.block.BlockSize()
	rdBuf := make([]byte, paddedLength)
	resultBuf := make([]byte, paddedLength)
	n, err = io.ReadFull(r.r, rdBuf)
	if err != nil {
		return n, err
	}
	decryptor.CryptBlocks(resultBuf, rdBuf)
	r.buf = resultBuf[:length]
	return
}

func (r *Reader) readInstant(p []byte) (n int, err error) {
	c := copy(p, r.buf)
	r.buf = r.buf[c:]
	return c, nil
}

func (r *Reader) Read(p []byte) (n int, err error) {
	if len(r.buf) != 0 {
		return r.readInstant(p)
	}
	n, err = r.requestNewFrame()
	if err != nil {
		return 0, err
	}
	return r.readInstant(p)
}
