package event

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"time"
)

type MessageKind byte

const (
	Event          MessageKind = iota
	ReceiveConfirm MessageKind = iota
)

type IncomingEvent struct {
	Name      string          `json:"name"`
	SendToken uint64          `json:"sendToken"`
	SentAt    time.Time       `json:"sentAt"`
	Content   json.RawMessage `json:"content"`
}

func (i IncomingEvent) ParseContent(v any) error {
	return json.Unmarshal(i.Content, v)
}

func readVariable(r io.Reader) ([]byte, error) {
	var lenBuf [8]byte
	_, err := io.ReadFull(r, lenBuf[:])
	if err != nil {
		return nil, err
	}
	result := make([]byte, binary.LittleEndian.Uint64(lenBuf[:]))
	_, err = io.ReadFull(r, result)
	return result, err
}

func writeVariable(w io.Writer, p []byte) error {
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(p)))
	_, err := w.Write(lenBuf[:])
	if err != nil {
		return err
	}
	_, err = w.Write(p)
	return err
}

func Receive(r io.Reader, evC chan<- IncomingEvent, recC chan<- uint64) error {
	var typeBuf [1]byte
	_, err := io.ReadFull(r, typeBuf[:])
	if err != nil {
		return err
	}

	switch MessageKind(typeBuf[0]) {
	case Event:
		raw, err := readVariable(r)
		if err != nil {
			return err
		}
		var e IncomingEvent
		err = json.Unmarshal(raw, &e)
		if err != nil {
			return err
		}
		evC <- e
		break
	case ReceiveConfirm:
		var contentBuf [8]byte
		_, err := io.ReadFull(r, contentBuf[:])
		if err != nil {
			return err
		}
		recC <- binary.LittleEndian.Uint64(contentBuf[:])
		break
	}

	return nil
}
