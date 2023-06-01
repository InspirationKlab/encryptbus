package event

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"time"
)

type OutgoingEvent struct {
	Name    string
	Content any
}

func Send(w io.Writer, evt OutgoingEvent) (uint64, error) {
	content, err := json.Marshal(evt.Content)
	if err != nil {
		return 0, err
	}

	var sendTokenBuf [8]byte
	rand.Read(sendTokenBuf[:])

	dto := IncomingEvent{
		Name:      evt.Name,
		SendToken: binary.LittleEndian.Uint64(sendTokenBuf[:]),
		SentAt:    time.Now(),
		Content:   content,
	}

	marshalled, err := json.Marshal(dto)
	if err != nil {
		return 0, err
	}
	_, err = w.Write([]byte{byte(Event)})
	if err != nil {
		return 0, err
	}
	return dto.SendToken, writeVariable(w, marshalled)
}
