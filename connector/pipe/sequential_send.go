package pipe

import (
	"context"
	"github.com/inspirationklab/encryptbus/event"
	"io"
)

func runSequentialSend(
	ctx context.Context,
	writer io.Writer,
	confirmC <-chan uint64,
	eventC <-chan event.OutgoingEvent,
) error {
	var token uint64
	var err error
	for {
		select {
		case <-ctx.Done():
			return nil
		case tokenV := <-confirmC:
			if tokenV == token {

			}
			break
		case ev := <-eventC:

			token, err = event.Send(writer, ev)
			if err != nil {
				return err
			}

		}
	}
}
