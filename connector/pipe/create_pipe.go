package pipe

import (
	"context"
	"github.com/inspirationklab/encryptbus/event"
	"io"
	"log"
)

func RunManagedPipe(ctx context.Context, r io.Reader, w io.Writer) (chan<- event.OutgoingEvent, <-chan event.IncomingEvent, chan<- uint64) {
	inC := make(chan event.IncomingEvent, 100)
	outC := make(chan event.OutgoingEvent, 1)
	confirmC := make(chan uint64, 100)
	go func() {
		defer close(confirmC)
		err := runSequentialSend(ctx, w, confirmC, outC)
		if err != nil {
			log.Printf("Error sequential send :%v\n", err)
		}
	}()
	go func() {
		defer close(inC)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				err := event.Receive(r, inC, confirmC)
				if err != nil {
					log.Printf("Error receiving: %v\n", err)
				}
			}
		}

	}()
	return outC, inC, confirmC
}
