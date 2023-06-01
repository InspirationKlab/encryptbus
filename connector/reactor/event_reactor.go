package reactor

import (
	"context"
	"github.com/inspirationklab/encryptbus/connector/pipe"
	"github.com/inspirationklab/encryptbus/event"
	"io"
	"log"
)

type EventBusContext struct {
	event.IncomingEvent
	sendC chan<- event.OutgoingEvent
}

func (c *EventBusContext) Send(e event.OutgoingEvent) {
	c.sendC <- e
}

type EventReactor struct {
	routing map[string]func(ctx *EventBusContext) error
}

func (e *EventReactor) On(name string, f func(cxt *EventBusContext) error) {
	if e.routing == nil {
		e.routing = map[string]func(ctx *EventBusContext) error{}
	}
	e.routing[name] = f
}

func (e *EventReactor) ServeManagedPipe(
	ctx context.Context,
	r io.Reader,
	w io.Writer,
	logger *log.Logger,
) chan<- event.OutgoingEvent {
	outC, inC, confirmReceive := pipe.RunManagedPipe(ctx, r, w)

	go func() {
		defer close(outC)
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-inC:
				if !ok {
					return
				}
				processor, hasProcessor := e.routing[evt.Name]
				if !hasProcessor {
					continue
				}
				evctx := &EventBusContext{
					IncomingEvent: evt,
					sendC:         outC,
				}
				go func() {
					err := processor(evctx)
					if err != nil {
						logger.Printf("Error processing event [%s]: %v", evt.Name, err)
						return
					}
					confirmReceive <- evctx.SendToken
				}()
				break
			}
		}
	}()
	return outC
}
