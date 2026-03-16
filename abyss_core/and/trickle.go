package and

import (
	"context"
	"math/rand/v2"
	"time"
)

const INTERVAL_MIN_MS = 300 * 4
const INTERVAL_MAX_MS = 300 * 4 * 65536 // practically meaningless.

type TrickleEntry struct {
	ctx         context.Context
	ctx_cancel  context.CancelFunc
	callback    func()
	interval_ms int64
	done        chan bool
}

func NewTrickleEntry(ctx context.Context, callback func()) *TrickleEntry {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &TrickleEntry{
		ctx:         inner_ctx,
		ctx_cancel:  cancel,
		callback:    callback,
		interval_ms: INTERVAL_MIN_MS,
		done:        make(chan bool, 1),
	}
	go func() {
		t_ms := int64((0.5 + 0.5*rand.Float64()) * float64(result.interval_ms))
	MAIN_LOOP:
		for {
			select {
			case <-result.ctx.Done():
				break MAIN_LOOP
			case <-time.After(time.Millisecond * time.Duration(t_ms)):
				result.callback()
				select {
				case <-result.ctx.Done():
					break MAIN_LOOP
				case <-time.After(time.Millisecond * time.Duration(result.interval_ms-t_ms)):
					if result.interval_ms < INTERVAL_MAX_MS {
						result.interval_ms *= 2
					}
					t_ms = int64((0.5 + 0.5*rand.Float64()) * float64(result.interval_ms))
				}
			}
		}
		result.done <- true
	}()
	return result
}

type TrickleWorker struct {
	ctx context.Context

	workers map[ANDIdentity]*TrickleEntry

	done chan bool
}

func NewTrickleWorker(ctx context.Context) *TrickleWorker {
	return &TrickleWorker{
		ctx: ctx,

		workers: make(map[ANDIdentity]*TrickleEntry),

		done: make(chan bool, 1),
	}
}

func (w *TrickleWorker) Add(identity ANDIdentity, callback func()) {
	w.workers[identity] = NewTrickleEntry(w.ctx, callback)
}
func (w *TrickleWorker) Remove(identity ANDIdentity) {
	entry, ok := w.workers[identity]
	if !ok {
		return
	}

	delete(w.workers, identity)
	entry.ctx_cancel()
	<-entry.done
}
