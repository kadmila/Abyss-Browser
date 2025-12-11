package waiter

import (
	"context"
	"sync/atomic"
)

type Waiter[T any] struct {
	inner    chan T
	wait_cnt atomic.Int32 // this is set to -1 after close.
}

type WaiterError struct{}

func (e *WaiterError) Error() string {
	return "waiter unavailable"
}

func NewWaiter[T any]() *Waiter[T] {
	return &Waiter[T]{
		inner: make(chan T, 1),
	}
}

func (w *Waiter[T]) tryIncrementWaitCnt() bool {
	for {
		v := w.wait_cnt.Load()

		// conditional increment
		if v < 0 {
			return false
		}
		if !w.wait_cnt.CompareAndSwap(v, v+1) {
			continue
		}

		return true
	}
}

// Wait can be called multiple times concurrently.
// The error value can be either context errors, or *WaiterError.
func (w *Waiter[T]) Wait(ctx context.Context) (T, error) {
	var result T
	if !w.tryIncrementWaitCnt() {
		return result, &WaiterError{}
	}
	defer func() {
		w.wait_cnt.Add(-1)
	}()

	select {
	case v := <-w.inner:
		// recycle value for next waiter.
		w.inner <- v
		return v, nil
	case <-ctx.Done():
		return result, ctx.Err()
	}
}

// Set should not be called twice.
func (w *Waiter[T]) Set(v T) {
	w.inner <- v
}

// TryClose tries to close the waiter.
// If no Wait() calls are pending, it succeedes.
// It returns (the number of pending Wait() calls, did_close)
func (w *Waiter[T]) TryClose() (int32, bool) {
	for {
		v := w.wait_cnt.Load()

		// conditional decrement
		if v > 0 {
			return v, false
		}
		if !w.wait_cnt.CompareAndSwap(v, -1) {
			continue
		}

		return 0, true
	}
}

// TODO: forced close.
