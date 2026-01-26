package ahost

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWorldTimerQueuePushAndWait(t *testing.T) {
	q := newWorldTimerQueue()

	world1 := uuid.New()
	world2 := uuid.New()
	world3 := uuid.New()

	// Push worlds with different durations
	// world2 should expire first (100ms), then world3 (200ms), then world1 (300ms)
	q.Add(world1, time.Millisecond*300)
	q.Add(world2, time.Millisecond*100)
	q.Add(world3, time.Millisecond*200)

	ctx := context.Background()

	// Wait should return world2 first (shortest duration)
	start := time.Now()
	result1, err := q.Wait(ctx)
	elapsed1 := time.Since(start)
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	if result1 != world2 {
		t.Fatal("expected world2 to be returned first")
	}
	if elapsed1 < time.Millisecond*90 || elapsed1 > time.Millisecond*150 {
		t.Fatalf("expected wait time ~100ms, got %v", elapsed1)
	}

	// Wait should return world3 next
	start = time.Now()
	result2, err := q.Wait(ctx)
	elapsed2 := time.Since(start)
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	if result2 != world3 {
		t.Fatal("expected world3 to be returned second")
	}
	if elapsed2 < time.Millisecond*90 || elapsed2 > time.Millisecond*150 {
		t.Fatalf("expected wait time ~100ms, got %v", elapsed2)
	}

	// Wait should return world1 last
	start = time.Now()
	result3, err := q.Wait(ctx)
	elapsed3 := time.Since(start)
	if err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	if result3 != world1 {
		t.Fatal("expected world1 to be returned last")
	}
	if elapsed3 < time.Millisecond*90 || elapsed3 > time.Millisecond*150 {
		t.Fatalf("expected wait time ~100ms, got %v", elapsed3)
	}
}

func TestWorldTimerQueueWaitTimeout(t *testing.T) {
	q := newWorldTimerQueue()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()

	// Wait on empty queue should timeout
	start := time.Now()
	result, err := q.Wait(ctx)
	elapsed := time.Since(start)

	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	if result != uuid.Nil {
		t.Fatal("expected nil result on timeout")
	}
	if elapsed < time.Millisecond*90 || elapsed > time.Millisecond*150 {
		t.Fatalf("expected timeout ~100ms, got %v", elapsed)
	}
}

func TestWorldTimerQueueWaitCancellation(t *testing.T) {
	q := newWorldTimerQueue()
	world := uuid.New()

	// Push with long duration
	q.Add(world, time.Second*10)

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after 100ms
	go func() {
		time.Sleep(time.Millisecond * 100)
		cancel()
	}()

	start := time.Now()
	result, err := q.Wait(ctx)
	elapsed := time.Since(start)

	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if result != uuid.Nil {
		t.Fatal("expected nil result on cancellation")
	}
	if elapsed < time.Millisecond*90 || elapsed > time.Millisecond*200 {
		t.Fatalf("expected cancellation ~100ms, got %v", elapsed)
	}
}

func TestWorldTimerQueuePushWhileWaiting(t *testing.T) {
	q := newWorldTimerQueue()

	world1 := uuid.New()
	world2 := uuid.New()

	ctx := context.Background()

	// Start waiting on empty queue
	result_ch := make(chan uuid.UUID, 1)
	go func() {
		result, err := q.Wait(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		result_ch <- result
	}()

	// Give Wait time to start
	time.Sleep(time.Millisecond * 50)

	// Push world1 with short duration
	q.Add(world1, time.Millisecond*100)

	// Should receive world1
	select {
	case result := <-result_ch:
		if result != world1 {
			t.Fatal("expected world1")
		}
	case <-time.After(time.Millisecond * 200):
		t.Fatal("timeout waiting for result")
	}

	// Push world2 and verify it's also received
	go func() {
		result, err := q.Wait(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		result_ch <- result
	}()

	time.Sleep(time.Millisecond * 50)
	q.Add(world2, time.Millisecond*100)

	select {
	case result := <-result_ch:
		if result != world2 {
			t.Fatal("expected world2")
		}
	case <-time.After(time.Millisecond * 200):
		t.Fatal("timeout waiting for result")
	}
}

func TestWorldTimerQueueConcurrentPush(t *testing.T) {
	q := newWorldTimerQueue()

	num_worlds := 100
	worlds := make([]uuid.UUID, num_worlds)
	for i := 0; i < num_worlds; i++ {
		worlds[i] = uuid.New()
	}

	// Push concurrently
	done := make(chan bool, num_worlds)
	for i := 0; i < num_worlds; i++ {
		go func(idx int) {
			q.Add(worlds[idx], time.Millisecond*time.Duration(100+idx))
			done <- true
		}(i)
	}

	// Wait for all pushes
	for i := 0; i < num_worlds; i++ {
		<-done
	}

	// Verify all entries are in queue
	q.mtx.Lock()
	length := q.Len()
	q.mtx.Unlock()

	if length != num_worlds {
		t.Fatalf("expected %d entries, got %d", num_worlds, length)
	}
}

func TestWorldTimerQueuePushUpdatesWaiter(t *testing.T) {
	q := newWorldTimerQueue()

	world1 := uuid.New()
	world2 := uuid.New()

	ctx := context.Background()

	// Push world1 with long duration
	q.Add(world1, time.Second*5)

	// Start waiting
	result_ch := make(chan uuid.UUID, 1)
	error_ch := make(chan error, 1)
	go func() {
		result, err := q.Wait(ctx)
		if err != nil {
			error_ch <- err
			return
		}
		result_ch <- result
	}()

	// Give Wait time to start
	time.Sleep(time.Millisecond * 50)

	// Push world2 with shorter duration - should be returned first
	q.Add(world2, time.Millisecond*100)

	// Should receive world2 (not world1)
	start := time.Now()
	select {
	case result := <-result_ch:
		elapsed := time.Since(start)
		if result != world2 {
			t.Fatal("expected world2 to be returned (shorter duration)")
		}
		if elapsed > time.Millisecond*200 {
			t.Fatalf("expected quick response, got %v", elapsed)
		}
	case err := <-error_ch:
		t.Fatalf("unexpected error: %v", err)
	case <-time.After(time.Millisecond * 300):
		t.Fatal("timeout waiting for result")
	}
}
