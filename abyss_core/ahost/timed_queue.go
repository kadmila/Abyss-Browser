package ahost

import (
	"container/heap"
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

type worldTimerEndpoint struct {
	world_id uuid.UUID
	end      time.Time
}

// worldTimerQueue is a priority queue of worldTimerEndpoint entries.
// Entries with the oldest (earliest) time.Time have highest priority (pop first).
type worldTimerQueue struct {
	entries []worldTimerEndpoint
	updated chan bool
	mtx     sync.Mutex
}

func newWorldTimerQueue() *worldTimerQueue {
	q := &worldTimerQueue{
		entries: make([]worldTimerEndpoint, 0),
		updated: make(chan bool, 1),
	}
	heap.Init(q)
	return q
}

// Add adds an entry to the queue
func (q *worldTimerQueue) Add(world_id uuid.UUID, duration time.Duration) {
	q.mtx.Lock()
	defer q.mtx.Unlock()

	heap.Push(q, worldTimerEndpoint{
		world_id: world_id,
		end:      time.Now().Add(duration),
	})
	select {
	case q.updated <- true:
	default:
	}
}

// Wait waits for the nearest entry.
func (q *worldTimerQueue) Wait(ctx context.Context) (uuid.UUID, error) {
	for {
		q.mtx.Lock()
		if q.Len() == 0 {
			q.mtx.Unlock()
			select {
			case <-ctx.Done():
				return uuid.Nil, ctx.Err()
			case <-q.updated:
			}
			continue
		}

		nearest := q.entries[0]
		if time.Now().After(nearest.end) {
			heap.Pop(q)
			q.mtx.Unlock()

			return nearest.world_id, nil
		}
		q.mtx.Unlock()

		select {
		case <-ctx.Done():
			return uuid.Nil, ctx.Err()
		case <-q.updated:
		case <-time.After(time.Until(nearest.end)):
		}
	}
}

/// heap.Interface
// This should never be called directly.

func (q *worldTimerQueue) Len() int {
	return len(q.entries)
}
func (q *worldTimerQueue) Less(i, j int) bool {
	return q.entries[i].end.Before(q.entries[j].end)
}
func (q *worldTimerQueue) Swap(i, j int) {
	q.entries[i], q.entries[j] = q.entries[j], q.entries[i]
}
func (q *worldTimerQueue) Push(x any) {
	q.entries = append(q.entries, x.(worldTimerEndpoint))
}
func (q *worldTimerQueue) Pop() any {
	old := q.entries
	n := len(old)
	entry := old[n-1]
	q.entries = old[0 : n-1]
	return entry
}

/// heap.Interface done
