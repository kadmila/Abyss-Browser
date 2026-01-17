package ds_test

import (
	"testing"

	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
)

func TestQueue(t *testing.T) {
	q := ds.MakeQueue()
	q2 := q
	q2.Push(3)

	v, ok := q.Pop()
	if !ok || v != 3 {
		t.Fatal("queue failed")
	}
}
