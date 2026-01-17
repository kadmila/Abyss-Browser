package ds

import "container/list"

type Queue struct {
	inner *list.List
}

func MakeQueue() Queue {
	return Queue{
		inner: list.New(),
	}
}

func (q *Queue) Push(e any) {
	q.inner.PushBack(e)
}
func (q *Queue) Pop() (any, bool) {
	front := q.inner.Front()
	if front == nil {
		return nil, false
	}
	return q.inner.Remove(front), true
}
