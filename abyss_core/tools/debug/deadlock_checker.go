package debug

import (
	"fmt"
	"time"
)

// quick and dirty debug
type DeadlockChecker struct {
	done chan bool
}

func NewDeadlockChecker(tag string) *DeadlockChecker {
	result := &DeadlockChecker{
		done: make(chan bool, 1),
	}
	go func() {
		select {
		case <-result.done:
		case <-time.After(time.Second * 3):
			fmt.Println("DEADLOCK: " + tag)
		}
	}()
	return result
}

func (d *DeadlockChecker) Done() {
	d.done <- true
}
