package ann

import (
	"math/rand/v2"
	"net"
	"time"
)

type ReadResult struct {
	data []byte
	addr net.Addr
	err  error
	time time.Time
}

// DelayConn is a net.PacketConn wrapper around *net.UDPConn that simulates
// network delay and unordered packet arrival.
type DelayConn struct {
	// The underlying connection
	net.PacketConn

	raw_read_ch chan *ReadResult
	delayed_ch  chan *ReadResult

	// Configuration for simulation
	delay  time.Duration // Base delay for all packets
	jitter time.Duration // Amount of jitter
}

func NewDelayConn(original *net.UDPConn, delay time.Duration, jitter time.Duration) *DelayConn {
	result := &DelayConn{
		PacketConn: original,

		raw_read_ch: make(chan *ReadResult, 32),
		delayed_ch:  make(chan *ReadResult, 32),

		delay:  delay,
		jitter: jitter,
	}
	go result.readRaw()
	go result.convey()
	return result
}

func (c *DelayConn) readRaw() {
	for {
		buf := make([]byte, 65536)
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			close(c.raw_read_ch)
			return
		}
		c.raw_read_ch <- &ReadResult{
			data: buf[:n],
			addr: addr,
			err:  err,
			time: time.Now(),
		}
	}
}
func (c *DelayConn) convey() {
	for {
		read_res, ok := <-c.raw_read_ch
		if !ok {
			close(c.delayed_ch)
			return
		}
		// delay
		time.Sleep(time.Until(read_res.time.Add(c.delay + c.jitter*time.Duration(rand.Float32()))))
		c.delayed_ch <- read_res
	}
}

func (c *DelayConn) ReadFrom(p []byte) (int, net.Addr, error) {
	res, ok := <-c.delayed_ch
	if !ok {
		return 0, nil, &net.OpError{
			Op:     "read",
			Net:    "udp",
			Source: nil,
			Err:    net.ErrClosed,
		}
	}
	n := copy(p, res.data)
	return n, res.addr, res.err
}
