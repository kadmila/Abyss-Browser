package infchan

type InfiniteChan[v any] struct {
	In  chan<- v
	Out <-chan v

	buf []v

	in  chan v
	out chan v
}

func NewInfiniteChan[v any](backlog int) *InfiniteChan[v] {
	in := make(chan v, backlog)
	out := make(chan v, backlog)
	result := &InfiniteChan[v]{
		In:  in,
		Out: out,

		buf: make([]v, 0, backlog),

		in:  in,
		out: out,
	}
	go func() {
	MAIN_LOOP:
		for {
			if len(result.buf) > 0 {
				select {
				case item, ok := <-result.in:
					if !ok {
						break MAIN_LOOP
					}
					result.buf = append(result.buf, item)
				case result.out <- result.buf[0]:
					result.buf = result.buf[1:]
				}
			} else {
				item, ok := <-result.in
				if !ok {
					break MAIN_LOOP
				}
				result.buf = append(result.buf, item)
			}
		}
		for _, item := range result.buf {
			result.out <- item
		}
		close(result.out)
	}()
	return result
}
