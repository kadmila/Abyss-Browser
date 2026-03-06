package and

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

type ANDTimer struct {
	*time.Timer
	due time.Time
	N   int
}

func NewANDTimer() *ANDTimer {
	new_timer := time.NewTimer(-1)
	<-new_timer.C
	return &ANDTimer{
		Timer: new_timer,
		due:   time.Time{},
		N:     1,
	}
}

const (
	TimerMinInterval  = 100 * time.Millisecond
	TimerIntervalUnit = 150.0
)

func (t *ANDTimer) Increment() {
	t.N++
	now := time.Now()

	if t.due.After(now) {
		elongate_duration := t.due.Sub(now) * time.Duration(t.N) / time.Duration(t.N-1)
		if elongate_duration > TimerMinInterval {
			t.Reset(elongate_duration)
		}
		// worst case: double expiration - if the host is very very slow and badly timed. unlikely to happen.
	} else {
		new_duration := TimerMinInterval + time.Millisecond*time.Duration(rand.Float64()*TimerIntervalUnit*float64(t.N))
		t.Reset(new_duration)
		// worst case: timer expiration miss if a new timer is set before the previous expiration is handled.
		// This should be ignorable; just missing one SJN.
	}
}
func (t *ANDTimer) Decrement() {
	t.N--
	if t.N < 1 {
		panic("ANDTimer N cannot be smaller than 1")
	}
	now := time.Now()

	shortened_duration := t.due.Sub(now) * time.Duration(t.N) / time.Duration(t.N-1)
	if shortened_duration > TimerMinInterval {
		t.Reset(shortened_duration)
	}
}

type ANDIdentity struct {
	PeerID    string
	SessionID uuid.UUID
}

type ANDPeerSession struct {
	Peer      ani.IAbyssPeer
	SessionID uuid.UUID
}

func (s *ANDPeerSession) ANDIdentity() ANDIdentity {
	return ANDIdentity{
		PeerID:    s.Peer.ID(),
		SessionID: s.SessionID,
	}
}

///// AND entries

type ANDSessionState int

const (
	WS_NOTIRCVD ANDSessionState = iota
	WS_NOTISENT
	WS_MEM
)

func (s ANDSessionState) String() string {
	switch s {
	case WS_NOTIRCVD:
		return "WS_NOTIRCVD"
	case WS_NOTISENT:
		return "WS_NOTISENT"
	case WS_MEM:
		return "WS_MEM"
	default:
		return fmt.Sprintf("ANDSessionState(%d)", s)
	}
}

// peerWorldSessionState represents the peer's state in world session lifecycle.
// timestamp is used only for JNI.
type peerWorldSessionState struct {
	ANDPeerSession
	state ANDSessionState
	fwd   bool
	cnt   int
}

// ANDFullPeerSessionInfo provides all the information required to
// connect a peer, identify its world session, negotiate ordering.
// As a result, a peer who receives this can construct ANDFullPeerSession.
type ANDFullPeerSessionInfo struct {
	ANDIdentity
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}

// ObjectInfo is used to represent shared object.
type ObjectInfo struct {
	ID        uuid.UUID
	Addr      string
	Transform [7]float32
}
