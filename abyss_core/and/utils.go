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
	N   int64
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
	TimerMinInterval  = 300
	TimerUnitInterval = 300
)

// All durations are calculated in miliseconds, and then applied to native time type later.

func (t *ANDTimer) Increment() {
	t.N++
	now := time.Now()

	if t.due.After(now) {
		time_remaining_ms := t.due.Sub(now).Milliseconds()
		elongate_duration_ms := time_remaining_ms * t.N / (t.N - 1)
		if elongate_duration_ms > TimerMinInterval {
			elongated_duration := time.Duration(elongate_duration_ms) * time.Millisecond
			t.Reset(elongated_duration)
			t.due = now.Add(elongated_duration)
		}
		// worst case: double expiration - if the host is very very slow and badly timed. unlikely to happen.
	} else {
		rand_interval_ms := TimerMinInterval + rand.Int64N(TimerUnitInterval*t.N)
		new_duration := time.Duration(rand_interval_ms) * time.Millisecond
		t.Reset(new_duration)
		t.due = now.Add(new_duration)
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

	time_remaining_ms := t.due.Sub(now).Milliseconds()
	shortened_duration_ms := time_remaining_ms * t.N / (t.N + 1)
	if shortened_duration_ms > TimerMinInterval {
		shortened_duration := time.Duration(shortened_duration_ms) * time.Millisecond
		t.Reset(shortened_duration)
		t.due = now.Add(shortened_duration)
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

	// trickle broadcast
	t    float32 // ratio
	cnt  int
	done chan bool
}

// ANDFullPeerSessionInfo provides all the information required to
// connect a peer, identify its world session, negotiate ordering.
// As a result, a peer who receives this can construct ANDFullPeerSession.
type ANDFullPeerSessionInfo struct {
	ANDIdentity
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}

func MakeANDFullPeerSessionInfo(peer_session ANDPeerSession) ANDFullPeerSessionInfo {
	return ANDFullPeerSessionInfo{
		ANDIdentity:                peer_session.ANDIdentity(),
		RootCertificateDer:         peer_session.Peer.RootCertificateDer(),
		HandshakeKeyCertificateDer: peer_session.Peer.HandshakeKeyCertificateDer(),
	}
}

// ObjectInfo is used to represent shared object.
type ObjectInfo struct {
	ID        uuid.UUID
	Addr      string
	Transform [7]float32
}
