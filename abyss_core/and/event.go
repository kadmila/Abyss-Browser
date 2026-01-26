package and

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

// IANDEvent conveys event/request from AND to host.
// a session may close before ready, but never before request.
// No event should be pushed after JoinFail or WorldLeave.
// This must be a pointer for an EAND struct.
type IANDEvent any

type EANDWorldEnter struct {
	World *World
	URL   string
}
type EANDSessionRequest struct {
	World *World
	ANDPeerSession
}
type EANDSessionReady struct {
	World *World
	ANDPeerSession
}
type EANDSessionClose struct {
	World *World
	ANDPeerSession
}
type EANDPeerRequest struct {
	World                      *World
	PeerID                     string
	AddressCandidates          []netip.AddrPort
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}
type EANDPeerDiscard struct {
	World *World
	Peer  ani.IAbyssPeer
}
type EANDTimerRequest struct {
	World    *World
	Duration time.Duration
}
type EANDWorldLeave struct {
	World   *World
	Code    int
	Message string
}

/// shared object

type EANDObjectAppend struct {
	World *World
	ANDPeerSession
	Objects []ObjectInfo
}
type EANDObjectDelete struct {
	World *World
	ANDPeerSession
	ObjectIDs []uuid.UUID
}

/// debug

type EANDError struct {
}

// type ANDEventQueue struct {
// 	inner *list.List
// }

// func NewANDEventQueue() *ANDEventQueue {
// 	return &ANDEventQueue{
// 		inner: list.New(),
// 	}
// }

// func (q *ANDEventQueue) Push(e any) {
// 	q.inner.PushBack(e)
// }
// func (q *ANDEventQueue) Pop() (any, bool) {
// 	front := q.inner.Front()
// 	if front == nil {
// 		return nil, false
// 	}
// 	return q.inner.Remove(front), true
// }
