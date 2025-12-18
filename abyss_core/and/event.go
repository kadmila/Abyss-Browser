package and

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

// IANDEvent conveys event/request from AND to host.
// a session my close before ready, but never before request.
// Discard/Leave is a confirmation, not a request.
// If JoinFail or WorldLeave is fired,
// no further event is meaningful.
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
