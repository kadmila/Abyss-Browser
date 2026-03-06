package and

import (
	"net/netip"

	"github.com/google/uuid"
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
	World *World
	Error error
}
