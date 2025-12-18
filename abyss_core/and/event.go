package and

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

type IANDEvent any

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
type EANDJoinSuccess struct {
	World *World
	URL   string
}
type EANDJoinFail struct {
	World   *World
	Code    int
	Message string
}
type EANDWorldLeave struct {
	World *World
}
type EANDPeerRequest struct {
	PeerID                     string
	AddressCandidates          []netip.AddrPort
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}
type EANDPeerRemove struct {
	World *World
	Peer  ani.IAbyssPeer
}
type EANDTimerRequest struct {
	World    *World
	Duration time.Duration
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
