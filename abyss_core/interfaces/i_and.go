package interfaces

import (
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"

	"github.com/google/uuid"
)

type NeighborEventType int

const (
	ANDSessionRequest NeighborEventType = iota + 2
	ANDSessionReady
	ANDSessionClose
	ANDJoinSuccess
	ANDJoinFail
	ANDWorldLeave //called after WorldLeave
	ANDConnectRequest
	ANDTimerRequest
	ANDPeerRegister

	ANDObjectAppend
	ANDObjectDelete
	ANDNeighborEventDebug
)

type NeighborEvent struct {
	Type           NeighborEventType
	LocalSessionID uuid.UUID
	ANDPeerSession
	Text   string
	Value  int
	Object any
}

type PeerCertificates struct {
	RootCertDer         []byte
	HandshakeKeyCertDer []byte
}

type ANDERROR int

const (
	_      ANDERROR = iota //no error
	EINVAL                 //invalid argument
	EPANIC                 //unrecoverable internal error (must not occur)
)

type INeighborDiscovery interface { // all calls must be thread-safe
	EventChannel() chan NeighborEvent

	//calls
	PeerConnected(peer IANDPeer) ANDERROR
	PeerClose(peer IANDPeer) ANDERROR
	OpenWorld(local_session_id uuid.UUID, world_url string) ANDERROR
	JoinWorld(local_session_id uuid.UUID, abyss_url *aurl.AURL) ANDERROR
	AcceptSession(local_session_id uuid.UUID, peer_session ANDPeerSession) ANDERROR
	DeclineSession(local_session_id uuid.UUID, peer_session ANDPeerSession, code int, message string) ANDERROR
	CloseWorld(local_session_id uuid.UUID) ANDERROR
	TimerExpire(local_session_id uuid.UUID) ANDERROR

	//ahmp messages
	JN(local_session_id uuid.UUID, peer_session ANDPeerSession, timestamp time.Time) ANDERROR
	JOK(local_session_id uuid.UUID, peer_session ANDPeerSession, timestamp time.Time, world_url string, member_sessions []ANDFullPeerSessionIdentity) ANDERROR
	JDN(local_session_id uuid.UUID, peer IANDPeer, code int, message string) ANDERROR
	JNI(local_session_id uuid.UUID, peer_session ANDPeerSession, member_session ANDFullPeerSessionIdentity) ANDERROR
	MEM(local_session_id uuid.UUID, peer_session ANDPeerSession, timestamp time.Time) ANDERROR
	SJN(local_session_id uuid.UUID, peer_session ANDPeerSession, member_infos []ANDPeerSessionIdentity) ANDERROR
	CRR(local_session_id uuid.UUID, peer_session ANDPeerSession, member_infos []ANDPeerSessionIdentity) ANDERROR
	RST(local_session_id uuid.UUID, peer_session ANDPeerSession, message string) ANDERROR

	SOA(local_session_id uuid.UUID, peer_session ANDPeerSession, objects []ObjectInfo) ANDERROR
	SOD(local_session_id uuid.UUID, peer_session ANDPeerSession, objectIDs []uuid.UUID) ANDERROR

	Statistics() string
}
