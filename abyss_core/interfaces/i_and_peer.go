package interfaces

import (
	"context"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"

	"github.com/google/uuid"
)

type ANDPeerSession struct {
	Peer          IANDPeer
	PeerSessionID uuid.UUID
}

type ANDPeerSessionWithTimeStamp struct {
	ANDPeerSession
	TimeStamp time.Time
}

type ANDPeerSessionIdentity struct {
	PeerHash  string
	SessionID uuid.UUID
}

type ANDFullPeerSessionIdentity struct {
	AURL                       *aurl.AURL
	SessionID                  uuid.UUID
	TimeStamp                  time.Time
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}

type IANDPeer interface {
	IDHash() string
	RootCertificateDer() []byte
	HandshakeKeyCertificateDer() []byte

	IsConnected() bool
	AURL() *aurl.AURL

	//inactivity check
	Context() context.Context
	Activate()
	Renew()
	Deactivate()
	Error() error

	AhmpCh() chan any

	TrySendJN(local_session_id uuid.UUID, path string, timestamp time.Time) bool
	TrySendJOK(local_session_id uuid.UUID, peer_session_id uuid.UUID, timestamp time.Time, world_url string, member_sessions []ANDPeerSessionWithTimeStamp) bool
	TrySendJDN(peer_session_id uuid.UUID, code int, message string) bool
	TrySendJNI(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_session ANDPeerSessionWithTimeStamp) bool
	TrySendMEM(local_session_id uuid.UUID, peer_session_id uuid.UUID, timestamp time.Time) bool
	TrySendSJN(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_sessions []ANDPeerSessionIdentity) bool
	TrySendCRR(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_sessions []ANDPeerSessionIdentity) bool
	TrySendRST(local_session_id uuid.UUID, peer_session_id uuid.UUID, message string) bool

	TrySendSOA(local_session_id uuid.UUID, peer_session_id uuid.UUID, objects []ObjectInfo) bool
	TrySendSOD(local_session_id uuid.UUID, peer_session_id uuid.UUID, objectIDs []uuid.UUID) bool
}
