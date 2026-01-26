package and

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

// ANDPeerSession is used to indirect a peer world session
// in IANDEvent.
type ANDPeerSession struct {
	Peer      ani.IAbyssPeer
	SessionID uuid.UUID
}

// ObjectInfo is used to represent shared object.
type ObjectInfo struct {
	ID        uuid.UUID
	Addr      string
	Transform [7]float32
}

///// For world algorithm
/* copy-paste
WS_DC_JNI
WS_CC
WS_JN
WS_RMEM_NJNI
WS_JNI
WS_RMEM
WS_TMEM
WS_MEM
*/

type ANDSessionState int

const (
	// WS_DC_JNI : disconnected, JNI received
	// (X) Peer, is_session_requested
	// (O) PeerID, SessionID, TimeStamp
	WS_DC_JNI ANDSessionState = iota + 1

	// from now on, PeerID, Peer, AddressCandidates are known.

	// WS_CC : connected, no info. <<W_Joining>>
	// (X) SessionID, TimeStamp, is_session_requested
	WS_CC

	// WS_JN : JN received
	// (O) SessionID, TimeStamp, is_session_requested
	WS_JN

	// WS_RMEM_NJNI : MEM received, JNI not received. <<W_Joining>>
	// (X) is_session_requested
	// (O) SessionID, TimeStamp
	WS_RMEM_NJNI

	// WS_JNI : JNI received, MEM not received
	// (X)
	// (O) SessionID, TimeStamp is_session_requested
	WS_JNI

	// WS_RMEM : MEM received
	// (X)
	// (O) SessionID, TimeStamp, is_session_requested
	WS_RMEM

	// WS_TMEM : MEM/JOK sent
	// (X)
	// (O) SessionID, TimeStamp, is_session_requested
	WS_TMEM

	// WS_MEM : member
	// (X)
	// (O) SessionID, TimeStamp, is_session_requested
	WS_MEM
)

func (s ANDSessionState) String() string {
	switch s {
	case WS_DC_JNI:
		return "DC_JNI"
	case WS_CC:
		return "CC"
	case WS_JN:
		return "JN"
	case WS_RMEM_NJNI:
		return "RMEM_NJNI"
	case WS_JNI:
		return "JNI"
	case WS_RMEM:
		return "RMEM"
	case WS_TMEM:
		return "TMEM"
	case WS_MEM:
		return "MEM"
	default:
		return fmt.Sprintf("ANDSessionState(%d)", s)
	}
}

// peerWorldSessionState represents the peer's state in world session lifecycle.
// timestamp is used only for JNI.
type peerWorldSessionState struct {
	state                ANDSessionState
	PeerID               string
	Peer                 ani.IAbyssPeer // this is nil if state is WS_DN_JNI
	SessionID            uuid.UUID
	TimeStamp            time.Time
	is_session_requested bool // this is true if EANDSessionRequest was fired.
	sjnp                 bool //is sjn suppressed
	sjnc                 int  //sjn receive count
}

func (s *peerWorldSessionState) ANDPeerSession() ANDPeerSession {
	return ANDPeerSession{
		Peer:      s.Peer,
		SessionID: s.SessionID,
	}
}

// ANDFullPeerSessionInfo provides all the information required to
// connect a peer, identify its world session, negotiate ordering.
// As a result, a peer who receives this can construct ANDFullPeerSession.
type ANDFullPeerSessionInfo struct {
	PeerID                     string
	AddressCandidates          []netip.AddrPort
	SessionID                  uuid.UUID
	TimeStamp                  time.Time
	RootCertificateDer         []byte
	HandshakeKeyCertificateDer []byte
}

// ANDPeerSessionIdentity is used to indirect a peer world session,
// which is used in connection recovery.
type ANDPeerSessionIdentity struct {
	PeerID    string
	SessionID uuid.UUID
}
