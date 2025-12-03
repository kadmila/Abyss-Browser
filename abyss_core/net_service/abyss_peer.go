package net_service

import (
	"net"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/quic-go/quic-go"

	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
	"github.com/kadmila/Abyss-Browser/abyss_core/watchdog"
)

// Peer Network Complex State
type PNCState int

const (
	PNCS_DISCONNECTED PNCState = iota
	PNCS_INBOUND
	PNCS_OUTBOUND
	PNCS_CONNECTED
	PNCS_CLOSED
)

type AbyssPeer struct {
	state           PNCState     //can be checked without entering mtx only after once its state becomes PNCS_CONNECTED
	identity        PeerIdentity //must be set at creation
	addresses       []*net.UDPAddr
	inbound_conn    quic.Connection
	outbound_conn   quic.Connection
	ahmp_encoder    *cbor.Encoder
	ahmp_decoder    *cbor.Decoder //only listenAhmp() reads from this
	ahmp_decoded_ch chan any
	err             error

	mtx sync.Mutex //for peer component changes.
}

func NewAbyssPeer(identity PeerIdentity) *AbyssPeer {
	return &AbyssPeer{
		state:           PNCS_DISCONNECTED,
		identity:        identity,
		addresses:       make([]*net.UDPAddr, 0),
		ahmp_decoded_ch: make(chan any, 32),
	}
}

func (p *AbyssPeer) IDHash() string {
	return p.identity.root_id_hash
}

func (p *AbyssPeer) RootCertificateDer() []byte {
	return p.identity.root_self_cert_der
}

func (p *AbyssPeer) HandshakeKeyCertificateDer() []byte {
	return p.identity.handshake_key_cert_der
}
func (p *AbyssPeer) AURL() *aurl.AURL {
	return &aurl.AURL{
		Scheme:    "abyss",
		Hash:      p.identity.root_id_hash,
		Addresses: p.addresses,
		Path:      "/",
	}
}

func (p *AbyssPeer) IsConnected() bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	return p.state == PNCS_CONNECTED
}
func (p *AbyssPeer) AhmpCh() chan any {
	return p.ahmp_decoded_ch
}

func (p *ContextedPeer) _trySend(v any) bool {
	if p.state != PNCS_CONNECTED {
		return false
	}

	err := p.ahmp_encoder.Encode(v)
	if err != nil {
		p.mtx.Lock()
		p.state = PNCS_CLOSED
		p.err = err
		p.mtx.Unlock()

		p.cancelfunc()
		return false
	}
	return true
}
func (p *ContextedPeer) _trySend2(v int, w any) bool {
	//debug
	watchdog.InfoV(ahmp.Msg_type_names[v]+"> "+p.inbound_conn.RemoteAddr().String(), w)
	type_sent := p._trySend(v)
	body_sent := p._trySend(w)
	return type_sent && body_sent
}

func (p *ContextedPeer) TrySendJN(local_session_id uuid.UUID, path string, timestamp time.Time) bool {
	return p._trySend2(ahmp.JN_T, ahmp.RawJN{
		SenderSessionID: local_session_id.String(),
		Text:            path,
		TimeStamp:       timestamp.UnixMilli(),
	})
}
func (p *ContextedPeer) TrySendJOK(local_session_id uuid.UUID, peer_session_id uuid.UUID, timestamp time.Time, world_url string, member_sessions []abyss.ANDPeerSessionWithTimeStamp) bool {
	return p._trySend2(ahmp.JOK_T, ahmp.RawJOK{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		TimeStamp:       timestamp.UnixMilli(),
		Text:            world_url,
		Neighbors: functional.Filter(member_sessions, func(session abyss.ANDPeerSessionWithTimeStamp) ahmp.RawSessionInfoForDiscovery {
			return ahmp.RawSessionInfoForDiscovery{
				AURL:                       session.Peer.AURL().ToString(),
				SessionID:                  session.PeerSessionID.String(),
				TimeStamp:                  session.TimeStamp.UnixMilli(),
				RootCertificateDer:         session.Peer.RootCertificateDer(),
				HandshakeKeyCertificateDer: session.Peer.HandshakeKeyCertificateDer(),
			}
		}),
	})
}
func (p *ContextedPeer) TrySendJDN(peer_session_id uuid.UUID, code int, message string) bool {
	return p._trySend2(ahmp.JDN_T, ahmp.RawJDN{
		RecverSessionID: peer_session_id.String(),
		Text:            message,
		Code:            code,
	})
}
func (p *ContextedPeer) TrySendJNI(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_session abyss.ANDPeerSessionWithTimeStamp) bool {
	return p._trySend2(ahmp.JNI_T, ahmp.RawJNI{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		Neighbor: ahmp.RawSessionInfoForDiscovery{
			AURL:                       member_session.Peer.AURL().ToString(),
			SessionID:                  member_session.PeerSessionID.String(),
			TimeStamp:                  member_session.TimeStamp.UnixMilli(),
			RootCertificateDer:         member_session.Peer.RootCertificateDer(),
			HandshakeKeyCertificateDer: member_session.Peer.HandshakeKeyCertificateDer(),
		},
	})
}
func (p *ContextedPeer) TrySendMEM(local_session_id uuid.UUID, peer_session_id uuid.UUID, timestamp time.Time) bool {
	return p._trySend2(ahmp.MEM_T, ahmp.RawMEM{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		TimeStamp:       timestamp.UnixMilli(),
	})
}
func (p *ContextedPeer) TrySendSJN(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_sessions []abyss.ANDPeerSessionIdentity) bool {
	return p._trySend2(ahmp.SJN_T, ahmp.RawSJN{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		MemberInfos: functional.Filter(member_sessions, func(i abyss.ANDPeerSessionIdentity) ahmp.RawSessionInfoForSJN {
			return ahmp.RawSessionInfoForSJN{
				PeerHash:  i.PeerHash,
				SessionID: i.SessionID.String(),
			}
		}),
	})
}
func (p *ContextedPeer) TrySendCRR(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_sessions []abyss.ANDPeerSessionIdentity) bool {
	return p._trySend2(ahmp.CRR_T, ahmp.RawCRR{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		MemberInfos: functional.Filter(member_sessions, func(i abyss.ANDPeerSessionIdentity) ahmp.RawSessionInfoForSJN {
			return ahmp.RawSessionInfoForSJN{
				PeerHash:  i.PeerHash,
				SessionID: i.SessionID.String(),
			}
		}),
	})
}
func (p *ContextedPeer) TrySendRST(local_session_id uuid.UUID, peer_session_id uuid.UUID, message string) bool {
	return p._trySend2(ahmp.RST_T, ahmp.RawRST{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		Message:         message,
	})
}

func (p *ContextedPeer) TrySendSOA(local_session_id uuid.UUID, peer_session_id uuid.UUID, objects []abyss.ObjectInfo) bool {
	return p._trySend2(ahmp.SOA_T, ahmp.RawSOA{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		Objects: functional.Filter(objects, func(u abyss.ObjectInfo) ahmp.RawObjectInfo {
			return ahmp.RawObjectInfo{
				ID:        u.ID.String(),
				Address:   u.Addr,
				Transform: u.Transform,
			}
		}),
	})
}
func (p *ContextedPeer) TrySendSOD(local_session_id uuid.UUID, peer_session_id uuid.UUID, objectIDs []uuid.UUID) bool {
	return p._trySend2(ahmp.SOD_T, ahmp.RawSOD{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		ObjectIDs:       functional.Filter(objectIDs, func(u uuid.UUID) string { return u.String() }),
	})
}
