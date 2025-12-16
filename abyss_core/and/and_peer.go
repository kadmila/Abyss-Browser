package and

import (
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

type ANDPeer struct {
	ani.IAbyssPeer
}

func (p *ANDPeer) SendJN(local_session_id uuid.UUID, path string, timestamp time.Time) error {
	return p.Send(ahmp.JN_T, ahmp.RawJN{
		SenderSessionID: local_session_id.String(),
		Text:            path,
		TimeStamp:       timestamp.UnixMilli(),
	})
}
func (p *ANDPeer) TrySendJOK(local_session_id uuid.UUID, peer_session_id uuid.UUID, timestamp time.Time, world_url string, member_sessions []abyss.ANDPeerSessionWithTimeStamp) error {
	return p.Send(ahmp.JOK_T, ahmp.RawJOK{
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
func (p *ANDPeer) TrySendJDN(peer_session_id uuid.UUID, code int, message string) error {
	return p.Send(ahmp.JDN_T, ahmp.RawJDN{
		RecverSessionID: peer_session_id.String(),
		Text:            message,
		Code:            code,
	})
}
func (p *ANDPeer) TrySendJNI(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_session abyss.ANDPeerSessionWithTimeStamp) error {
	return p.Send(ahmp.JNI_T, ahmp.RawJNI{
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
func (p *ANDPeer) TrySendMEM(local_session_id uuid.UUID, peer_session_id uuid.UUID, timestamp time.Time) error {
	return p.Send(ahmp.MEM_T, ahmp.RawMEM{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		TimeStamp:       timestamp.UnixMilli(),
	})
}
func (p *ANDPeer) TrySendSJN(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_sessions []abyss.ANDPeerSessionIdentity) error {
	return p.Send(ahmp.SJN_T, ahmp.RawSJN{
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
func (p *ANDPeer) TrySendCRR(local_session_id uuid.UUID, peer_session_id uuid.UUID, member_sessions []abyss.ANDPeerSessionIdentity) error {
	return p.Send(ahmp.CRR_T, ahmp.RawCRR{
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
func (p *ANDPeer) TrySendRST(local_session_id uuid.UUID, peer_session_id uuid.UUID, message string) error {
	return p.Send(ahmp.RST_T, ahmp.RawRST{
		SenderSessionID: local_session_id.String(),
		RecverSessionID: peer_session_id.String(),
		Message:         message,
	})
}
