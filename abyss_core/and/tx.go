package and

import (
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

// TODO: define transmission error type.

func (w *World) SendJN(target *peerWorldSessionState) error {
	return target.Peer.Send(ahmp.JN_T, RawJN{
		SenderSessionID: w.lsid.String(),
		Path:            w.join_path,
		TimeStamp:       w.timestamp.UnixMilli(),
	})
}
func (w *World) SendJOK_JNI(joiner *peerWorldSessionState) error {
	member_entries := make([]*peerWorldSessionState, 0, len(w.entries))
	for _, e := range w.entries {
		if e.state != WS_MEM {
			continue
		}
		member_entries = append(member_entries, e)
		w.SendJNI(e, joiner)
	}
	return joiner.Peer.Send(ahmp.JOK_T, RawJOK{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: joiner.SessionID.String(),
		TimeStamp:       w.timestamp.UnixMilli(),
		URL:             w.url,
		Neighbors:       functional.Filter(member_entries, MakeRawSessionInfoForDiscovery),
	})
}
func (w *World) SendJDN(peer ani.IAbyssPeer, peer_session_id uuid.UUID, code int, message string) error {
	return peer.Send(ahmp.JDN_T, RawJDN{
		RecverSessionID: peer_session_id.String(),
		Message:         message,
		Code:            code,
	})
}
func (w *World) SendJNI(member *peerWorldSessionState, joiner *peerWorldSessionState) error {
	return member.Peer.Send(ahmp.JNI_T, RawJNI{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: member.SessionID.String(),
		Neighbor:        MakeRawSessionInfoForDiscovery(joiner),
	})
}
func (w *World) SendMEM(peer ani.IAbyssPeer, peer_session_id uuid.UUID, timestamp time.Time) error {
	return peer.Send(ahmp.MEM_T, RawMEM{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: peer_session_id.String(),
		TimeStamp:       timestamp.UnixMilli(),
	})
}
func (w *World) SendSJN(peer ani.IAbyssPeer, peer_session_id uuid.UUID, member_sessions []ANDPeerSessionIdentity) error {
	return peer.Send(ahmp.SJN_T, RawSJN{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: peer_session_id.String(),
		MemberInfos: functional.Filter(member_sessions, func(i ANDPeerSessionIdentity) RawSessionInfoForSJN {
			return RawSessionInfoForSJN{
				PeerID:    i.PeerID,
				SessionID: i.SessionID.String(),
			}
		}),
	})
}
func (w *World) SendCRR(peer ani.IAbyssPeer, peer_session_id uuid.UUID, member_sessions []ANDPeerSessionIdentity) error {
	return peer.Send(ahmp.CRR_T, RawCRR{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: peer_session_id.String(),
		MemberInfos: functional.Filter(member_sessions, func(i ANDPeerSessionIdentity) RawSessionInfoForSJN {
			return RawSessionInfoForSJN{
				PeerID:    i.PeerID,
				SessionID: i.SessionID.String(),
			}
		}),
	})
}
func (w *World) SendRST(peer ani.IAbyssPeer, peer_session_id uuid.UUID, message string) error {
	return peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: peer_session_id.String(),
		Message:         message,
	})
}
