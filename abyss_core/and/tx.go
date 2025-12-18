package and

import (
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

// TODO: define transmission error type.

func (w *World) sendJN(target *peerWorldSessionState) error {
	return target.Peer.Send(ahmp.JN_T, RawJN{
		SenderSessionID: w.lsid.String(),
		Path:            w.join_path,
		TimeStamp:       w.timestamp.UnixMilli(),
	})
}
func (w *World) sendJOK_JNI(joiner *peerWorldSessionState) error {
	member_entries := make([]*peerWorldSessionState, 0, len(w.entries))
	for _, e := range w.entries {
		if e.state != WS_MEM {
			continue
		}
		member_entries = append(member_entries, e)
		w.sendJNI(e, joiner)
	}
	return joiner.Peer.Send(ahmp.JOK_T, RawJOK{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: joiner.SessionID.String(),
		TimeStamp:       w.timestamp.UnixMilli(),
		URL:             w.url,
		Neighbors:       functional.Filter(member_entries, MakeRawSessionInfoForDiscovery),
	})
}
func (w *World) sendJDN(joiner *peerWorldSessionState, code int, message string) error {
	return joiner.Peer.Send(ahmp.JDN_T, RawJDN{
		RecverSessionID: joiner.SessionID.String(),
		Code:            code,
		Message:         message,
	})
}
func (w *World) sendJNI(member *peerWorldSessionState, joiner *peerWorldSessionState) error {
	return member.Peer.Send(ahmp.JNI_T, RawJNI{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: member.SessionID.String(),
		Joiner:          MakeRawSessionInfoForDiscovery(joiner),
	})
}
func (w *World) sendMEM(member *peerWorldSessionState) error {
	return member.Peer.Send(ahmp.MEM_T, RawMEM{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: member.SessionID.String(),
		TimeStamp:       w.timestamp.UnixMilli(),
	})
}
func (w *World) broadcastSJN(member *peerWorldSessionState) error {
	sjn_mem := make([]*peerWorldSessionState, 0)
	for _, entry := range w.entries {
		if entry.state != WS_MEM || // not a member
			time.Since(entry.TimeStamp) < time.Second || // too early
			entry.sjnp || // prohibited
			entry.sjnc > 3 { // more than three counts
			continue
		}
		sjn_mem = append(sjn_mem, entry)
		entry.sjnc += 3 // count as enough
	}

	if len(sjn_mem) == 0 {
		return nil
	}

	// send
	for _, entry := range w.entries {
		if entry.state != WS_MEM {
			continue
		}
		entry.Peer.Send(ahmp.SJN_T, RawSJN{
			SenderSessionID: w.lsid.String(),
			RecverSessionID: entry.SessionID.String(),
			MemberInfos:     functional.Filter(sjn_mem, MakeRawSessionInfoForSJN),
		})
	}
	return nil
}
func (w *World) sendCRR(member *peerWorldSessionState, missing_entries []ANDPeerSessionIdentity) error {
	return member.Peer.Send(ahmp.CRR_T, RawCRR{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: member.SessionID.String(),
		MemberInfos: functional.Filter(missing_entries, func(i ANDPeerSessionIdentity) RawSessionInfoForSJN {
			return RawSessionInfoForSJN{
				PeerID:    i.PeerID,
				SessionID: i.SessionID.String(),
			}
		}),
	})
}
func (w *World) sendRST(target *peerWorldSessionState, message string) error {
	return target.Peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: target.SessionID.String(),
		Message:         message,
	})
}

func SendRST_NoWorld(peer ani.IAbyssPeer, peer_session_id uuid.UUID, message string) error {
	return peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: uuid.Nil.String(),
		RecverSessionID: peer_session_id.String(),
		Message:         message,
	})
}
