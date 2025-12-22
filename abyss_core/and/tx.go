package and

import (
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/config"
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
func (w *World) sendJDN_Direct(peer_session ANDPeerSession, code int, message string) error {
	return peer_session.Peer.Send(ahmp.JDN_T, RawJDN{
		RecverSessionID: peer_session.SessionID.String(),
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
func (w *World) broadcastSJN() error {
	sjn_entries := functional.Filter_MtS_ok(w.entries, func(e *peerWorldSessionState) (RawSessionInfoForSJN, bool) {
		result := MakeRawSessionInfoForSJN(e)
		if e.state != WS_MEM || time.Since(e.TimeStamp) < time.Second || e.sjnp || e.sjnc > 3 {
			return result, false
		}
		e.sjnc++
		return result, true
	})

	if len(sjn_entries) == 0 {
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
			MemberInfos:     sjn_entries,
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
func (w *World) sendRST(target *peerWorldSessionState, code int, message string) error {
	config.IF_DEBUG(func() {
		if target.SessionID == uuid.Nil {
			panic("sending RST with empty RecverSessionID is prohibited")
		}
	})
	return target.Peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: target.SessionID.String(),
		Code:            code,
		Message:         message,
	})
}
func (w *World) sendRST_Direct(peer_session ANDPeerSession, code int, message string) error {
	config.IF_DEBUG(func() {
		if peer_session.SessionID == uuid.Nil {
			panic("sending RST with empty RecverSessionID is prohibited")
		}
	})
	return peer_session.Peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: w.lsid.String(),
		RecverSessionID: peer_session.SessionID.String(),
		Code:            code,
		Message:         message,
	})
}
func (w *World) broadcastRST(code int, message string) error {
	for _, entry := range w.entries {
		if entry.Peer == nil || entry.SessionID == uuid.Nil {
			// must not send an untargetted reset.
			continue
		}
		if entry.state == WS_JN {
			entry.Peer.Send(ahmp.RST_T, RawJDN{
				RecverSessionID: entry.SessionID.String(),
				Code:            code,
				Message:         message,
			})
		} else {
			entry.Peer.Send(ahmp.RST_T, RawRST{
				SenderSessionID: w.lsid.String(),
				RecverSessionID: entry.SessionID.String(),
				Code:            code,
				Message:         message,
			})
		}
	}
	return nil
}

func SendRST_NoWorld(peer_session ANDPeerSession, code int, message string) error {
	config.IF_DEBUG(func() {
		if peer_session.SessionID == uuid.Nil {
			panic("sending RST with empty RecverSessionID is prohibited")
		}
	})
	return peer_session.Peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: uuid.Nil.String(),
		RecverSessionID: peer_session.SessionID.String(),
		Code:            code,
		Message:         message,
	})
}
