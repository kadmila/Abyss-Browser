package and

import (
	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/config"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

// TODO: define transmission error type.

func (w *World) sendJN(target ani.IAbyssPeer, path string) error {
	return target.Send(ahmp.JN_T, RawJN{
		SenderSessionID: w.WSID.String(),
		Path:            path,
	})
}
func (w *World) sendJOK_JNI(joiner ANDPeerSession) error {
	member_entries := make([]ANDPeerSession, 0, len(w.entries))
	for _, e := range w.entries {
		if e.state != WS_MEM {
			continue
		}
		member_entries = append(member_entries, e.ANDPeerSession)
		w.sendJNI(e, joiner)
	}
	return joiner.Peer.Send(ahmp.JOK_T, RawJOK{
		SenderSessionID: w.WSID.String(),
		RecverSessionID: joiner.SessionID.String(),
		URL:             w.env_url,
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
func (w *World) sendJNI(member *peerWorldSessionState, joiner ANDPeerSession) error {
	return member.Peer.Send(ahmp.JNI_T, RawJNI{
		SenderSessionID: w.WSID.String(),
		RecverSessionID: member.SessionID.String(),
		Joiner:          MakeRawSessionInfoForDiscovery(joiner),
	})
}
func (w *World) sendMEM(member *peerWorldSessionState) error {
	return member.Peer.Send(ahmp.MEM_T, RawMEM{
		SenderSessionID: w.WSID.String(),
		RecverSessionID: member.SessionID.String(),
		TimeStamp:       w.timestamp.UnixMilli(),
	})
}
func (w *World) broadcastSJN() error {
	sjn_entries := functional.Filter_MtS_ok(w.entries, func(e *peerWorldSessionState) (RawSessionInfoForSJN, bool) {
		if e.state == WS_MEM && e.fwd && e.cnt < 3 {
			e.fwd = false
			return RawSessionInfoForSJN{
				e.Peer.ID(),
				e.SessionID.String(),
			}, true
		}
		return RawSessionInfoForSJN{}, false
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
			SenderSessionID: w.WSID.String(),
			RecverSessionID: entry.SessionID.String(),
			MemberInfos:     sjn_entries,
		})
	}
	return nil
}
func (w *World) sendCRR(member *peerWorldSessionState, missing_entries []ANDIdentity) error {
	return member.Peer.Send(ahmp.CRR_T, RawCRR{
		SenderSessionID: w.WSID.String(),
		RecverSessionID: member.SessionID.String(),
		MemberInfos: functional.Filter(missing_entries, func(i ANDIdentity) RawSessionInfoForSJN {
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
		SenderSessionID: w.WSID.String(),
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
		SenderSessionID: w.WSID.String(),
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
		entry.Peer.Send(ahmp.RST_T, RawRST{
			SenderSessionID: w.WSID.String(),
			RecverSessionID: entry.SessionID.String(),
			Code:            code,
			Message:         message,
		})
	}
	return nil
}

func SendJDN_NoWorld(peer_session ANDPeerSession, code int, message string) error {
	return peer_session.Peer.Send(ahmp.JDN_T, RawJDN{
		RecverSessionID: peer_session.SessionID.String(),
		Code:            code,
		Message:         message,
	})
}

func SendRST_UnexpectedArbitraryWorld(peer_session ANDPeerSession, unknown_wsid uuid.UUID) error {
	return peer_session.Peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: unknown_wsid.String(),
		RecverSessionID: peer_session.SessionID.String(),
		Code:            JNC_UNEXPECTED_WSID,
		Message:         JNM_UNEXPECTED_WSID,
	})
}

// sendSOA sends SOA (Shared Object Append) message to a specific peer.
func (w *World) sendSOA(target *peerWorldSessionState, objects []ObjectInfo) error {
	rawObjects := functional.Filter(objects, func(obj ObjectInfo) RawObjectInfo {
		return RawObjectInfo{
			ID:        obj.ID.String(),
			Address:   obj.Addr,
			Transform: obj.Transform,
		}
	})

	return target.Peer.Send(ahmp.SOA_T, RawSOA{
		SenderSessionID: w.WSID.String(),
		RecverSessionID: target.SessionID.String(),
		Objects:         rawObjects,
	})
}

// sendSOD sends SOD (Shared Object Delete) message to a specific peer.
func (w *World) sendSOD(target *peerWorldSessionState, objectIDs []uuid.UUID) error {
	rawObjectIDs := functional.Filter(objectIDs, func(oid uuid.UUID) string {
		return oid.String()
	})

	return target.Peer.Send(ahmp.SOD_T, RawSOD{
		SenderSessionID: w.WSID.String(),
		RecverSessionID: target.SessionID.String(),
		ObjectIDs:       rawObjectIDs,
	})
}
