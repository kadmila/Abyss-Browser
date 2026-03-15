package and

import (
	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

// TODO: define transmission error type.

func (w *World) sendJN(target ani.IAbyssPeer, path string) error {
	return target.Send(ahmp.JN_T, RawJN{
		SenderSessionID: w.WSID[:],
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
		w.sendJNI(e.ANDPeerSession, joiner, true)
	}
	return joiner.Peer.Send(ahmp.JOK_T, RawJOK{
		SenderSessionID: w.WSID[:],
		RecverSessionID: joiner.SessionID[:],
		URL:             w.env_url,
		Neighbors:       functional.Filter(member_entries, MakeRawANDFullPeerSessionInfo),
	})
}
func (w *World) sendJNI(member ANDPeerSession, joiner ANDPeerSession, fwd bool) error {
	return member.Peer.Send(ahmp.JNI_T, RawJNI{
		SenderSessionID: w.WSID[:],
		RecverSessionID: member.SessionID[:],
		Joiner:          MakeRawANDFullPeerSessionInfo(joiner),
		Fwd:             fwd,
	})
}
func (w *World) sendMEM(member ANDPeerSession) error {
	return member.Peer.Send(ahmp.MEM_T, RawMEM{
		SenderSessionID: w.WSID[:],
		RecverSessionID: member.SessionID[:],
	})
}
func (w *World) sendRST(target ANDPeerSession, code int, message string) error {
	return target.Peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: w.WSID[:],
		RecverSessionID: target.SessionID[:],
		Code:            code,
		Message:         message,
	})
}
func (w *World) broadcastRST(code int, message string) error {
	for _, entry := range w.entries {
		entry.Peer.Send(ahmp.RST_T, RawRST{
			SenderSessionID: w.WSID[:],
			RecverSessionID: entry.SessionID[:],
			Code:            code,
			Message:         message,
		})
	}
	return nil
}

func SendRST(peer_session ANDPeerSession, sender_wsid uuid.UUID, code int, message string) error {
	return peer_session.Peer.Send(ahmp.RST_T, RawRST{
		SenderSessionID: sender_wsid[:],
		RecverSessionID: peer_session.SessionID[:],
		Code:            code,
		Message:         message,
	})
}

// sendSOA sends SOA (Shared Object Append) message to a specific peer.
func (w *World) sendSOA(target ANDPeerSession, objects []ObjectInfo) error {
	rawObjects := functional.Filter(
		objects,
		func(obj ObjectInfo) RawObjectInfo {
			return RawObjectInfo{
				ID:        obj.ID[:],
				Address:   obj.Addr,
				Transform: obj.Transform,
			}
		},
	)

	return target.Peer.Send(ahmp.SOA_T, RawSOA{
		SenderSessionID: w.WSID[:],
		RecverSessionID: target.SessionID[:],
		Objects:         rawObjects,
	})
}

// sendSOD sends SOD (Shared Object Delete) message to a specific peer.
func (w *World) sendSOD(target ANDPeerSession, objectIDs []uuid.UUID) error {
	rawObjectIDs := functional.Filter(
		objectIDs,
		func(oid uuid.UUID) []byte {
			return oid[:]
		},
	)

	return target.Peer.Send(ahmp.SOD_T, RawSOD{
		SenderSessionID: w.WSID[:],
		RecverSessionID: target.SessionID[:],
		ObjectIDs:       rawObjectIDs,
	})
}
