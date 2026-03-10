package ahost

import (
	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

func (h *AbyssHost) onJN(
	JN *and.JN,
	peer ani.IAbyssPeer,
) error {
	peer_session := and.ANDPeerSession{Peer: peer, SessionID: JN.SenderSessionID}
	world, ok := h.getWorldByPath(JN.Path)
	if !ok {
		and.SendRST(peer_session, uuid.Nil, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
		return nil
	}
	world.JN(peer_session)
	return nil
}

func (h *AbyssHost) ahmpWorldPrep(peer ani.IAbyssPeer, receiver_wsid uuid.UUID) (*and.World, and.ANDPeerSession, bool) {
	peer_session := and.ANDPeerSession{Peer: peer, SessionID: receiver_wsid}
	world, ok := h.getWorld(receiver_wsid)
	if !ok {
		and.SendRST(peer_session, receiver_wsid, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
		return nil, and.ANDPeerSession{}, false
	}
	return world, peer_session, true
}

func (h *AbyssHost) onJOK(
	JOK *and.JOK,
	peer ani.IAbyssPeer,
) error {
	world, peer_session, ok := h.ahmpWorldPrep(peer, JOK.RecverSessionID)
	if !ok {
		return nil
	}
	world.JOK(peer_session, JOK.URL, JOK.Neighbors)
	return nil
}

func (h *AbyssHost) onJNI(
	JNI *and.JNI,
	peer ani.IAbyssPeer,
) error {
	world, peer_session, ok := h.ahmpWorldPrep(peer, JNI.RecverSessionID)
	if !ok {
		return nil
	}
	world.JNI(peer_session, JNI.Neighbor, JNI.Fwd)
	return nil
}

func (h *AbyssHost) onMEM(
	MEM *and.MEM,
	peer ani.IAbyssPeer,
) error {
	world, peer_session, ok := h.ahmpWorldPrep(peer, MEM.RecverSessionID)
	if !ok {
		return nil
	}
	world.MEM(peer_session)
	return nil
}

func (h *AbyssHost) onSJN(
	SJN *and.SJN,
	peer ani.IAbyssPeer,
) error {
	world, peer_session, ok := h.ahmpWorldPrep(peer, SJN.RecverSessionID)
	if !ok {
		return nil
	}
	world.SJN(peer_session, SJN.MemberInfos)
	return nil
}

func (h *AbyssHost) onCRR(
	CRR *and.CRR,
	peer ani.IAbyssPeer,
) error {
	world, peer_session, ok := h.ahmpWorldPrep(peer, CRR.RecverSessionID)
	if !ok {
		return nil
	}
	world.CRR(peer_session, CRR.MemberInfos)
	return nil
}

func (h *AbyssHost) onRST(
	RST *and.RST,
	peer ani.IAbyssPeer,
) error {
	world, peer_session, ok := h.ahmpWorldPrep(peer, RST.RecverSessionID)
	if !ok {
		return nil
	}
	world.RST(peer_session)
	return nil
}

func (h *AbyssHost) onSOA(
	SOA *and.SOA,
	peer ani.IAbyssPeer,
) error {
	world, peer_session, ok := h.ahmpWorldPrep(peer, SOA.RecverSessionID)
	if !ok {
		return nil
	}
	world.SOA(peer_session, SOA.Objects)
	return nil
}

func (h *AbyssHost) onSOD(
	SOD *and.SOD,
	peer ani.IAbyssPeer,
) error {
	world, peer_session, ok := h.ahmpWorldPrep(peer, SOD.RecverSessionID)
	if !ok {
		return nil
	}
	world.SOD(peer_session, SOD.ObjectIDs)
	return nil
}
