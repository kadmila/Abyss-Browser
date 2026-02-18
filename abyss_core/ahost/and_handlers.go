package ahost

import (
	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
)

func (h *AbyssHost) onJN(
	events ds.Queue,
	JN *and.JN,
	peer_session and.ANDPeerSession,
	participating_worlds map[uuid.UUID]*and.World,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// JN forces appending participating_worlds.
	world, ok := h.exposed_worlds[JN.Path]
	if !ok {
		return and.SendJDN_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
	}

	if _, ok := participating_worlds[world.SessionID()]; !ok {
		participating_worlds[world.SessionID()] = world
		world.PeerConnected(events, peer_session.Peer)
		world.CheckSanity()
		h.handleANDEvent(events)
	}

	world.JN(events, peer_session, JN.TimeStamp)
	world.CheckSanity()
	h.handleANDEvent(events)
	return nil
}

func (h *AbyssHost) onJOK(
	events ds.Queue,
	JOK *and.JOK,
	peer_session and.ANDPeerSession,
	participating_worlds map[uuid.UUID]*and.World,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := participating_worlds[JOK.RecverSessionID]
	if !ok {
		return and.SendRST_UnexpectedArbitraryWorld(peer_session, JOK.RecverSessionID)
	}
	world.JOK(events, peer_session, JOK.TimeStamp, JOK.URL, JOK.Neighbors)
	world.CheckSanity()
	h.handleANDEvent(events)
	return nil
}

func (h *AbyssHost) onJDN(
	events ds.Queue,
	JDN *and.JDN,
	peer ani.IAbyssPeer,
	participating_worlds map[uuid.UUID]*and.World,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := participating_worlds[JDN.RecverSessionID]
	if !ok {
		return nil
	}
	world.JDN(events, peer, JDN.Code, JDN.Message)
	world.CheckSanity()
	h.handleANDEvent(events)
	return nil
}

func (h *AbyssHost) onJNI(
	events ds.Queue,
	JNI *and.JNI,
	peer_session and.ANDPeerSession,
	participating_worlds map[uuid.UUID]*and.World,
	joiner_info and.ANDFullPeerSessionInfo,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := participating_worlds[JNI.RecverSessionID]
	if !ok {
		return and.SendRST_UnexpectedArbitraryWorld(peer_session, JNI.RecverSessionID)
	}
	world.JNI(events, peer_session, joiner_info)
	world.CheckSanity()
	h.handleANDEvent(events)
	return nil
}

func (h *AbyssHost) onMEM(
	events ds.Queue,
	MEM *and.MEM,
	peer_session and.ANDPeerSession,
	participating_worlds map[uuid.UUID]*and.World,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// MEM forces appending participating_worlds.
	world, ok := h.worlds[MEM.RecverSessionID]
	if !ok {
		return and.SendRST_UnexpectedArbitraryWorld(peer_session, MEM.RecverSessionID)
	}

	if _, ok := participating_worlds[MEM.RecverSessionID]; !ok {
		participating_worlds[world.SessionID()] = world
		world.PeerConnected(events, peer_session.Peer)
		world.CheckSanity()
		h.handleANDEvent(events)
	}

	world.MEM(events, peer_session, MEM.TimeStamp)
	world.CheckSanity()
	h.handleANDEvent(events)
	return nil
}

func (h *AbyssHost) onRST(
	events ds.Queue,
	RST *and.RST,
	peer_session and.ANDPeerSession,
	participating_worlds map[uuid.UUID]*and.World,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := participating_worlds[RST.RecverSessionID]
	if !ok {
		return nil // must be no reflection
	}
	world.RST(events, peer_session)
	world.CheckSanity()
	h.handleANDEvent(events)
	return nil
}

func (h *AbyssHost) onSOA(
	events ds.Queue,
	SOA *and.SOA,
	peer_session and.ANDPeerSession,
	participating_worlds map[uuid.UUID]*and.World,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := participating_worlds[SOA.RecverSessionID]
	if !ok {
		return and.SendRST_UnexpectedArbitraryWorld(peer_session, SOA.RecverSessionID)
	}
	world.SOA(events, peer_session, SOA.Objects)
	h.handleANDEvent(events)
	return nil
}

func (h *AbyssHost) onSOD(
	events ds.Queue,
	SOD *and.SOD,
	peer_session and.ANDPeerSession,
	participating_worlds map[uuid.UUID]*and.World,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := participating_worlds[SOD.RecverSessionID]
	if !ok {
		return and.SendRST_UnexpectedArbitraryWorld(peer_session, SOD.RecverSessionID)
	}
	world.SOD(events, peer_session, SOD.ObjectIDs)
	h.handleANDEvent(events)
	return nil
}
