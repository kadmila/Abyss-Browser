package host

import (
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"

	"github.com/google/uuid"
)

type World struct {
	origin       abyss.INeighborDiscovery
	session_id   uuid.UUID
	url          string
	eventChannel chan any
}

func NewWorld(origin abyss.INeighborDiscovery, session_id uuid.UUID, url string) *World {
	return &World{
		origin:       origin,
		session_id:   session_id,
		url:          url,
		eventChannel: make(chan any, 4096),
	}
}

func (w *World) SessionID() uuid.UUID { return w.session_id }
func (w *World) URL() string          { return w.url }
func (w *World) GetEventChannel() chan any {
	return w.eventChannel
}

func (w *World) RaisePeerRequest(peer_session abyss.ANDPeerSession) {
	w.eventChannel <- abyss.EWorldMemberRequest{
		MemberHash: peer_session.Peer.IDHash(),
		Accept: func() {
			w.origin.AcceptSession(w.session_id, peer_session)
		},
		Decline: func(code int, message string) {
			w.origin.DeclineSession(w.session_id, peer_session, code, message)
		},
	}
}
func (w *World) RaisePeerReady(peer_session abyss.ANDPeerSession) {
	w.eventChannel <- abyss.EWorldMemberReady{
		Member: &WorldMember{
			world:       w,
			hash:        peer_session.Peer.IDHash(),
			peerSession: peer_session,
		},
	}
}
func (w *World) RaiseObjectAppend(peer_hash string, objects []abyss.ObjectInfo) {
	w.eventChannel <- abyss.EMemberObjectAppend{
		PeerHash: peer_hash,
		Objects:  objects,
	}
}
func (w *World) RaiseObjectDelete(peer_hash string, objectIDs []uuid.UUID) {
	w.eventChannel <- abyss.EMemberObjectDelete{
		PeerHash:  peer_hash,
		ObjectIDs: objectIDs,
	}
}
func (w *World) RaisePeerLeave(peer_hash string) {
	w.eventChannel <- abyss.EWorldMemberLeave{
		PeerHash: peer_hash,
	}
}
func (w *World) RaiseWorldTerminate() {
	w.eventChannel <- abyss.EWorldTerminate{}
}
