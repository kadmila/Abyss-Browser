package host

import (
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"

	"github.com/google/uuid"
)

type WorldMember struct {
	world       *World
	hash        string
	peerSession abyss.ANDPeerSession
}

func (p *WorldMember) Hash() string {
	return p.hash
}
func (p *WorldMember) SessionID() uuid.UUID {
	return p.peerSession.PeerSessionID
}
func (p *WorldMember) AppendObjects(objects []abyss.ObjectInfo) bool {
	return p.peerSession.Peer.TrySendSOA(p.world.session_id, p.peerSession.PeerSessionID, objects)
}
func (p *WorldMember) DeleteObjects(objectIDs []uuid.UUID) bool {
	return p.peerSession.Peer.TrySendSOD(p.world.session_id, p.peerSession.PeerSessionID, objectIDs)
}
