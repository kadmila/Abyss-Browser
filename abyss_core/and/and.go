package and

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"
	"github.com/kadmila/Abyss-Browser/abyss_core/watchdog"
)

type AND struct {
	eventCh chan abyss.NeighborEvent

	local_hash string

	peers  map[string]abyss.IANDPeer //id hash - peer
	worlds map[uuid.UUID]*ANDWorld   //local session id - world

	stat ANDStatistics

	api_mtx *sync.Mutex
}

func NewAND(local_hash string) *AND {
	return &AND{
		eventCh:    make(chan abyss.NeighborEvent, 4096),
		local_hash: local_hash,
		peers:      make(map[string]abyss.IANDPeer),
		worlds:     make(map[uuid.UUID]*ANDWorld),
		api_mtx:    new(sync.Mutex),
	}
}

func (a *AND) EventChannel() chan abyss.NeighborEvent {
	return a.eventCh
}

func (a *AND) PeerConnected(peer abyss.IANDPeer) abyss.ANDERROR {
	//debug
	watchdog.Info("appCall::PeerConnected " + peer.ID())

	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	a.stat.B(0)

	a.peers[peer.ID()] = peer

	for _, world := range a.worlds {
		a.stat.B(1)
		world.PeerConnected(peer)
	}
	return 0
}

func (a *AND) PeerClose(peer abyss.IANDPeer) abyss.ANDERROR {
	//debug
	watchdog.Info("appCall::PeerClose " + peer.ID())

	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	a.stat.B(2)

	for _, world := range a.worlds {
		a.stat.B(3)
		world.RemovePeer(peer)
	}
	delete(a.peers, peer.ID())
	return 0
}

func (a *AND) OpenWorld(local_session_id uuid.UUID, world_url string) abyss.ANDERROR {
	//debug
	watchdog.Info("appCall::OpenWorld " + local_session_id.String())

	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	a.stat.B(4)

	world := NewWorldOpen(a, a.local_hash, local_session_id, world_url, a.peers, a.eventCh)
	a.worlds[world.lsid] = world
	return 0
}

func (a *AND) JoinWorld(local_session_id uuid.UUID, abyss_url *aurl.AURL) abyss.ANDERROR {
	//debug
	watchdog.Info("appCall::JoinWorld " + local_session_id.String() + " " + abyss_url.Hash)

	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	a.stat.B(5)

	world := NewWorldJoin(a, a.local_hash, local_session_id, abyss_url, a.peers, a.eventCh) //should immediate return
	a.worlds[world.lsid] = world
	return 0
}

func (a *AND) AcceptSession(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession) abyss.ANDERROR {
	//debug
	watchdog.Info("appCall::AcceptSession " + local_session_id.String() + " " + peer_session.PeerSessionID.String())

	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(6)
		return 0
	}
	a.stat.B(7)

	world.AcceptSession(peer_session)
	return 0
}

func (a *AND) DeclineSession(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, code int, message string) abyss.ANDERROR {
	//debug
	watchdog.Info("appCall::DeclineSession " + local_session_id.String() + " " + peer_session.PeerSessionID.String())

	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(8)
		return 0
	}
	a.stat.B(9)

	world.DeclineSession(peer_session, code, message)
	return 0
}

func (a *AND) CloseWorld(local_session_id uuid.UUID) abyss.ANDERROR {
	//debug
	watchdog.Info("appCall::CloseWorld " + local_session_id.String())

	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(10)
		return 0
	}
	a.stat.B(11)

	world.Close()
	delete(a.worlds, local_session_id)
	return 0
}

func (a *AND) TimerExpire(local_session_id uuid.UUID) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(12)
		return 0
	}
	a.stat.B(13)

	world.TimerExpire()
	return 0
}

func (a *AND) JN(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, timestamp time.Time) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(14)
		return 0
	}
	a.stat.B(15)

	world.JN(peer_session, timestamp)
	return 0
}
func (a *AND) JOK(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, timestamp time.Time, world_url string, member_infos []abyss.ANDFullPeerSessionIdentity) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(16)
		return 0
	}
	a.stat.B(17)

	world.JOK(peer_session, timestamp, world_url, member_infos)
	return 0
}
func (a *AND) JDN(local_session_id uuid.UUID, peer abyss.IANDPeer, code int, message string) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(18)
		return 0
	}
	a.stat.B(19)

	world.JDN(peer, code, message) // after, world should be manually closed from application-side.
	return 0
}
func (a *AND) JNI(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, member_info abyss.ANDFullPeerSessionIdentity) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(20)
		return 0
	}
	a.stat.B(21)

	world.JNI(peer_session, member_info)
	return 0
}
func (a *AND) MEM(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, timestamp time.Time) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(22)
		return 0
	}
	a.stat.B(23)

	world.MEM(peer_session, timestamp)
	return 0
}
func (a *AND) SJN(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, member_infos []abyss.ANDPeerSessionIdentity) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(24)
		return 0
	}
	a.stat.B(25)

	world.SJN(peer_session, member_infos)
	return 0
}
func (a *AND) CRR(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, member_infos []abyss.ANDPeerSessionIdentity) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(26)
		return 0
	}
	a.stat.B(27)

	world.CRR(peer_session, member_infos)
	return 0
}
func (a *AND) RST(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, message string) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	watchdog.Info("RST: " + message)

	if local_session_id != uuid.Nil {
		world, ok := a.worlds[local_session_id]
		if !ok {
			a.stat.B(28)
			return 0
		}
		a.stat.B(29)

		world.RST(peer_session)
	} else {
		a.stat.B(30)

		for _, world := range a.worlds {
			a.stat.B(31)
			world.RST(peer_session)
		}
	}
	return 0
}

func (a *AND) SOA(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, objects []abyss.ObjectInfo) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(32)
		return 0
	}
	a.stat.B(33)

	world.SOA(peer_session, objects)
	return 0
}
func (a *AND) SOD(local_session_id uuid.UUID, peer_session abyss.ANDPeerSession, objectIDs []uuid.UUID) abyss.ANDERROR {
	a.api_mtx.Lock()
	defer a.api_mtx.Unlock()

	world, ok := a.worlds[local_session_id]
	if !ok {
		a.stat.B(34)
		return 0
	}
	a.stat.B(35)

	world.SOD(peer_session, objectIDs)
	return 0
}

func (a *AND) Statistics() string {
	return a.stat.String()
}
