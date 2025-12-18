// and (Abyss Neighbor Discovery) algorithm defines worlds in abyss network.
// AND is the algorithm provider
// A World is created by OpenWorld or JoinWorld call.
// Within a world, algorithm pushes events into the shared AND event queue.
// World algorithm may request a peer through event.
// On host-side event consumer prvides peer (by dialing or just giving connected peer).
// When a peer closes, the host calls PeerClose() to each world that references the peer.
// By this way, the host has full control over peer references.
package and

import (
	"net/netip"

	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/watchdog"
)

type AND struct {
	local_id string
	eventCh  chan IANDEvent
}

func NewAND(local_id string) *AND {
	return &AND{
		local_id: local_id,
		eventCh:  make(chan IANDEvent, 1024),
	}
}

func (a *AND) EventChannel() <-chan IANDEvent {
	return a.eventCh
}

func (a *AND) OpenWorld(world_url string) *World {
	watchdog.Info("appCall::OpenWorld " + world_url)

	return newWorld_Open(a, world_url)
}

func (a *AND) JoinWorld(target ani.IAbyssPeer, target_addrs []netip.AddrPort, path string) (*World, error) {
	watchdog.Info("appCall::JoinWorld " + target.ID() + " " + path)

	return NewWorld_Join(a, target, target_addrs, path) //should immediate return
}
