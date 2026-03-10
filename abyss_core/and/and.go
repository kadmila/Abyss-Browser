// and (Abyss Neighbor Discovery) algorithm defines worlds in abyss network.
// A World is created by OpenWorld or JoinWorld call on AND, which is the algorithm provider.
// Calling world writes back events synchronously.
// World algorithm may request a peer through event.
// On host-side event consumer prvides peer (by dialing or just giving connected peer).
// When a peer closes, the host calls PeerClose() to each world that references the peer.
// By this way, the host has full control over peer references.
// package and

// import (
// 	"context"

// 	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
// 	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
// 	"github.com/kadmila/Abyss-Browser/abyss_core/watchdog"
// )

// type AND struct {
// 	local_id string
// }

// func NewAND(local_id string) *AND {
// 	return &AND{
// 		local_id: local_id,
// 	}
// }

// func (a *AND) OpenWorld(ctx context.Context, events ds.Queue, world_url string) *World {
// 	watchdog.Info("appCall::OpenWorld " + world_url)

// 	return newWorld_Open(ctx, events, a, world_url)
// }

// func (a *AND) JoinWorld(ctx context.Context, target ani.IAbyssPeer, path string) (*World, error) {
// 	watchdog.Info("appCall::JoinWorld " + target.ID() + " " + path)

// 	return newWorld_Join(ctx, a, target, path) //should immediate return
// }
