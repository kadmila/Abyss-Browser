// ahost (alpha/abyss host) is a revised abyss host implementation of previous host package.
// ahost features better straightforward API interfaces, with significantly enhanced code maintainability.
package ahost

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

type AbyssHost struct {
	net ani.IAbyssNode
	and *and.AND

	service_ctx        context.Context
	service_cancelfunc context.CancelFunc

	mtx                       sync.Mutex
	worlds                    map[uuid.UUID]*and.World
	world_path_mapping        map[uuid.UUID]string  // inverse of exposed_worlds
	exposed_worlds            map[string]*and.World // JN path -> world
	peer_participating_worlds map[string]map[uuid.UUID]*and.World
	peers                     map[string]ani.IAbyssPeer
	address_candidates        map[string][]netip.AddrPort

	event_ch chan any
}

func NewAbyssHost(root_key sec.PrivateKey) (*AbyssHost, error) {
	node, err := ann.NewAbyssNode(root_key)
	if err != nil {
		return nil, err
	}
	service_ctx, service_cancelfunc := context.WithCancel(context.Background())
	return &AbyssHost{
		net: node,
		and: and.NewAND(node.ID()),

		service_ctx:        service_ctx,
		service_cancelfunc: service_cancelfunc,

		worlds:                    make(map[uuid.UUID]*and.World),
		world_path_mapping:        make(map[uuid.UUID]string),
		exposed_worlds:            make(map[string]*and.World),
		peer_participating_worlds: make(map[string]map[uuid.UUID]*and.World),
		peers:                     make(map[string]ani.IAbyssPeer),
		address_candidates:        make(map[string][]netip.AddrPort),

		event_ch: make(chan any, 1024),
	}, nil
}

func (h *AbyssHost) Main() error {
	err := h.net.Listen()
	if err != nil {
		return err
	}
	node_done := make(chan error)
	go func() {
		node_done <- h.net.Serve()
	}()

	for {
		peer, err := h.net.Accept(h.service_ctx)
		if errors.Is(err, context.Canceled) {
			break
		}

		go func() {
			h.servePeer(peer)
			// TODO: handle error
		}()
	}

	<-node_done
	return nil
}

func (h *AbyssHost) ExposeWorldForJoin(world *and.World, path string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	h.world_path_mapping[world.SessionID()] = path
	h.exposed_worlds[path] = world
}

// GetEvent blocks until an event is raised.
// Possible event types are below:
/*
and.EANDWorldEnter
and.EANDSessionRequest
and.EANDSessionReady
and.EANDSessionClose
and.EANDObjectAppend
and.EANDObjectDelete
and.EANDWorldLeave
EPeerConnected
EPeerDisconnected
*/
func (h *AbyssHost) GetEvent() (any, error) {
	return nil, nil
}
