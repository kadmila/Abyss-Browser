// ahost (alpha/abyss host) is a revised abyss host implementation of previous host package.
// ahost features better straightforward API interfaces, with significantly enhanced code maintainability.
package ahost

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sync"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/abyst"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
)

type AbyssHost struct {
	net         *ann.AbyssNode
	and         *and.AND
	timer_queue *worldTimerQueue

	service_ctx        context.Context
	service_cancelfunc context.CancelFunc

	mtx                       sync.Mutex
	worlds                    map[uuid.UUID]*and.World
	world_path_mapping        map[uuid.UUID]string  // inverse of exposed_worlds
	exposed_worlds            map[string]*and.World // JN path -> world
	peer_participating_worlds map[string]map[uuid.UUID]*and.World
	peers                     map[string]ani.IAbyssPeer
	requested_peers           map[string]map[uuid.UUID]*and.World // EANDPeerRequest origins

	event_ch chan any
}

func NewAbyssHost(root_key sec.PrivateKey) (*AbyssHost, error) {
	node, err := ann.NewAbyssNode(root_key)
	if err != nil {
		return nil, err
	}
	service_ctx, service_cancelfunc := context.WithCancel(context.Background())
	return &AbyssHost{
		net:         node,
		and:         and.NewAND(node.ID()),
		timer_queue: newWorldTimerQueue(),

		service_ctx:        service_ctx,
		service_cancelfunc: service_cancelfunc,

		worlds:                    make(map[uuid.UUID]*and.World),
		world_path_mapping:        make(map[uuid.UUID]string),
		exposed_worlds:            make(map[string]*and.World),
		peer_participating_worlds: make(map[string]map[uuid.UUID]*and.World),
		peers:                     make(map[string]ani.IAbyssPeer),
		requested_peers:           make(map[string]map[uuid.UUID]*and.World),

		event_ch: make(chan any, 1024),
	}, nil
}

func (h *AbyssHost) Bind() error {
	return h.net.Listen()
}

func (h *AbyssHost) Serve() error {
	defer h.service_cancelfunc()

	go h.net.Serve() // we ignore the return value of Serve()
	// This is somewhat temporary. Although we expect failure of Serve() will be
	// bubbled up to the Accept() call, this is a bit lazy.

	// and timer event worker
	go func() {
		events := ds.MakeQueue()
		for {
			wsid, err := h.timer_queue.Wait(h.service_ctx)
			if err != nil {
				return
			}

			h.mtx.Lock()
			world, ok := h.worlds[wsid]
			if ok {
				world.TimerExpire(events)
				world.CheckSanity()
				h.handleANDEvent(events)
			}
			h.mtx.Unlock()
		}
	}()

	for {
		peer, err := h.net.Accept(h.service_ctx)
		if err != nil {
			if _, ok := err.(*ann.HandshakeError); ok {
				continue // TODO: log handshake errors for diagnosis
			}
			// other errors are fatal.
			close(h.event_ch)
			return err
		}

		h.mtx.Lock()
		h.peers[peer.ID()] = peer
		h.event_ch <- &EPeerConnected{PeerID: peer.ID()}

		participating_worlds := make(map[uuid.UUID]*and.World)
		h.peer_participating_worlds[peer.ID()] = participating_worlds

		request_note, ok := h.requested_peers[peer.ID()]
		if ok {
			events := ds.MakeQueue()
			for _, world := range request_note {
				participating_worlds[world.SessionID()] = world
				world.PeerConnected(events, peer)
				world.CheckSanity()
				h.handleANDEvent(events)
			}
			delete(h.requested_peers, peer.ID())
		}
		h.mtx.Unlock()

		go h.servePeer(peer, participating_worlds)
	}
}

func (h *AbyssHost) Close() {
	h.service_cancelfunc()
}

//// AbyssNode APIs

func (h *AbyssHost) LocalAddrCandidates() []netip.AddrPort { return h.net.LocalAddrCandidates() }
func (h *AbyssHost) ID() string                            { return h.net.ID() }
func (h *AbyssHost) RootCertificate() string               { return h.net.RootCertificate() }
func (h *AbyssHost) HandshakeKeyCertificate() string       { return h.net.HandshakeKeyCertificate() }

func (h *AbyssHost) AppendKnownPeer(root_cert string, handshake_info_cert string) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	peer_id, ok, err := h.net.AppendKnownPeer(root_cert, handshake_info_cert)
	if ok {
		h.event_ch <- &EPeerFound{PeerID: peer_id}
	}

	return err
}
func (h *AbyssHost) EraseKnownPeer(id string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if h.net.EraseKnownPeer(id) {
		h.event_ch <- EPeerForgot{PeerID: id}
	}
}
func (h *AbyssHost) Dial(id string) error                   { return h.net.Dial(id) }
func (h *AbyssHost) ConfigAbystGateway(config string) error { return h.net.ConfigAbystGateway(config) }
func (h *AbyssHost) NewAbystClient() *abyst.AbystClient     { return h.net.NewAbystClient() }
func (h *AbyssHost) NewCollocatedHttp3Client() *http.Client {
	return h.net.NewCollocatedHttp3Client()
}

//// AND APIs

func (h *AbyssHost) OpenWorld(world_url string) *and.World {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	events := ds.MakeQueue()
	result := h.and.OpenWorld(events, world_url)
	h.handleANDEvent(events)

	return result
}

func (h *AbyssHost) JoinWorld(peer_id string, path string) (*and.World, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	peer, ok := h.peers[peer_id]
	if !ok {
		return nil, errors.New("peer not found")
	}

	result, err := h.and.JoinWorld(peer, path)
	if err != nil {
		return result, err
	}

	// JoinWorld forces the join target partcipates in my local AND world
	h.peer_participating_worlds[peer_id][result.SessionID()] = result
	// don't call world.PeerConnected, as the join target is handled specially.

	return result, err
}

// AcceptWorldSession accepts a peer session request for a world.
// This creates an event queue, calls World.AcceptSession, and processes resulting events.
func (h *AbyssHost) AcceptWorldSession(world *and.World, peer_id string, peerSessionID uuid.UUID) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	events := ds.MakeQueue()
	peer_session_identity := and.ANDPeerSessionIdentity{
		PeerID:    peer_id,
		SessionID: peerSessionID,
	}
	world.AcceptSession(events, peer_session_identity)
	world.CheckSanity()
	h.handleANDEvent(events)
}

// DeclineWorldSession declines a peer session request for a world.
// This creates an event queue, calls World.DeclineSession, and processes resulting events.
func (h *AbyssHost) DeclineWorldSession(world *and.World, peer_id string, peerSessionID uuid.UUID, code int, message string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	events := ds.MakeQueue()
	peer_session_identity := and.ANDPeerSessionIdentity{
		PeerID:    peer_id,
		SessionID: peerSessionID,
	}
	world.DeclineSession(events, peer_session_identity, code, message)
	world.CheckSanity()
	h.handleANDEvent(events)
}

// CloseWorld closes a world and broadcasts RST to all peers.
// This also cleans up the world from the host's tracking maps.
func (h *AbyssHost) CloseWorld(world *and.World) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world.Close()

	// Clean up world from host's tracking maps
	world_lsid := world.SessionID()

	// Remove world from all peers' participating worlds
	remaining_peers := world.Peers()
	for _, peer := range remaining_peers {
		delete(h.peer_participating_worlds[peer.ID()], world_lsid)
	}

	delete(h.worlds, world_lsid)
	join_path, ok := h.world_path_mapping[world_lsid]
	if ok {
		delete(h.world_path_mapping, world_lsid)
		delete(h.exposed_worlds, join_path)
	}
}

// WorldObjectAppend sends SOA message to the specified peers in the world.
func (h *AbyssHost) WorldObjectAppend(world *and.World, peer_session_identities []and.ANDPeerSessionIdentity, objects []and.ObjectInfo) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world.ObjectAppend(peer_session_identities, objects)
}

// WorldObjectDelete sends SOD message to the specified peers in the world.
func (h *AbyssHost) WorldObjectDelete(world *and.World, peer_session_identities []and.ANDPeerSessionIdentity, objectIDs []uuid.UUID) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world.ObjectDelete(peer_session_identities, objectIDs)
}

/// host features

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
func (h *AbyssHost) GetEventCh() <-chan any {
	return h.event_ch
}

func (h *AbyssHost) ExposeWorldForJoin(world *and.World, path string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	other_world, ok := h.exposed_worlds[path]
	if ok {
		delete(h.world_path_mapping, other_world.SessionID())
	}
	h.exposed_worlds[path] = world

	old_path, ok := h.world_path_mapping[world.SessionID()]
	if ok {
		delete(h.exposed_worlds, old_path)
	}
	h.world_path_mapping[world.SessionID()] = path
}

func (h *AbyssHost) HideWorld(world *and.World) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	path, ok := h.world_path_mapping[world.SessionID()]
	if !ok {
		return
	}
	delete(h.world_path_mapping, world.SessionID())
	delete(h.exposed_worlds, path)
}
