// ahost (alpha/abyss host) is a revised abyss host implementation of previous host package.
// ahost features better straightforward API interfaces, with significantly enhanced code maintainability.
package ahost

import (
	"context"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

type AbyssHost struct {
	net *ann.AbyssNode
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
	defer h.service_cancelfunc()

	if err := h.net.Listen(); err != nil {
		return err
	}
	go h.net.Serve() // we ignore the return value of Serve()
	// This is somewhat temporary. Although we expect failure of Serve() will be
	// bubbled up to the Accept() call, this is a bit lazy.

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

		go h.servePeer(peer)
	}
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

func (h *AbyssHost) Close() {
	h.service_cancelfunc()
}

//// AbyssNode APIs

func (h *AbyssHost) LocalAddrCandidates() []netip.AddrPort { return h.net.LocalAddrCandidates() }
func (h *AbyssHost) ID() string                            { return h.net.ID() }
func (h *AbyssHost) RootCertificate() string               { return h.net.RootCertificate() }
func (h *AbyssHost) HandshakeKeyCertificate() string       { return h.net.HandshakeKeyCertificate() }
func (h *AbyssHost) IssueTime() time.Time                  { return h.net.IssueTime() }

func (h *AbyssHost) AppendKnownPeer(root_cert string, handshake_key_cert string) error {
	return h.net.AppendKnownPeer(root_cert, handshake_key_cert)
}
func (h *AbyssHost) EraseKnownPeer(id string)                  { h.net.EraseKnownPeer(id) }
func (h *AbyssHost) Dial(id string, addr netip.AddrPort) error { return h.net.Dial(id, addr) }
func (h *AbyssHost) ConfigAbystGateway(config string) error    { return h.net.ConfigAbystGateway(config) }
func (h *AbyssHost) NewAbystClient() (ani.IAbystClient, error) { return h.net.NewAbystClient() }
func (h *AbyssHost) NewCollocatedHttp3Client() (*http.Client, error) {
	return h.net.NewCollocatedHttp3Client()
}

//// World Session APIs

// AcceptWorldSession accepts a peer session request for a world.
// This creates an event queue, calls World.AcceptSession, and processes resulting events.
func (h *AbyssHost) AcceptWorldSession(world *and.World, peer ani.IAbyssPeer, peerSessionID uuid.UUID) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	events := and.NewANDEventQueue()
	peer_session := and.ANDPeerSession{
		Peer:      peer,
		SessionID: peerSessionID,
	}
	world.AcceptSession(events, peer_session)
	h.handleANDEvent(events)
}

// DeclineWorldSession declines a peer session request for a world.
// This creates an event queue, calls World.DeclineSession, and processes resulting events.
func (h *AbyssHost) DeclineWorldSession(world *and.World, peer ani.IAbyssPeer, peerSessionID uuid.UUID, code int, message string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	events := and.NewANDEventQueue()
	peer_session := and.ANDPeerSession{
		Peer:      peer,
		SessionID: peerSessionID,
	}
	world.DeclineSession(events, peer_session, code, message)
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
