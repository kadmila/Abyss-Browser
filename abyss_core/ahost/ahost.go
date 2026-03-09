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
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

type ANDFetchPendingInfo struct {
	world         *and.World
	PeerSessionID uuid.UUID
	fwd           bool
}

type AbyssHost struct {
	net *ann.AbyssNode
	and *and.AND

	service_ctx        context.Context
	service_cancelfunc context.CancelFunc

	mtx                sync.Mutex // Below this are not thread safe.
	peers              map[string]ani.IAbyssPeer
	worlds             map[uuid.UUID]*and.World
	world_path_mapping map[uuid.UUID]string             // inverse of exposed_worlds
	exposed_worlds     map[string]*and.World            // JN path -> world
	and_fetch_pending  map[string][]ANDFetchPendingInfo // PeerID -> entries

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

		peers:              make(map[string]ani.IAbyssPeer),
		worlds:             make(map[uuid.UUID]*and.World),
		world_path_mapping: make(map[uuid.UUID]string),
		exposed_worlds:     make(map[string]*and.World),
		and_fetch_pending:  make(map[string][]ANDFetchPendingInfo),

		event_ch: make(chan any, 1024),
	}, nil
}

func (h *AbyssHost) Bind() error {
	return h.net.Listen()
}

func (h *AbyssHost) Serve() error {
	defer h.service_cancelfunc()

	// AbyssNode serve loop
	serve_done := make(chan error)
	go func() {
		serve_done <- h.net.Serve()
	}()

	// and timer event worker
	accept_err := h.acceptingLoop()
	serve_err := <-serve_done

	close(h.event_ch)
	close_err := h.net.Close()

	return errors.Join(accept_err, serve_err, close_err)
}

// acceptingLoop accepts new connections.
// This returns only when the AbyssNode failed.
// TODO: add waitgroup for servePeer() goroutines.
func (h *AbyssHost) acceptingLoop() error {
	for {
		peer, err := h.net.Accept(h.service_ctx)
		if err != nil {
			if _, ok := err.(*ann.HandshakeError); ok {
				continue // TODO: log handshake errors for diagnosis
			}
			// other errors are fatal.
			return err
		}
		go h.servePeer(peer)
	}
}

func (h *AbyssHost) Close() {
	h.service_cancelfunc()
	h.net.Close()
}

//// AbyssNode APIs

func (h *AbyssHost) LocalAddrCandidates() []netip.AddrPort { return h.net.LocalAddrCandidates() }
func (h *AbyssHost) ID() string                            { return h.net.ID() }
func (h *AbyssHost) RootCertificate() string               { return h.net.RootCertificate() }
func (h *AbyssHost) HandshakeKeyCertificate() string       { return h.net.HandshakeKeyCertificate() }
func (h *AbyssHost) UpdateHandshakeInfo(address_candidates []netip.AddrPort) error {
	return h.net.UpdateHandshakeInfo(address_candidates)
}

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
		h.event_ch <- &EPeerForgot{PeerID: id}
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
	world := h.and.OpenWorld(h.service_ctx, events, world_url)
	h.handleANDEvent(events)

	h.worlds[world.WSID] = world
	return world
}

func (h *AbyssHost) JoinWorld(peer_id string, path string) (*and.World, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	peer, ok := h.peers[peer_id]
	if !ok {
		return nil, errors.New("peer not found")
	}

	world, err := h.and.JoinWorld(h.service_ctx, peer, path)
	if err != nil {
		return nil, err
	}

	h.worlds[world.WSID] = world
	return world, err
}

// CloseWorld closes a world and broadcasts RST to all peers.
// This also cleans up the world from the host's tracking maps.
func (h *AbyssHost) CloseWorld(world *and.World) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// Remove entry from and_fetch_pending
	h.and_fetch_pending = functional.Filter_M_ok(
		h.and_fetch_pending,
		func(pendings []ANDFetchPendingInfo) ([]ANDFetchPendingInfo, bool) {
			remainder := functional.Filter_ok(
				pendings,
				func(e ANDFetchPendingInfo) (ANDFetchPendingInfo, bool) {
					if e.world != world {
						return e, true
					}
					return e, false
				},
			)
			if len(remainder) > 0 {
				return remainder, true
			}
			return remainder, false
		},
	)

	// Remove world from host's worlds and exposed worlds
	delete(h.worlds, world.WSID)
	join_path, ok := h.world_path_mapping[world.WSID]
	if ok {
		delete(h.world_path_mapping, world.WSID)
		delete(h.exposed_worlds, join_path)
	}

	// Destroy the world
	world.Close()
	delete(h.worlds, world.WSID)
}

/// host features

// GetEvent blocks until an event is raised.
// Possible event types are below:
/*
and.EANDWorldEnter
and.EANDSessionReady
and.EANDSessionClose
and.EANDObjectAppend
and.EANDObjectDelete
and.EANDWorldLeave
EPeerConnected
EPeerDisconnected
EPeerFound
EPeerForgot
*/
func (h *AbyssHost) GetEventCh() <-chan any {
	return h.event_ch
}

func (h *AbyssHost) ExposeWorldForJoin(world *and.World, path string) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if !world.IsExposable() {
		return errors.New("This world is under joining procedure, thus not exposable.")
	}

	if _, ok := h.exposed_worlds[path]; ok {
		return errors.New("Path in use")
	}
	if _, ok := h.world_path_mapping[world.WSID]; ok {
		return errors.New("World already exposed to another path")
	}

	h.exposed_worlds[path] = world
	h.world_path_mapping[world.WSID] = path
	return nil
}

func (h *AbyssHost) HideWorld(world *and.World) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	path, ok := h.world_path_mapping[world.WSID]
	if !ok {
		return
	}
	delete(h.world_path_mapping, world.WSID)
	delete(h.exposed_worlds, path)
}

func (h *AbyssHost) getWorld(wsid uuid.UUID) (*and.World, bool) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := h.worlds[wsid]
	return world, ok
}

func (h *AbyssHost) getPendingFetches(peerID string) ([]ANDFetchPendingInfo, bool) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	fetches, ok := h.and_fetch_pending[peerID]
	return fetches, ok
}
