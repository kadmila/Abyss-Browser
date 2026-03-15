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
	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/infchan"
)

type ANDFetchPendingInfo struct {
	world         *and.World
	PeerSessionID uuid.UUID
	fwd           bool
}

type AbyssHost struct {
	net *ann.AbyssNode

	service_ctx        context.Context
	service_cancelfunc context.CancelFunc

	mtx                sync.Mutex // Below this are not thread safe.
	worlds             map[uuid.UUID]*and.World
	world_path_mapping map[uuid.UUID]string  // inverse of exposed_worlds
	exposed_worlds     map[string]*and.World // JN path -> world
	peer_fetcher       *PeerFetcher

	event_ch *infchan.InfiniteChan[any]
}

func NewAbyssHost(root_key sec.PrivateKey) (*AbyssHost, error) {
	node, err := ann.NewAbyssNode(root_key)
	if err != nil {
		return nil, err
	}
	service_ctx, service_cancelfunc := context.WithCancel(context.Background())
	result := &AbyssHost{
		net: node,

		service_ctx:        service_ctx,
		service_cancelfunc: service_cancelfunc,

		worlds:             make(map[uuid.UUID]*and.World),
		world_path_mapping: make(map[uuid.UUID]string),
		exposed_worlds:     make(map[string]*and.World),

		event_ch: infchan.NewInfiniteChan[any](512),
	}
	result.peer_fetcher = NewPeerFetcher(service_ctx, result.ANDDial)

	return result, nil
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

	close(h.event_ch.In)
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
	peer_id, ok, err := h.net.AppendKnownPeer(root_cert, handshake_info_cert)
	if ok {
		h.event_ch.In <- &EPeerFound{PeerID: peer_id}
	}
	return err
}
func (h *AbyssHost) AppendKnownPeerDer(root_cert_der []byte, handshake_info_cert_der []byte) error {
	peer_id, ok, err := h.net.AppendKnownPeerDer(root_cert_der, handshake_info_cert_der)
	if ok {
		h.event_ch.In <- &EPeerFound{PeerID: peer_id}
	}
	return err
}
func (h *AbyssHost) EraseKnownPeer(id string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if h.net.EraseKnownPeer(id) {
		h.event_ch.In <- &EPeerForgot{PeerID: id}
	}
}
func (h *AbyssHost) Dial(id string) error                   { return h.net.Dial(id) }
func (h *AbyssHost) ConfigAbystGateway(config string) error { return h.net.ConfigAbystGateway(config) }
func (h *AbyssHost) NewAbystClient() *abyst.AbystClient     { return h.net.NewAbystClient() }
func (h *AbyssHost) NewCollocatedHttp3Client() *http.Client {
	return h.net.NewCollocatedHttp3Client()
}
func (h *AbyssHost) ANDDial(info and.ANDFullPeerSessionInfo) {
	h.AppendKnownPeerDer(info.RootCertificateDer, info.HandshakeKeyCertificateDer)
	h.net.Dial(info.PeerID)
}

//// AND APIs

func (h *AbyssHost) OpenWorld(world_url string) (*and.World, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, err := and.NewWorld_Open(
		h.peer_fetcher,
		h.event_ch,
		h.net.ID(),
		world_url,
	)
	if err != nil {
		return nil, err
	}

	h.worlds[world.WSID] = world
	return world, nil
}

func (h *AbyssHost) JoinWorld(peer_id string, path string) (*and.World, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	peer, ok := h.peer_fetcher.GetPeer(peer_id)
	if !ok {
		return nil, errors.New("peer not found")
	}

	world, err := and.NewWorld_Join(
		h.peer_fetcher,
		h.event_ch,
		h.net.ID(),
		peer,
		path,
	)
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

	// Remove pending fetches for the world; This is not perfect
	h.peer_fetcher.WorldClose(world)

	// Remove world from host's worlds and exposed worlds
	delete(h.worlds, world.WSID)
	join_path, ok := h.world_path_mapping[world.WSID]
	if ok {
		delete(h.world_path_mapping, world.WSID)
		delete(h.exposed_worlds, join_path)
	}

	// Destroy the world
	world.Close()
}

func (h *AbyssHost) getWorldByPath(path string) (*and.World, bool) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := h.exposed_worlds[path]
	return world, ok
}

func (h *AbyssHost) getWorld(wsid uuid.UUID) (*and.World, bool) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	world, ok := h.worlds[wsid]
	return world, ok
}

// propagatePeerClose is a quick and dirty approach for dead peer handling in AND.
// This should be replaced with PeerFetcher.RemovePeer().
func (h *AbyssHost) propagatePeerClose(peerID string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	for _, world := range h.worlds {
		world.Disconnect(peerID)
	}
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
	return h.event_ch.Out
}

func (h *AbyssHost) ExposeWorldForJoin(world *and.World, path string) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if !world.IsActive() {
		return errors.New("Inactive world cannot be exposed for join")
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
