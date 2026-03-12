package ann

import (
	"crypto/x509"
	"net/netip"
	"sync"

	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

// AbyssPeerRegistry ensures only one connection exists with a peer.
// tls_certs entry only exists while the corresponding peer is connected.
type AbyssPeerRegistry struct {
	mtx         sync.Mutex
	known       map[string]*sec.AbyssPeerIdentity
	peer_id_cnt uint64
	connected   map[string]*AbyssPeer
	tls_certs   map[[32]byte]string // for abyst
}

func NewAbyssPeerRegistry() *AbyssPeerRegistry {
	return &AbyssPeerRegistry{
		known:     make(map[string]*sec.AbyssPeerIdentity),
		connected: make(map[string]*AbyssPeer),
		tls_certs: make(map[[32]byte]string),
	}
}

// AddOrUpdatePeerIdentity tries to add or update peer identity.
// It returns true only when the peer identity was newly added.
func (r *AbyssPeerRegistry) AddOrUpdatePeerIdentity(root_cert *x509.Certificate, handshake_info *x509.Certificate) (bool, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	peer_id := root_cert.Issuer.CommonName

	// when there is an old identity, update it and return.
	old_identity, ok := r.known[peer_id]
	if ok {
		return false, old_identity.UpdateHandshakeInfo(handshake_info)
	}

	new_identity, err := sec.NewAbyssPeerIdentity(root_cert, handshake_info)
	if err != nil {
		return false, err
	}
	r.known[peer_id] = new_identity
	return true, nil
}

// TryRemovePeerIdentity removes every information for the peer, and
// Kills everything from the peer.
// We don't delete the peer from dialed or connected,
// as it should be removed by ReportDialTermination and ReportPeerClose.
// However, we signal the connection silently.
func (r *AbyssPeerRegistry) TryRemovePeerIdentity(id string) bool {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	_, did_exist := r.known[id]
	if did_exist {
		delete(r.known, id)
	}

	// For entries of r.connected, we don't directly delete them.
	// Instead, cut the connection and let the client-side Close() call handle it.
	if old_peer, ok := r.connected[id]; ok {
		delete(r.tls_certs, sec.HashTlsCertificate(old_peer.client_tls_cert))
		old_peer.connection.CloseWithError(AbyssQuicClose, "")
	}

	return did_exist
}

type RegistryEntryStatus int

const (
	RE_Redundant RegistryEntryStatus = iota + 1
	RE_UnknownPeer
	RE_OK
)

// GetPeerIdentityIfAcceptable returns error if the dialing is considered redundant,
// or the peer id is unknown.
func (r *AbyssPeerRegistry) GetPeerIdentityIfAcceptable(id string) (*sec.AbyssPeerIdentity, RegistryEntryStatus) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	// Cannot accept if the peer is unknown.
	identity, ok := r.known[id]
	if !ok {
		return nil, RE_UnknownPeer
	}

	// There is no need to accept a connected peer
	if peer, ok := r.connected[id]; ok {
		return peer.AbyssPeerIdentity, RE_Redundant
	}

	return identity, RE_OK
}

// GetPeerIdentityIfDialable behaves like GetPeerIdentityIfAcceptable.
// As there is no occasion where a node binds to multiple ports in same host,
// we only compare IP addresses.
func (r *AbyssPeerRegistry) GetPeerIdentityIfDialable(id string) (*sec.AbyssPeerIdentity, RegistryEntryStatus) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	// Cannot dial if the peer is unknown.
	identity, ok := r.known[id]
	if !ok {
		return nil, RE_UnknownPeer
	}

	// There is no need to dial connected peer
	if _, ok := r.connected[id]; ok {
		return nil, RE_Redundant
	}

	return identity, RE_OK
}

// ReportDialTermination removes entry from m.dialed map, allowing retry.
func (r *AbyssPeerRegistry) ReportDialTermination(identity *sec.AbyssPeerIdentity, addr netip.Addr) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	//TODO
}

// TryCompletingPeer numbers the peer and registers it,
// If there is no existing connection, and the peer is known.
func (r *AbyssPeerRegistry) TryCompletingPeer(peer *AbyssPeer) (*AbyssPeer, RegistryEntryStatus) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	if _, ok := r.known[peer.ID()]; !ok {
		return nil, RE_UnknownPeer
	}

	_, ok := r.connected[peer.ID()]
	if ok {
		return nil, RE_Redundant
	}

	r.peer_id_cnt++
	peer.internal_id = r.peer_id_cnt
	r.connected[peer.ID()] = peer
	r.tls_certs[sec.HashTlsCertificate(peer.client_tls_cert)] = peer.ID()
	return peer, RE_OK
}

// ReportPeerClose is called from AbyssPeer.
func (r *AbyssPeerRegistry) ReportPeerClose(peer *AbyssPeer) error {
	// check if Close() is already called.
	if !peer.is_closed.CompareAndSwap(false, true) {
		return nil
	}

	err := peer.connection.CloseWithError(AbyssQuicClose, "")

	// remove peer from backlog.
	r.mtx.Lock()
	defer r.mtx.Unlock()

	delete(r.connected, peer.ID())
	delete(r.tls_certs, sec.HashTlsCertificate(peer.client_tls_cert))
	return err
}

// GetPeerIdFromTlsCertificate implements ani.IAbystTlsCertChecker interface
func (r *AbyssPeerRegistry) GetPeerIdFromTlsCertificate(abyst_tls_cert *x509.Certificate) (string, bool) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	id, ok := r.tls_certs[sec.HashTlsCertificate(abyst_tls_cert)]
	return id, ok
}

func (r *AbyssPeerRegistry) GetPeer(id string) (*AbyssPeer, bool) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	peer, ok := r.connected[id]
	return peer, ok
}
