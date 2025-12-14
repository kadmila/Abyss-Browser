package ann

import (
	"crypto/x509"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

type dialHistory struct {
	handshake_key_issue_time time.Time
	addresses                []netip.Addr
}

// AbyssPeerRegistry ensures only one connection exists with a peer.
// tls_certs entry only exists while the corresponding peer is connected.
type AbyssPeerRegistry struct {
	mtx         sync.Mutex
	known       map[string]*sec.AbyssPeerIdentity
	dialed      map[string]dialHistory
	peer_id_cnt uint64
	connected   map[string]*AbyssPeer
	tls_certs   map[[32]byte]string // for abyst
}

func NewAbyssPeerRegistry() *AbyssPeerRegistry {
	return &AbyssPeerRegistry{
		known:     make(map[string]*sec.AbyssPeerIdentity),
		dialed:    make(map[string]dialHistory),
		connected: make(map[string]*AbyssPeer),
		tls_certs: make(map[[32]byte]string),
	}
}

func (r *AbyssPeerRegistry) UpdatePeerIdentity(identity *sec.AbyssPeerIdentity) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	// when there is an old identity, replace it and return.
	old_identity, ok := r.known[identity.ID()]
	if ok && old_identity.IssueTime().After(identity.IssueTime()) {
		return
	}

	r.known[identity.ID()] = identity

	// peer identity updated - new handshake key, all old ongoing dials will fail.
	delete(r.dialed, identity.ID())
}

// RemovePeerIdentity removes every information for the peer, and
// Kills everything from the peer.
// We don't delete the peer from dialed or connected,
// as it should be removed by ReportDialTermination and ReportPeerClose.
// However, we signal the connection silently.
func (r *AbyssPeerRegistry) RemovePeerIdentity(id string) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	delete(r.known, id)
	if old_peer, ok := r.connected[id]; ok {
		delete(r.tls_certs, sec.HashTlsCertificate(old_peer.client_tls_cert))
		old_peer.connection.CloseWithError(AbyssQuicClose, "")
	}
}

// GetPeerIdentityIfAcceptable returns error if the dialing is considered redundant,
// or the peer id is unknown.
func (r *AbyssPeerRegistry) GetPeerIdentityIfAcceptable(id string) (*sec.AbyssPeerIdentity, *DialError) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	// Cannot accept if the peer is unknown.
	identity, ok := r.known[id]
	if !ok {
		return nil, &DialError{T: DE_UnknownPeer}
	}

	// There is no need to accept a connected peer
	if peer, ok := r.connected[id]; ok {
		return peer.AbyssPeerIdentity, &DialError{T: DE_Redundant}
	}

	return identity, nil
}

// GetPeerIdentityIfDialable behaves like GetPeerIdentityIfAcceptable.
// As there is no occasion where a node binds to multiple ports in same host,
// we only compare IP addresses.
func (r *AbyssPeerRegistry) GetPeerIdentityIfDialable(id string, addr netip.Addr) (*sec.AbyssPeerIdentity, *DialError) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	// Cannot dial if the peer is unknown.
	identity, ok := r.known[id]
	if !ok {
		return nil, &DialError{T: DE_UnknownPeer}
	}

	// There is no need to dial the same IP address twice.
	history, ok := r.dialed[id]
	if ok {
		for _, v := range history.addresses {
			if v.Compare(addr) != 0 {
				return nil, &DialError{T: DE_Redundant}
			}
		}
	}

	// There is no need to dial connected peer
	if _, ok := r.connected[id]; ok {
		return nil, &DialError{T: DE_Redundant}
	}

	return identity, nil
}

// ReportDialTermination removes entry from m.dialed map, allowing retry.
func (m *AbyssPeerRegistry) ReportDialTermination(identity *sec.AbyssPeerIdentity, addr netip.Addr) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	history, ok := m.dialed[identity.ID()]
	if !ok || !history.handshake_key_issue_time.Equal(identity.IssueTime()) {
		return
	}
	for i, v := range history.addresses {
		if v.Compare(addr) != 0 {
			history.addresses = slices.Delete(history.addresses, i, i+1)
		}
	}
}

// TryCompletingPeer numbers the peer and registers it,
// If there is no existing connection, and the peer is known.
func (n *AbyssPeerRegistry) TryCompletingPeer(peer *AbyssPeer) (*AbyssPeer, *DialError) {
	n.mtx.Lock()
	defer n.mtx.Unlock()

	if _, ok := n.known[peer.ID()]; !ok {
		return nil, &DialError{T: DE_UnknownPeer}
	}

	_, ok := n.connected[peer.ID()]
	if ok {
		return nil, &DialError{T: DE_Redundant}
	}

	n.peer_id_cnt++
	peer.internal_id = n.peer_id_cnt
	n.connected[peer.ID()] = peer
	n.tls_certs[sec.HashTlsCertificate(peer.client_tls_cert)] = peer.ID()
	return peer, nil
}

// ReportPeerClose is called from AbyssPeer.
func (n *AbyssPeerRegistry) ReportPeerClose(peer *AbyssPeer) error {
	// check if Close() is already called.
	if !peer.is_closed.CompareAndSwap(false, true) {
		return nil
	}

	err := peer.connection.CloseWithError(AbyssQuicClose, "")

	// remove peer from backlog.
	n.mtx.Lock()
	defer n.mtx.Unlock()

	delete(n.connected, peer.ID())
	delete(n.tls_certs, sec.HashTlsCertificate(peer.client_tls_cert))
	return err
}

// GetPeerIdFromTlsCertificate implements ani.IAbystTlsCertChecker interface
func (r *AbyssPeerRegistry) GetPeerIdFromTlsCertificate(abyst_tls_cert *x509.Certificate) (string, bool) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	id, ok := r.tls_certs[sec.HashTlsCertificate(abyst_tls_cert)]
	return id, ok
}
