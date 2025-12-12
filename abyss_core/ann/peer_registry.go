package ann

import (
	"crypto/sha3"
	"crypto/x509"
	"net"
	"net/netip"
	"sync"

	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/waiter"
)

// AbyssPeerRegistry ensures only one connection exists with a peer.
type AbyssPeerRegistry struct {
	mtx         sync.Mutex
	known       map[string]*sec.AbyssPeerIdentity
	waiting     map[string]*waiter.Waiter[*sec.AbyssPeerIdentity]
	dialed      map[string][]netip.Addr
	peer_id_cnt uint64
	connected   map[string]*AbyssPeer
	tls_certs   map[[32]byte]string // for abyst
}

func NewAbyssPeerRegistry() *AbyssPeerRegistry {
	return &AbyssPeerRegistry{}
}

// func (m *AbyssPeerRegistry) Store(key [32]byte, value string) {
// 	m.inner.Store(key, value)
// }
// func (m *AbyssPeerRegistry) Load(key [32]byte) (string, bool) {
// 	value, ok := m.inner.Load(key)
// 	str, ok2 := value.(string)
// 	return str, ok && ok2
// }
// func (m *AbyssPeerRegistry) Delete(key [32]byte) {
// 	m.inner.Delete(key)
// }

// tryClearPeerInternals returns (closing error, is_first)
// This is used to 1) check is abyss peer internals closed,
// 2) if not, mark so, close quic Connection and return result.
// This does not actually cleanup the internals; just marks so.
func tryClearPeerInternals(peer *AbyssPeer) (error, bool) {
	if !peer.is_closed.CompareAndSwap(false, true) {
		return net.ErrClosed, false
	}
	return peer.connection.CloseWithError(AbyssQuicClose, ""), false
}

// reportPeerClose is called from AbyssPeer.
func (n *AbyssPeerRegistry) reportPeerClose(peer *AbyssPeer) error {
	var err error
	var is_first bool
	if err, is_first = tryClearPeerInternals(peer); !is_first {
		return err
	}

	// remove peer from back office.
	n.mtx.Lock()
	defer n.mtx.Unlock()

	delete(n.connected_peers, peer.ID())
	return err
}

func (n *AbyssPeerRegistry) tryAddPrePeerOrClose(peer *AbyssPeer) bool {
	is_added := false

	n.mtx.Lock()

	old_peer, ok := n.connected_peers[peer.ID()]
	if !ok {
		n.connected_peers[peer.ID()] = peer
		n.verified_tls_certs.Store(sha3.Sum256(peer.client_tls_cert.Raw), peer.ID())
		is_added = true
	}

	n.mtx.Unlock()

	if !is_added {
		tryClearPeerInternals(old_peer)
	}
	return is_added
}

func (n *AbyssPeerRegistry) forceAddPrePeer(peer *AbyssPeer) {
	n.mtx.Lock()

	// check if old one exists.
	old_peer, ok := n.connected_peers[peer.ID()]

	n.connected_peers[peer.ID()] = peer
	n.verified_tls_certs.Store(sha3.Sum256(peer.client_tls_cert.Raw), peer.ID())

	n.mtx.Unlock()

	if ok {
		tryClearPeerInternals(old_peer)
	}
}

func hashTlsCertificate(cert *x509.Certificate) [32]byte {
	return sha3.Sum256(cert.Raw)
}
