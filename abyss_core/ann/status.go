package ann

import (
	"net/netip"
	"sync"

	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

// PeerStatusMap helps avoiding redundant dials,
// but it may still allow some redundancy.
type PeerStatusMap struct {
	mtx sync.Mutex

	known     map[string]*sec.AbyssPeerIdentity
	dialed    map[string][]*netip.AddrPort
	connected map[string]bool
}

func MakePeerStatusMap() PeerStatusMap {
	return PeerStatusMap{
		known:     make(map[string]*sec.AbyssPeerIdentity),
		dialed:    make(map[string][]*netip.AddrPort),
		connected: make(map[string]bool),
	}
}

func (m *PeerStatusMap) UpdatePeerInformation(identity *sec.AbyssPeerIdentity) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	old_identity, ok := m.known[identity.ID()]
	if ok && old_identity.IssueTime().After(identity.IssueTime()) {
		return
	}

	m.known[identity.ID()] = identity

	// peer information updated - new handshake key, all old ongoing dials and connections will fail.
	delete(m.dialed, identity.ID())
	delete(m.connected, identity.ID())
}

// TryAppendDialingAndGetIdentity returns (nil, false) if the dialing is considered redundant,
// or the peer id is unknown.
func (m *PeerStatusMap) TryAppendDialingAndGetIdentity(id string, addr *netip.AddrPort) (*sec.AbyssPeerIdentity, bool) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Dial not required if connected.
	_, ok := m.connected[id]
	if ok {
		return nil, false
	}

	// Cannot dial if the peer is unknown
	identity, ok := m.known[id]
	if !ok {
		return nil, false
	}

	dialed, ok := m.dialed[id]
	if ok {

	}

	return nil, false
}
