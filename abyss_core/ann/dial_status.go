package ann

import (
	"net/netip"
	"sync"

	"slices"

	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

type DialErrorType int

const (
	DE_Redundant DialErrorType = iota + 1
	DE_UnknownPeer
)

type DialError struct {
	T DialErrorType
}

func (e *DialError) Error() string {
	switch e.T {
	case DE_Redundant:
		return "redundant"
	case DE_UnknownPeer:
		return "unknown peer"
	default:
		return "fatal::Memory Corruption"
	}
}

// DialStatusMap helps avoiding redundant dials,
// but it may still allow some redundancy.
// TODO: known peer information expiration.
type DialStatusMap struct {
	mtx sync.Mutex

	known     map[string]*sec.AbyssPeerIdentity
	dialed    map[string][]netip.Addr
	connected map[string]bool
}

func MakePeerStatusMap() DialStatusMap {
	return DialStatusMap{
		known:     make(map[string]*sec.AbyssPeerIdentity),
		dialed:    make(map[string][]netip.Addr),
		connected: make(map[string]bool),
	}
}

func (m *DialStatusMap) UpdatePeerInformation(identity *sec.AbyssPeerIdentity) {
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
// As there is no occasion where a node binds to multiple ports in same host,
// we only compare IP addresses.
func (m *DialStatusMap) TryAppendDialingAndGetIdentity(id string, addr netip.Addr) (*sec.AbyssPeerIdentity, *DialError) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Dial not required if connected.
	_, ok := m.connected[id]
	if ok {
		return nil, &DialError{T: DE_Redundant}
	}

	// Cannot dial if the peer is unknown.
	identity, ok := m.known[id]
	if !ok {
		return nil, &DialError{T: DE_UnknownPeer}
	}

	// There is no need to dial the same IP address twice.
	dialed, ok := m.dialed[id]
	if ok {
		for _, v := range dialed {
			if v.Compare(addr) != 0 {
				return nil, &DialError{T: DE_Redundant}
			}
		}
	}

	return identity, nil
}

// ReportDialFailure removes entry from m.dialed map, allowing retry.
func (m *DialStatusMap) ReportDialFailure(id string, addr netip.Addr) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	dialed, ok := m.dialed[id]
	if !ok {
		return
	}
	for i, v := range dialed {
		if v.Compare(addr) != 0 {
			dialed = slices.Delete(dialed, i, i+1)
		}
	}
}
