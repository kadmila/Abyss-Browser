package ahost

import (
	"net/netip"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
)

// peerReservation represents a peer that needs to be connected to a world
type peerReservation struct {
	peer  ani.IAbyssPeer
	world *and.World
	addrs []netip.AddrPort
}

func (h *AbyssHost) handleANDEvent(events ds.Queue) {
	// Collect peers that need to be connected after processing all events
	var reservations []peerReservation

	for {
		event, ok := events.Pop()
		if !ok {
			break
		}

		switch e := event.(type) {
		case *and.EANDFetchPeerSession:
			// Try to find peer in registry
			peer, found := h.peers[e.PeerID]
			if found {
				// Reserve peer for PeerConnected call after handling all events
				reservations = append(reservations, peerReservation{
					peer:  peer,
					world: e.World,
					addrs: e.AddressCandidates,
				})
			} else {
				// Peer not found, dial it
				peer_id, ok, err := h.net.AppendKnownPeerDer(e.RootCertificateDer, e.HandshakeKeyCertificateDer)
				if err != nil {
					// TODO: handle AppendKnownPeer failure.
					continue
				}
				if err := h.net.Dial(e.PeerID); err != nil {
					// TODO: handle Dial failure.
					continue
				}
				if ok {
					h.event_ch <- &EPeerFound{PeerID: peer_id}
				}

				// record peer request.
				request_note, ok := h.requested_peers[e.PeerID]
				if !ok {
					request_note = make(map[uuid.UUID]*and.World)
					h.requested_peers[e.PeerID] = request_note
				}

				request_note[e.World.SessionID()] = e.World
			}

		default:
			h.event_ch <- e
		}
	}

	// Call PeerConnected sequentially after handling all events
	for _, res := range reservations {
		res.world.PeerConnected(events, res.peer)
		h.handleANDEvent(events)
	}
}
