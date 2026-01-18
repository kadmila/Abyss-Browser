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
		case *and.EANDPeerRequest:
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

		case *and.EANDPeerDiscard:
			// Remove peer from peer_participating_worlds
			participating_worlds, ok := h.peer_participating_worlds[e.Peer.ID()]
			if !ok {
				panic("and algorithm fired peer removal from a non-participating world")
			}
			delete(participating_worlds, e.World.SessionID())

		case *and.EANDTimerRequest:
			//fmt.Println(e.Duration.Milliseconds())
			h.timer_queue.Add(e.World.SessionID(), e.Duration)

		case *and.EANDWorldEnter:
			h.event_ch <- e
			h.worlds[e.World.SessionID()] = e.World
			// apending world to AbyssHost must be alredy handled by the WorldOpen/WorldJoin caller.

		case *and.EANDWorldLeave:
			world_lsid := e.World.SessionID()
			remaining_peers := e.World.Peers()
			for _, peer := range remaining_peers {
				delete(h.peer_participating_worlds[peer.ID()], world_lsid)
			}
			delete(h.worlds, world_lsid)
			join_path, ok := h.world_path_mapping[world_lsid]
			if ok {
				delete(h.world_path_mapping, world_lsid)
				delete(h.exposed_worlds, join_path)
			}
			h.event_ch <- e

		case *and.EANDSessionRequest, *and.EANDSessionReady, *and.EANDSessionClose,
			*and.EANDObjectAppend, *and.EANDObjectDelete:
			h.event_ch <- e
		}
	}

	// Call PeerConnected sequentially after handling all events
	for _, res := range reservations {
		res.world.PeerConnected(events, res.peer)
		h.handleANDEvent(events)
	}
}
