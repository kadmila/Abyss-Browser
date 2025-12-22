// ahost (alpha/abyss host) is a revised abyss host implementation of previous host package.
// ahost features better straightforward API interfaces, with significantly enhanced code maintainability.
package ahost

import (
	"errors"
	"net/netip"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

type AbyssHost struct {
	net ani.IAbyssNode
	and *and.AND

	exposed_worlds_mtx sync.Mutex
	exposed_worlds     map[string]*and.World // accepting JN requests.

	event_ch chan any
}

func NewAbyssHost(root_key sec.PrivateKey) (*AbyssHost, error) {
	node, err := ann.NewAbyssNode(root_key)
	if err != nil {
		return nil, err
	}
	return &AbyssHost{
		net: node,
		and: and.NewAND(node.ID()),

		exposed_worlds: make(map[string]*and.World),
	}, nil
}

func (h *AbyssHost) Main() error {
	err := h.net.Listen()
	if err != nil {
		return err
	}
	node_done := make(chan error)
	go func() {
		node_done <- h.net.Serve()
	}()
	return nil
}

type parsibleAhmp[T any] interface {
	TryParse() (*T, error)
}

func tryParseAhmp[RawT parsibleAhmp[T], T any](msg *ahmp.AHMPMesage) (*T, error) {
	var raw RawT
	if err := cbor.Unmarshal(msg.Payload, &raw); err != nil {
		return nil, err
	}
	return raw.TryParse()
}

func (h *AbyssHost) servePeer(peer ani.IAbyssPeer) error {
	and_event_receiver := and.NewANDEventQueue()
	participating_worlds := make(map[uuid.UUID]*and.World)
	event_handler := func() {
		for {
			event, ok := and_event_receiver.Pop()
			if !ok {
				return
			}
			switch e := event.(type) {
			case *and.EANDPeerRequest:
				if err := h.net.AppendKnownPeerDer(e.RootCertificateDer, e.HandshakeKeyCertificateDer); err != nil {
					// TODO: handle AppendKnownPeer failure.
				}
				functional.Foreach(e.AddressCandidates, func(addr netip.AddrPort) {
					h.net.Dial(e.PeerID, addr)
					// TODO: handle Dial failure.
				})
			case *and.EANDPeerDiscard:
				// This is tricky
			case *and.EANDTimerRequest:
			case *and.EANDWorldEnter, *and.EANDWorldLeave,
				*and.EANDSessionRequest, *and.EANDSessionReady, *and.EANDSessionClose,
				*and.EANDObjectAppend, *and.EANDObjectDelete:
				h.event_ch <- e
			}
		}
	}
	defer func() {
		for _, world := range participating_worlds {
			world.Lock()
			world.PeerDisconnected(and_event_receiver, peer.ID())
			event_handler()
			world.Unlock()
		}
		peer.Close()
	}()

	var msg ahmp.AHMPMesage
	for {
		err := peer.Recv(&msg)
		if err != nil {
			return err
		}
		switch msg.Type {
		case ahmp.JN_T:
			JN, err := tryParseAhmp[*and.RawJN](&msg)
			if err != nil {
				return err
			}

			h.exposed_worlds_mtx.Lock()
			world, ok := h.exposed_worlds[JN.Path]
			h.exposed_worlds_mtx.Unlock()

			peer_session := and.ANDPeerSession{Peer: peer, SessionID: JN.SenderSessionID}

			if !ok {
				if err := and.SendJDN_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND); err != nil {
					return err
				}
			}

			world.JN(
				and_event_receiver,
				peer_session,
				JN.TimeStamp,
			)
		case ahmp.JOK_T:
			JOK, err := tryParseAhmp[*and.RawJOK](&msg)
			if err != nil {
				return err
			}
			peer_session := and.ANDPeerSession{Peer: peer, SessionID: JOK.SenderSessionID}
			world, ok := participating_worlds[JOK.RecverSessionID]
			if !ok {
				and.SendRST_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
				continue
			}
			world.JOK(and_event_receiver, peer_session, JOK.TimeStamp, JOK.URL, JOK.Neighbors)
		case ahmp.JDN_T:
			JDN, err := tryParseAhmp[*and.RawJDN](&msg)
			if err != nil {
				return err
			}
			world, ok := participating_worlds[JDN.RecverSessionID]
			if !ok {
				continue
			}
			world.JDN(and_event_receiver, peer, JDN.Code, JDN.Message)
		case ahmp.JNI_T:
			JNI, err := tryParseAhmp[*and.RawJNI](&msg)
			if err != nil {
				return err
			}
			peer_session := and.ANDPeerSession{Peer: peer, SessionID: JNI.SenderSessionID}
			world, ok := participating_worlds[JNI.RecverSessionID]
			if !ok {
				and.SendRST_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
				continue
			}
			world.RST(and_event_receiver, peer_session)
		case ahmp.MEM_T:
			MEM, err := tryParseAhmp[*and.RawMEM](&msg)
			if err != nil {
				return err
			}
			peer_session := and.ANDPeerSession{Peer: peer, SessionID: MEM.SenderSessionID}
			world, ok := participating_worlds[MEM.RecverSessionID]
			if !ok {
				and.SendRST_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
				continue
			}
			world.MEM(and_event_receiver, peer_session, MEM.TimeStamp)
		case ahmp.SJN_T:
			SJN, err := tryParseAhmp[*and.RawSJN](&msg)
			if err != nil {
				return err
			}
			peer_session := and.ANDPeerSession{Peer: peer, SessionID: SJN.SenderSessionID}
			world, ok := participating_worlds[SJN.RecverSessionID]
			if !ok {
				and.SendRST_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
				continue
			}
			world.SJN(and_event_receiver, peer_session, SJN.MemberInfos)
		case ahmp.CRR_T:
			CRR, err := tryParseAhmp[*and.RawCRR](&msg)
			if err != nil {
				return err
			}
			peer_session := and.ANDPeerSession{Peer: peer, SessionID: CRR.SenderSessionID}
			world, ok := participating_worlds[CRR.RecverSessionID]
			if !ok {
				and.SendRST_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
				continue
			}
			world.CRR(and_event_receiver, peer_session, CRR.MemberInfos)
		case ahmp.RST_T:
			RST, err := tryParseAhmp[*and.RawRST](&msg)
			if err != nil {
				return err
			}
			peer_session := and.ANDPeerSession{Peer: peer, SessionID: RST.SenderSessionID}
			world, ok := participating_worlds[RST.RecverSessionID]
			if !ok {
				and.SendRST_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
				continue
			}
			world.RST(and_event_receiver, peer_session)
		case ahmp.SOA_T:
			SOA, err := tryParseAhmp[*and.RawSOA](&msg)
			if err != nil {
				return err
			}
			peer_session := and.ANDPeerSession{Peer: peer, SessionID: SOA.SenderSessionID}
			world, ok := participating_worlds[SOA.RecverSessionID]
			if !ok {
				and.SendRST_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
				continue
			}
			world.SOA(and_event_receiver, peer_session, SOA.Objects)
		case ahmp.SOD_T:
			SOD, err := tryParseAhmp[*and.RawSOD](&msg)
			if err != nil {
				return err
			}
			peer_session := and.ANDPeerSession{Peer: peer, SessionID: SOD.SenderSessionID}
			world, ok := participating_worlds[SOD.RecverSessionID]
			if !ok {
				and.SendRST_NoWorld(peer_session, and.JNC_NOT_FOUND, and.JNM_NOT_FOUND)
				continue
			}
			world.SOD(and_event_receiver, peer_session, SOD.ObjectIDs)
		case ahmp.AU_PING_TX_T:
			// TODO

		case ahmp.AU_PING_RX_T:
			// TODO

		default:
			// malformed message
			return errors.New("unsupported AHMP message type")
		}
	}
}

func (h *AbyssHost) ExposeWorldForJoin(world *and.World, path string) {
	h.exposed_worlds_mtx.Lock()
	defer h.exposed_worlds_mtx.Unlock()

	h.exposed_worlds[path] = world
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
func (h *AbyssHost) GetEvent() (any, error) {
	return nil, nil
}
