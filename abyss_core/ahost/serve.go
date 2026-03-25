package ahost

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

type parsibleAhmp[T any] interface {
	TryParse() (*T, error)
}

func tryParseAhmp[RawT parsibleAhmp[T], T any](msg *ahmp.AHMPMessage) (*T, error) {
	var raw RawT
	if err := cbor.Unmarshal(msg.Payload, &raw); err != nil {
		return nil, err
	}
	return raw.TryParse()
}

func (h *AbyssHost) servePeer(peer ani.IAbyssPeer) error {
	// register related information to the host, and handle pending peer requests
	h.event_ch.In <- &EPeerConnected{PeerID: peer.ID()}

	// notify peer fetcher
	h.peer_fetcher.AddPeer(peer)

	// prepare for disconnection
	defer func() {
		// again, this is a quick and dirty approach;
		h.propagatePeerClose(peer.ID())

		// reverse order of peer insertion
		h.peer_fetcher.RemovePeer(peer.ID())
		h.event_ch.In <- &EPeerDisconnected{PeerID: peer.ID()}
		peer.Close()
	}()

	// receive AHMP messages and handle them
	for {
		msg, err := peer.Recv()
		if err != nil {
			return err
		}
		switch msg.Type {
		case ahmp.JN_T:
			JN, err := tryParseAhmp[*and.RawJN](msg)
			if err != nil {
				return err
			}
			if err := h.onJN(JN, peer); err != nil {
				return err
			}
		case ahmp.JOK_T:
			JOK, err := tryParseAhmp[*and.RawJOK](msg)
			if err != nil {
				return err
			}
			if err := h.onJOK(JOK, peer); err != nil {
				return err
			}
		case ahmp.JNI_T:
			JNI, err := tryParseAhmp[*and.RawJNI](msg)
			if err != nil {
				return err
			}
			if err := h.onJNI(JNI, peer); err != nil {
				return err
			}
		case ahmp.MEM_T:
			MEM, err := tryParseAhmp[*and.RawMEM](msg)
			if err != nil {
				return err
			}
			if err := h.onMEM(MEM, peer); err != nil {
				return err
			}
		case ahmp.SJN_T:
			SJN, err := tryParseAhmp[*and.RawSJN](msg)
			if err != nil {
				return err
			}
			if err := h.onSJN(SJN, peer); err != nil {
				return err
			}
		case ahmp.CRR_T:
			CRR, err := tryParseAhmp[*and.RawCRR](msg)
			if err != nil {
				return err
			}
			if err := h.onCRR(CRR, peer); err != nil {
				return err
			}
		case ahmp.RST_T:
			RST, err := tryParseAhmp[*and.RawRST](msg)
			if err != nil {
				return err
			}
			if err := h.onRST(RST, peer); err != nil {
				return err
			}
		case ahmp.SOA_T:
			SOA, err := tryParseAhmp[*and.RawSOA](msg)
			if err != nil {
				return err
			}
			if err := h.onSOA(SOA, peer); err != nil {
				return err
			}
		case ahmp.SOD_T:
			SOD, err := tryParseAhmp[*and.RawSOD](msg)
			if err != nil {
				return err
			}
			if err := h.onSOD(SOD, peer); err != nil {
				return err
			}
		case ahmp.AU_PING_TX_T:
			if err := h.onAUPingTX(peer); err != nil {
				return err
			}
		case ahmp.AU_PING_RX_T:
			if err := h.onAUPingRX(peer); err != nil {
				return err
			}
		default:
			// malformed message
			return errors.New("unsupported AHMP message type")
		}
	}
}
