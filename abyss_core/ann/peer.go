package ann

import (
	"context"
	"crypto/x509"
	"net/netip"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
)

type AbyssPeer struct {
	*sec.AbyssPeerIdentity
	origin          *AbyssNode
	internal_id     uint64
	client_tls_cert *x509.Certificate // this is stupid

	connection   quic.Connection
	remote_addr  netip.AddrPort
	ahmp_encoder *cbor.Encoder
	ahmp_decoder *cbor.Decoder

	// abyst connections

	// is_closed should be referenced only from AbyssNode.
	is_closed atomic.Bool
}

func (p *AbyssPeer) RemoteAddr() netip.AddrPort {
	return p.remote_addr
}

func (p *AbyssPeer) Send(t ahmp.AHMPMsgType, v any) error {
	var msg ahmp.AHMPMesage
	msg.Type = t
	var err error
	msg.Payload, err = cbor.Marshal(v)
	if err != nil {
		return err
	}
	return p.ahmp_encoder.Encode(&msg)
}
func (p *AbyssPeer) Recv(v *ahmp.AHMPMesage) error {
	return p.ahmp_decoder.Decode(v)
}
func (p *AbyssPeer) Context() context.Context {
	return p.connection.Context()
}

func (p *AbyssPeer) Close() error {
	return p.origin.registry.ReportPeerClose(p)
}

func (p *AbyssPeer) Equal(subject *AbyssPeer) bool {
	return p.internal_id == subject.internal_id
}
