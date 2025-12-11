package ann

import (
	"context"
	"net/netip"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
)

type AbyssPeer struct {
	*sec.AbyssPeerIdentity
	origin      *AbyssNode
	internal_id uint64

	connection   quic.Connection
	remote_addr  netip.AddrPort
	ahmp_encoder *cbor.Encoder
	ahmp_decoder *cbor.Decoder
}

func (p *AbyssPeer) RemoteAddr() netip.AddrPort {
	return p.remote_addr
}

func (p *AbyssPeer) Send(v any) error {
	return p.ahmp_encoder.Encode(v)
}
func (p *AbyssPeer) Recv(v any) error {
	return p.ahmp_decoder.Decode(v)
}
func (p *AbyssPeer) Context() context.Context {
	return p.connection.Context()
}

func (p *AbyssPeer) Close() error {
	err := p.connection.CloseWithError(AbyssQuicClose, "")
	p.origin.ReportPeerClose(p)
	return err
}

func (p *AbyssPeer) Equal(subject *AbyssPeer) bool {
	return p.internal_id == subject.internal_id
}
