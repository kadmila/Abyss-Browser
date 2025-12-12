package ann

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
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

	// is_closed should be referenced only from AbyssNode.
	is_closed atomic.Bool
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
	if p.origin.reportPeerClose(p) {
		return nil
	} else {
		return net.ErrClosed
	}
}

func (p *AbyssPeer) Equal(subject *AbyssPeer) bool {
	return p.internal_id == subject.internal_id
}
