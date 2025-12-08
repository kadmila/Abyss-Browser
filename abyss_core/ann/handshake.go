package ann

import (
	"context"
	"errors"
	"net/netip"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
)

type InboundConnection struct {
	conn         quic.Connection
	ahmp_encoder *cbor.Encoder
	ahmp_decoder *cbor.Decoder
}

type OutboundConnection struct {
	conn         quic.Connection
	ahmp_encoder *cbor.Encoder
	ahmp_decoder *cbor.Decoder
}

type HandshakeHandler struct {
	table              PeerStatusMap
	verified_tls_certs *sec.VerifiedTlsCertMap
	backlog            chan *AbyssPeer

	inbound_backlog  chan *InboundConnection
	outbound_backlog chan *OutboundConnection
}

func MakeHandshakeHandler() HandshakeHandler {
	return HandshakeHandler{
		table:              MakePeerStatusMap(),
		verified_tls_certs: sec.NewVerifiedTlsCertMap(),
		backlog:            make(chan *AbyssPeer, 32),

		inbound_backlog:  make(chan *InboundConnection, 32),
		outbound_backlog: make(chan *OutboundConnection, 32),
	}
}

func (n *HandshakeHandler) AppendKnownPeer(root_cert string, handshake_key_cert string) error {
	identity, err := sec.NewAbyssPeerIdentityFromPEM(root_cert, handshake_key_cert)
	if err != nil {
		return err
	}

	n.table.UpdatePeerInformation(identity)
	return nil
}
func (n *HandshakeHandler) AppendKnownPeerDer(root_cert []byte, handshake_key_cert []byte) error {
	identity, err := sec.NewAbyssPeerIdentityFromDER(root_cert, handshake_key_cert)
	if err != nil {
		return err
	}

	n.table.UpdatePeerInformation(identity)
	return nil
}

func (n *HandshakeHandler) dial(hash string, addr *netip.AddrPort, transport *quic.Transport) error {
	// conn, err := transport.Dial(
	// 	n.dial_ctx,
	// 	&net.UDPAddr{
	// 		IP:   addr.Addr().AsSlice(),
	// 		Port: int(addr.Port()),
	// 	},
	// 	n.NewAbyssClientTlsConf(),
	// 	newQuicConfig(),
	// )
	return nil
}

func (n *HandshakeHandler) Accept(ctx context.Context) (*AbyssPeer, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case new_peer, ok := <-n.backlog:
		if !ok {
			return nil, errors.New("AbyssNode closed")
		}
		return new_peer, nil
	}
}

func (h *HandshakeHandler) run() error {
	return nil
}

// func (n *AbyssNode) handshakeService(ctx context.Context, done chan<- bool) {

// 	accepter_done := make(chan bool)

// 	go connectionAccepter(accepter_done, n)

// 	<-ctx.Done()
// 	n.inner_done <- true
// }

// func connectionAccepter(ctx context.Context, host AbyssNode, target chan quic.Connection, done chan<- bool) {
// 	for {
// 		connection, err := host.listener.Accept(ctx)
// 		if err != nil {
// 			if ctx.Err() != nil {
// 				break
// 			}
// 		}
// 	}
// 	done <- true
// }

// func inboundR1Handler(host AbyssNode, connection quic.Connection, target chan quic.Connection, done chan<- bool) {
// 	// get self-signed TLS certificate that the peer presented.
// 	// we ensure they presented only one self-signed certificate during the TLS handshake.
// 	tls_cert := connection.ConnectionState().TLS.PeerCertificates[0]

// 	ahmp_stream, err := connection.AcceptStream(host.inner_ctx)
// 	if err != nil {
// 		err = aerr.NewConnErr(connection, nil, err)
// 		return
// 	}
// 	ahmp_encoder := cbor.NewEncoder(ahmp_stream)
// 	ahmp_decoder = cbor.NewDecoder(ahmp_stream)
// }
