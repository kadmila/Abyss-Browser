package ann

import (
	"github.com/fxamacker/cbor/v2"
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

type AbyssConnection struct {
	inbound_connection  quic.Connection
	outbound_connection quic.Connection
	ahmp_encoder        *cbor.Encoder
	ahmp_decoder        *cbor.Decoder
}

const (
	AbyssQuicRedundantConnection quic.ApplicationErrorCode = 1000
	AbyssQuicAhmpStreamFail      quic.ApplicationErrorCode = 1001
	AbyssQuicCryptoFail          quic.ApplicationErrorCode = 1002
	AbyssQuicAuthenticationFail  quic.ApplicationErrorCode = 1002
)

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
