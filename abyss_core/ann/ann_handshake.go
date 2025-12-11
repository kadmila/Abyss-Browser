package ann

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
)

func (n *AbyssNode) dialRoutine(id string, addr netip.AddrPort, peer_identity *sec.AbyssPeerIdentity) {
	// prepare handshake context - sets timeout for abyss handshake
	handshake_ctx, handshake_ctx_cancel := context.WithTimeout(n.service_ctx, time.Second*5)
	defer func() {
		handshake_ctx_cancel()
		n.dial_stats.ReportDialTermination(id, addr.Addr())
	}()

	// dial
	connection, err := n.transport.Dial(
		handshake_ctx,
		&net.UDPAddr{
			IP:   addr.Addr().AsSlice(),
			Port: int(addr.Port()),
		},
		n.TLSIdentity.NewAbyssClientTlsConf(),
		newQuicConfig(),
	)
	if err != nil {
		if connection != nil {
			connection.CloseWithError(0, "dial error")
		}
		n.backlogAppendError(addr, true, err)
		return
	}

	// get ephemeral TLS certificate
	tls_info := connection.ConnectionState().TLS
	client_tls_cert := tls_info.PeerCertificates[0]

	// open ahmp stream
	ahmp_stream, err := connection.OpenStreamSync(handshake_ctx)
	if err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to start AHMP")
		n.backlogAppendError(addr, true, err)
		return
	}
	ahmp_encoder := cbor.NewEncoder(ahmp_stream)
	ahmp_decoder := cbor.NewDecoder(ahmp_stream)

	// (handshake 1)
	// send local tls-abyss binding cert encrypted with remote handshake key.
	encrypted_cert, aes_secret, err := peer_identity.EncryptHandshake(n.TLSIdentity.AbyssBindingCertificate())
	if err != nil {
		connection.CloseWithError(AbyssQuicCryptoFail, "abyss cryptograhic failure")
		n.backlogAppendError(addr, true, err)
		return
	}
	handshake_1_message := &ahmp.RawHS1{
		EncryptedCertificate: encrypted_cert,
		EncryptedSecret:      aes_secret,
	}
	err = ahmp_encoder.Encode(handshake_1_message)
	if err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to transmit AHMP")
		n.backlogAppendError(addr, true, err)
		return
	}

	// (handshake 2)
	// receive server-side tls-abyss binding and verify
	var handshake_2_message []byte
	err = ahmp_decoder.Decode(&handshake_2_message)
	if err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to receive AHMP")
		n.backlogAppendError(addr, true, err)
		return
	}
	handshake_2_payload_x509, err := x509.ParseCertificate(handshake_2_message)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "failed to parse certificate")
		n.backlogAppendError(addr, true, err)
		return
	}
	err = peer_identity.VerifyTLSBinding(handshake_2_payload_x509, client_tls_cert)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.backlogAppendError(addr, true, err)
		return
	}

	n.backlogAppend(
		true,
		peer_identity, connection, addr,
		ahmp_encoder, ahmp_decoder)
}

func (n *AbyssNode) serveRoutine(connection quic.Connection) {
	// prepare handshake context - sets timeout for abyss handshake
	handshake_ctx, handshake_ctx_cancel := context.WithTimeout(n.service_ctx, time.Second*5)
	defer handshake_ctx_cancel()

	// get address (for logging)
	a := connection.RemoteAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte(a.IP.To4())), uint16(a.Port))

	// get self-signed TLS certificate that the peer presented.
	tls_info := connection.ConnectionState().TLS
	client_tls_cert := tls_info.PeerCertificates[0]

	ahmp_stream, err := connection.AcceptStream(handshake_ctx)
	if err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to start AHMP")
		n.backlogAppendError(addr, false, err)
		return
	}
	ahmp_encoder := cbor.NewEncoder(ahmp_stream)
	ahmp_decoder := cbor.NewDecoder(ahmp_stream)

	// (handshake 1)
	// receive and decrypt peer's tls-binding certificate
	var handshake_1_message ahmp.RawHS1
	if err = ahmp_decoder.Decode(&handshake_1_message); err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to receive AHMP")
		n.backlogAppendError(addr, false, err)
		return
	}
	tls_binding_cert_derBytes, err := n.DecryptHandshake(handshake_1_message.EncryptedCertificate, handshake_1_message.EncryptedSecret)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.backlogAppendError(addr, false, err)
		return
	}
	tls_binding_cert, err := x509.ParseCertificate(tls_binding_cert_derBytes)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.backlogAppendError(addr, false, err)
		return
	}

	// retrieve known identity
	peer_id := tls_binding_cert.Issuer.CommonName
	peer_identity, err := n.dial_stats.Get(handshake_ctx, peer_id)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.backlogAppendError(addr, false, err)
		return
	}

	// verify abyss-tls binding
	err = peer_identity.VerifyTLSBinding(tls_binding_cert, client_tls_cert)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.backlogAppendError(addr, false, err)
		return
	}

	// (handshake 2)
	// send local tls-abyss binding cert
	if err = ahmp_encoder.Encode(n.TLSIdentity.AbyssBindingCertificate()); err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to transmit AHMP")
		n.backlogAppendError(addr, true, err)
		return
	}

	n.backlogAppend(
		false,
		peer_identity, connection, addr,
		ahmp_encoder, ahmp_decoder,
	)
}

// Append blocks until 1) context cancels, or 2) abyss peer is constructed.
// * Issue: it hard-blocks when BackLog is full.
func (n *AbyssNode) backlogAppend(
	is_dialing bool,
	identity *sec.AbyssPeerIdentity, connection quic.Connection, addr netip.AddrPort,
	ahmp_encoder *cbor.Encoder, ahmp_decoder *cbor.Decoder) {
	///////////////////////////////////////
	// check who's in control.
	controller_id, err := TieBreak(n.ID(), identity.ID())
	if err != nil {
		n.backlogAppendError(addr, is_dialing, err)
		connection.CloseWithError(AbyssQuicCryptoFail, "abyss tie breaking fail")
		return
	}
	if n.ID() == controller_id {
		// I'm in control. Append peer only when there is no active connection.
		var new_peer *AbyssPeer
		var is_new_peer_created bool

		n.backlog_mtx.Lock()
		{
			_, ok := n.connected_peers[identity.ID()]
			if !ok {
				n.internal_peer_id_cnt++
				new_peer = &AbyssPeer{
					AbyssPeerIdentity: identity,
					origin:            n,
					internal_id:       n.internal_peer_id_cnt,

					connection:   connection,
					remote_addr:  addr,
					ahmp_encoder: ahmp_encoder,
					ahmp_decoder: ahmp_decoder,
				}
				n.connected_peers[identity.ID()] = new_peer
				is_new_peer_created = true
			}
		}
		n.backlog_mtx.Unlock()

		// if this does not create a new peer, prune connection.
		if !is_new_peer_created {
			connection.CloseWithError(AbyssQuicRedundantConnection, "")
			n.backlogAppendError(addr, is_dialing, errors.New("redundant connection"))
			return
		}

		// connection confirmation (handshake 3)
		code := 0
		err = ahmp_encoder.Encode(code)
		if err != nil {
			connection.CloseWithError(AbyssQuicAhmpStreamFail, "fail to send abyss confirmation")
			n.backlogAppendError(addr, is_dialing, err)
			return
		}

		n.backlog <- backLogEntry{
			peer: new_peer,
			err:  nil,
		}
		return
	} else {
		// Opponent is in control.
		// Wait for connection confirmation (handshake 3)
		var code int
		err := ahmp_decoder.Decode(&code)
		if err != nil {
			// opponent killed the connection (or ahmp stream fail)
			connection.CloseWithError(AbyssQuicAhmpStreamFail, "abyss confirmation fail")
			n.backlogAppendError(addr, is_dialing, err)
			return
		}
		var new_peer *AbyssPeer

		// This connection is accepted.
		n.backlog_mtx.Lock()
		{
			n.internal_peer_id_cnt++
			new_peer = &AbyssPeer{
				AbyssPeerIdentity: identity,
				origin:            n,
				internal_id:       n.internal_peer_id_cnt,

				connection:   connection,
				remote_addr:  addr,
				ahmp_encoder: ahmp_encoder,
				ahmp_decoder: ahmp_decoder,
			}

			// renew peer if old one exists.
			old_peer, ok := n.connected_peers[identity.ID()]
			if ok {
				old_peer.connection.CloseWithError(AbyssQuicOverride, "")
			}
			n.connected_peers[identity.ID()] = new_peer
		}
		n.backlog_mtx.Unlock()

		n.backlog <- backLogEntry{
			peer: new_peer,
			err:  nil,
		}
		return
	}
}

func (c *AbyssNode) backlogAppendError(addr netip.AddrPort, is_dialing bool, err error) {
	var direction string
	if is_dialing {
		direction = "(outbound)"
	} else {
		direction = "(inbound)"
	}
	c.backlog <- backLogEntry{
		peer: nil,
		err:  errors.New(addr.String() + direction + err.Error()),
	}
}

func (c *AbyssNode) ReportPeerClose(peer *AbyssPeer) {
	c.backlog_mtx.Lock()
	defer c.backlog_mtx.Unlock()

	old_peer, ok := c.connected_peers[peer.ID()]
	if ok && old_peer.Equal(peer) {
		delete(c.connected_peers, peer.ID())
	}
}
