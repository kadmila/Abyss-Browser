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

// decodeWithContext decodes CBOR data with context support.
// This is somewhat lame, but is forced by the quic interface.
func decodeWithContext(ctx context.Context, decoder *cbor.Decoder, v any) error {
	done := make(chan error, 1)
	go func() {
		err := decoder.Decode(v)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// handshakeResult is for dialRoutine and serveRoutine internal use only.
type handshakeResult struct {
	err               error
	do_timeout        bool // this is set true, if we must disguise this as timeout for security reasons.
	close_code        quic.ApplicationErrorCode
	close_msg         string
	received_identity *sec.AbyssPeerIdentity // only for serving side.
}

func (n *AbyssNode) dialRoutine(addr netip.AddrPort, peer_identity *sec.AbyssPeerIdentity) {
	// prepare handshake context - sets timeout for abyss handshake
	handshake_ctx, handshake_ctx_cancel := context.WithTimeout(n.service_ctx, time.Second*5)
	defer func() {
		handshake_ctx_cancel()
		n.registry.ReportDialTermination(peer_identity, addr.Addr())
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
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			peer_identity.ID(),
			true,
			HS_Connection,
			HS_Fail_TransportFail,
		))
		return
	}

	// get ephemeral TLS certificate
	tls_info := connection.ConnectionState().TLS
	client_tls_cert := tls_info.PeerCertificates[0]

	// open ahmp stream
	ahmp_stream, err := connection.OpenStreamSync(handshake_ctx)
	if err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to start AHMP")
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			peer_identity.ID(),
			true,
			HS_StreamSetup,
			HS_Fail_TransportFail,
		))
		return
	}
	ahmp_encoder := cbor.NewEncoder(ahmp_stream)
	ahmp_decoder := cbor.NewDecoder(ahmp_stream)

	// (handshake 1)
	// send local tls-abyss binding cert encrypted with remote handshake key.
	encrypted_cert, aes_secret, err := peer_identity.EncryptHandshake(n.TLSIdentity.AbyssBindingCertificate())
	if err != nil {
		connection.CloseWithError(AbyssQuicCryptoFail, "abyss cryptograhic failure")
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			peer_identity.ID(),
			true,
			HS_Handshake1,
			HS_Fail_CryptoFail,
		))
		return
	}
	handshake_1_message := &ahmp.RawHS1{
		EncryptedCertificate: encrypted_cert,
		EncryptedSecret:      aes_secret,
	}
	if err := ahmp_encoder.Encode(handshake_1_message); err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to transmit AHMP")
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			peer_identity.ID(),
			true,
			HS_Handshake1,
			HS_Fail_CryptoFail,
		))
		return
	}

	// (handshake 2)
	// receive server-side tls-abyss binding and verify
	var handshake_2_message []byte
	if err := decodeWithContext(handshake_ctx, ahmp_decoder, &handshake_2_message); err != nil {
		var cbor_err *cbor.SyntaxError
		if errors.As(err, &cbor_err) {
			connection.CloseWithError(AbyssQuicAhmpParseFail, "failed to parse AHMP message")
			n.backlogPushErr(NewHandshakeError(
				err,
				addr,
				peer_identity.ID(),
				true,
				HS_Handshake2,
				HS_Fail_ParserFail,
			))
			return
		} else {
			connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to receive AHMP")
			n.backlogPushErr(NewHandshakeError(
				err,
				addr,
				peer_identity.ID(),
				true,
				HS_Handshake2,
				HS_Fail_TransportFail,
			))
			return
		}
	}
	handshake_2_payload_x509, err := x509.ParseCertificate(handshake_2_message)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "failed to parse certificate")
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			peer_identity.ID(),
			true,
			HS_Handshake2,
			HS_Fail_InvalidCert,
		))
		return
	}
	if err := peer_identity.VerifyTLSBinding(handshake_2_payload_x509, client_tls_cert); err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			peer_identity.ID(),
			true,
			HS_Handshake2,
			HS_Fail_InvalidCert,
		))
		return
	}

	n.tryCompletePeer(
		handshake_ctx,
		true,
		&AbyssPeer{
			AbyssPeerIdentity: peer_identity,
			origin:            n,
			client_tls_cert:   client_tls_cert,
			connection:        connection,
			remote_addr:       addr,
			ahmp_encoder:      ahmp_encoder,
			ahmp_decoder:      ahmp_decoder,
		})
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

	// open ahmp stream
	ahmp_stream, err := connection.AcceptStream(handshake_ctx)
	if err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to start AHMP")
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			"",
			false,
			HS_StreamSetup,
			HS_Fail_TransportFail,
		))
		return
	}
	ahmp_encoder := cbor.NewEncoder(ahmp_stream)
	ahmp_decoder := cbor.NewDecoder(ahmp_stream)

	// (handshake 1)
	var handshake_1_message ahmp.RawHS1
	if err := decodeWithContext(handshake_ctx, ahmp_decoder, &handshake_1_message); err != nil {
		var cbor_err *cbor.SyntaxError
		if errors.As(err, &cbor_err) {
			connection.CloseWithError(AbyssQuicAhmpParseFail, "failed to parse AHMP message")
			n.backlogPushErr(NewHandshakeError(
				err,
				addr,
				"",
				false,
				HS_Handshake1,
				HS_Fail_ParserFail,
			))
			return
		} else {
			connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to receive AHMP")
			n.backlogPushErr(NewHandshakeError(
				err,
				addr,
				"",
				false,
				HS_Handshake1,
				HS_Fail_TransportFail,
			))
			return
		}
	}
	tls_binding_cert_derBytes, err := n.DecryptHandshake(handshake_1_message.EncryptedCertificate, handshake_1_message.EncryptedSecret)
	if err != nil {
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			"",
			false,
			HS_Handshake1,
			HS_Fail_CryptoFail,
		))
		<-handshake_ctx.Done()
		connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
		return
	}
	tls_binding_cert, err := x509.ParseCertificate(tls_binding_cert_derBytes)
	if err != nil {
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			"",
			false,
			HS_Handshake1,
			HS_Fail_InvalidCert,
		))
		<-handshake_ctx.Done()
		connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
		return
	}

	// retrieve known identity with exponential backoff (x1.5)
	peer_id := tls_binding_cert.Issuer.CommonName
	var peer_identity *sec.AbyssPeerIdentity
	retry_time := time.Millisecond * 50
IDENTITY_RETRIEVE_LOOP:
	for {
		var registry_status RegistryEntryStatus
		peer_identity, registry_status = n.registry.GetPeerIdentityIfAcceptable(peer_id)
		switch registry_status {
		case RE_OK: // just found peer_identity. Proceed.
			break IDENTITY_RETRIEVE_LOOP
		case RE_Redundant:
			// verify abyss-tls binding, to 1) quickly end connection,
			// or 2) make it timeout if its malicious.
			if err := peer_identity.VerifyTLSBinding(tls_binding_cert, client_tls_cert); err != nil {
				n.backlogPushErr(NewHandshakeError(
					err,
					addr,
					"",
					false,
					HS_Handshake1,
					HS_Fail_CryptoFail,
				))
				<-handshake_ctx.Done()
				connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
				return
			} else {
				connection.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
				n.backlogPushErr(NewHandshakeError(
					err,
					addr,
					"",
					false,
					HS_Handshake1,
					HS_Fail_Redundant,
				))
				return
			}
		case RE_UnknownPeer:
			select {
			case <-time.After(retry_time):
				retry_time = retry_time * 3 / 2
				continue
			case <-handshake_ctx.Done():
				n.backlogPushErr(NewHandshakeError(
					err,
					addr,
					"",
					false,
					HS_Handshake1,
					HS_Fail_UnknownPeer,
				))
				<-handshake_ctx.Done()
				connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
				return
			}
		}
	}

	// verify abyss-tls binding
	if err := peer_identity.VerifyTLSBinding(tls_binding_cert, client_tls_cert); err != nil {
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			"",
			false,
			HS_Handshake1,
			HS_Fail_CryptoFail,
		))
		<-handshake_ctx.Done()
		connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
		return
	}
	// now, the opponent is valid, acceptable peer.

	// (handshake 2)
	// send local tls-abyss binding cert
	if err = ahmp_encoder.Encode(n.TLSIdentity.AbyssBindingCertificate()); err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to transmit AHMP")
		n.backlogPushErr(NewHandshakeError(
			err,
			addr,
			"",
			false,
			HS_Handshake2,
			HS_Fail_TransportFail,
		))
		return
	}

	n.tryCompletePeer(
		handshake_ctx,
		false,
		&AbyssPeer{
			AbyssPeerIdentity: peer_identity,
			origin:            n,
			client_tls_cert:   client_tls_cert,
			connection:        connection,
			remote_addr:       addr,
			ahmp_encoder:      ahmp_encoder,
			ahmp_decoder:      ahmp_decoder,
		})
}

// Append blocks until 1) context cancels, or 2) abyss peer is constructed.
// * Issue: it hard-blocks when BackLog is full.
// should I let it accept context to prevent backlog blocking?
func (n *AbyssNode) tryCompletePeer(ctx context.Context, is_dialing bool, pre_peer *AbyssPeer) {
	// check who's in control.
	controller_id, err := TieBreak(n.ID(), pre_peer.ID())
	if err != nil {
		pre_peer.connection.CloseWithError(AbyssQuicCryptoFail, "abyss tie breaking fail") // this should never happen
		n.backlogPushErr(NewHandshakeError(
			err,
			pre_peer.remote_addr,
			pre_peer.ID(),
			is_dialing,
			HS_TieBreak,
			HS_Fail_TieBreakFail,
		))
		return
	}
	if n.ID() == controller_id {
		n.tryCompletePeerMaster(is_dialing, pre_peer)
	} else {
		n.tryCompletePeerSlave(ctx, is_dialing, pre_peer)
	}
}

func (n *AbyssNode) tryCompletePeerMaster(is_dialing bool, pre_peer *AbyssPeer) {
	// Append peer only when there is no active connection.
	// if this does not create a new peer, it is closed.
	new_peer, registry_status := n.registry.TryCompletingPeer(pre_peer)
	switch registry_status {
	case RE_OK:
		// proceed
	case RE_Redundant:
		pre_peer.connection.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
		n.backlogPushErr(NewHandshakeError(
			errors.New("redundant connection"),
			pre_peer.remote_addr,
			"",
			is_dialing,
			HS_PeerCompletion,
			HS_Fail_Redundant,
		))
		return
	case RE_UnknownPeer:
		pre_peer.connection.CloseWithError(AbyssQuicAuthenticationFail, "just rejected")
		n.backlogPushErr(NewHandshakeError(
			errors.New("redundant connection"),
			pre_peer.remote_addr,
			"",
			is_dialing,
			HS_PeerCompletion,
			HS_Fail_UnknownPeer,
		))
		return
	}

	// connection confirmation (handshake 3)
	code := 0
	err := pre_peer.ahmp_encoder.Encode(code)
	if err != nil {
		// really nasty error. The peer has to Close(), as it is already registered.
		// This is very dangerous code. Close() was not designed to be called inside handshake goroutine.
		// It is only allowed (and unavoidable) here as it is 1) ready for Accept(),
		// but 2) not actually fetched to the backlog, and 3) the registry data for the peer must be cleaned up.
		// Calling Close() is the only appropriate way to remove an established peer.
		pre_peer.connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to send abyss confirmation")
		pre_peer.Close()
		n.backlogPushErr(NewHandshakeError(
			err,
			pre_peer.remote_addr,
			"",
			is_dialing,
			HS_PeerCompletion,
			HS_Fail_TransportFail,
		))
		return
	}

	n.backlog <- backLogEntry{
		peer: new_peer,
		err:  nil,
	}
}

func (n *AbyssNode) tryCompletePeerSlave(ctx context.Context, is_dialing bool, pre_peer *AbyssPeer) {
	// Opponent is in control.
	// Wait for connection confirmation (handshake 3)
	var code int
	if err := decodeWithContext(ctx, pre_peer.ahmp_decoder, &code); err != nil {
		// opponent killed the connection (or ahmp stream fail)
		pre_peer.connection.CloseWithError(AbyssQuicAhmpStreamFail, "abyss confirmation fail")
		n.backlogPushErr(NewHandshakeError(
			err,
			pre_peer.remote_addr,
			pre_peer.ID(),
			is_dialing,
			HS_Handshake3,
			HS_Fail_TransportFail,
		))
		return
	}

	new_peer, registry_status := n.registry.TryCompletingPeer(pre_peer)
	switch registry_status {
	case RE_OK:
		// proceed
	case RE_Redundant:
		pre_peer.connection.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
		n.backlogPushErr(NewHandshakeError(
			errors.New("redundant connection"),
			pre_peer.remote_addr,
			"",
			is_dialing,
			HS_PeerCompletion,
			HS_Fail_Redundant,
		))
		return
	case RE_UnknownPeer:
		pre_peer.connection.CloseWithError(AbyssQuicAuthenticationFail, "just rejected")
		n.backlogPushErr(NewHandshakeError(
			errors.New("redundant connection"),
			pre_peer.remote_addr,
			"",
			is_dialing,
			HS_PeerCompletion,
			HS_Fail_UnknownPeer,
		))
		return
	}

	n.backlog <- backLogEntry{
		peer: new_peer,
		err:  nil,
	}
}
