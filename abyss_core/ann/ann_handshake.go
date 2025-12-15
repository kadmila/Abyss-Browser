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

	// handle handshake timeout for non-contexted calls. This is somewhat lame, but is forced by the quic interface.
	handshake_result := make(chan handshakeResult, 1)
	go func() {
		result := handshakeResult{}
		defer func() {
			handshake_result <- result
		}()
		// (handshake 1)
		// send local tls-abyss binding cert encrypted with remote handshake key.
		encrypted_cert, aes_secret, err := peer_identity.EncryptHandshake(n.TLSIdentity.AbyssBindingCertificate())
		if err != nil {
			result.err = err
			result.close_code = AbyssQuicCryptoFail
			result.close_msg = "abyss cryptograhic failure"
			return
		}
		handshake_1_message := &ahmp.RawHS1{
			EncryptedCertificate: encrypted_cert,
			EncryptedSecret:      aes_secret,
		}
		if err := ahmp_encoder.Encode(handshake_1_message); err != nil {
			result.err = err
			result.close_code = AbyssQuicAhmpStreamFail
			result.close_msg = "failed to transmit AHMP"
			return
		}

		// (handshake 2)
		// receive server-side tls-abyss binding and verify
		var handshake_2_message []byte
		if err := ahmp_decoder.Decode(&handshake_2_message); err != nil {
			result.err = err
			result.close_code = AbyssQuicAhmpStreamFail
			result.close_msg = "failed to receive AHMP"
			return
		}
		handshake_2_payload_x509, err := x509.ParseCertificate(handshake_2_message)
		if err != nil {
			result.err = err
			result.close_code = AbyssQuicAuthenticationFail
			result.close_msg = "failed to parse certificate"
			return
		}
		if err := peer_identity.VerifyTLSBinding(handshake_2_payload_x509, client_tls_cert); err != nil {
			result.err = err
			result.close_code = AbyssQuicAuthenticationFail
			result.close_msg = "invalid certificate"
			return
		}
	}()
	select {
	case result := <-handshake_result:
		if result.err == nil {
			n.backlogAppend(true,
				&AbyssPeer{
					AbyssPeerIdentity: peer_identity,
					origin:            n,
					client_tls_cert:   client_tls_cert,
					connection:        connection,
					remote_addr:       addr,
					ahmp_encoder:      ahmp_encoder,
					ahmp_decoder:      ahmp_decoder,
				})
		} else if result.do_timeout {
			<-handshake_ctx.Done()
			connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
			n.backlogAppendError(addr, true, result.err)
		} else {
			connection.CloseWithError(result.close_code, result.close_msg)
			n.backlogAppendError(addr, true, result.err)
		}
	case <-handshake_ctx.Done():
		connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
		n.backlogAppendError(addr, true, handshake_ctx.Err())
	}
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
		n.backlogAppendError(addr, false, err)
		return
	}
	ahmp_encoder := cbor.NewEncoder(ahmp_stream)
	ahmp_decoder := cbor.NewDecoder(ahmp_stream)

	// handle handshake timeout for non-contexted calls. This is somewhat lame, but is forced by the quic interface.
	handshake_result := make(chan handshakeResult, 1)
	go func() {
		result := handshakeResult{}
		defer func() {
			handshake_result <- result
		}()
		// (handshake 1)
		// receive and decrypt peer's tls-binding certificate
		var handshake_1_message ahmp.RawHS1
		if err := ahmp_decoder.Decode(&handshake_1_message); err != nil {
			result.err = err
			result.close_code = AbyssQuicAhmpStreamFail
			result.close_msg = "failed to receive AHMP"
			return
		}
		tls_binding_cert_derBytes, err := n.DecryptHandshake(handshake_1_message.EncryptedCertificate, handshake_1_message.EncryptedSecret)
		if err != nil {
			result.err = err
			result.do_timeout = true
			return
		}
		tls_binding_cert, err := x509.ParseCertificate(tls_binding_cert_derBytes)
		if err != nil {
			result.err = err
			result.do_timeout = true
			return
		}

		// retrieve known identity
		peer_id := tls_binding_cert.Issuer.CommonName
		var peer_identity *sec.AbyssPeerIdentity
		retry_time := time.Millisecond * 50
		for { // exponential backoff (x1.5)
			var err *DialError
			peer_identity, err = n.registry.GetPeerIdentityIfAcceptable(peer_id)
			if err == nil {
				break
			}
			switch err.T {
			case DE_Redundant:
				// verify abyss-tls binding, to 1) quickly end connection,
				// or 2) make it timeout if its malicious.
				if err := peer_identity.VerifyTLSBinding(tls_binding_cert, client_tls_cert); err != nil {
					result.err = err
					result.do_timeout = true
					return
				} else {
					result.err = &DialError{T: DE_Redundant}
					result.close_code = AbyssQuicRedundantConnection
					result.close_msg = "redundant connection"
					return
				}
			case DE_UnknownPeer:
				select {
				case <-time.After(retry_time):
					retry_time = retry_time * 3 / 2
					continue
				case <-handshake_ctx.Done():
					result.err = handshake_ctx.Err()
					result.close_code = AbyssQuicHandshakeTimeout
					result.close_msg = "handshake timeout"
					return
				}
			}
		}

		// verify abyss-tls binding
		if err := peer_identity.VerifyTLSBinding(tls_binding_cert, client_tls_cert); err != nil {
			result.err = err
			result.do_timeout = true
			return
		}

		// now, the opponent is valid, acceptable peer.

		// (handshake 2)
		// send local tls-abyss binding cert
		if err = ahmp_encoder.Encode(n.TLSIdentity.AbyssBindingCertificate()); err != nil {
			result.err = err
			result.close_code = AbyssQuicAhmpStreamFail
			result.close_msg = "failed to transmit AHMP"
			return
		}
		result.received_identity = peer_identity
	}()
	select {
	case result := <-handshake_result:
		if result.err == nil {
			n.backlogAppend(false,
				&AbyssPeer{
					AbyssPeerIdentity: result.received_identity,
					origin:            n,
					client_tls_cert:   client_tls_cert,
					connection:        connection,
					remote_addr:       addr,
					ahmp_encoder:      ahmp_encoder,
					ahmp_decoder:      ahmp_decoder,
				})
		} else if result.do_timeout {
			<-handshake_ctx.Done()
			connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
			n.backlogAppendError(addr, false, result.err)
		} else {
			connection.CloseWithError(result.close_code, result.close_msg)
			n.backlogAppendError(addr, false, result.err)
		}
	case <-handshake_ctx.Done():
		connection.CloseWithError(AbyssQuicHandshakeTimeout, "handshake timeout")
		n.backlogAppendError(addr, false, handshake_ctx.Err())
	}
}

// Append blocks until 1) context cancels, or 2) abyss peer is constructed.
// * Issue: it hard-blocks when BackLog is full.
// should I let it accept context to prevent backlog blocking?
func (n *AbyssNode) backlogAppend(is_dialing bool, pre_peer *AbyssPeer) {
	// check who's in control.
	controller_id, err := TieBreak(n.ID(), pre_peer.ID())
	if err != nil {
		pre_peer.connection.CloseWithError(AbyssQuicCryptoFail, "abyss tie breaking fail") // this should never happen
		n.backlogAppendError(pre_peer.remote_addr, is_dialing, err)
		return
	}
	if n.ID() == controller_id {
		n.backlogAppendMaster(is_dialing, pre_peer)
	} else {
		n.backlogAppendSlave(is_dialing, pre_peer)
	}
}

func (n *AbyssNode) backlogAppendMaster(is_dialing bool, pre_peer *AbyssPeer) {
	// Append peer only when there is no active connection.
	// if this does not create a new peer, it is closed.
	new_peer, dial_err := n.registry.TryCompletingPeer(pre_peer)
	if dial_err != nil {
		switch dial_err.T {
		case DE_Redundant:
			pre_peer.connection.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
		case DE_UnknownPeer:
			pre_peer.connection.CloseWithError(AbyssQuicAuthenticationFail, "just rejected")
		}
		n.backlogAppendError(pre_peer.remote_addr, is_dialing, dial_err)
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
		pre_peer.connection.CloseWithError(AbyssQuicAhmpStreamFail, "fail to send abyss confirmation")
		pre_peer.Close()
		n.backlogAppendError(pre_peer.remote_addr, is_dialing, err)
		return
	}

	n.backlog <- backLogEntry{
		peer: new_peer,
		err:  nil,
	}
}

func (n *AbyssNode) backlogAppendSlave(is_dialing bool, pre_peer *AbyssPeer) {
	// Opponent is in control.
	// Wait for connection confirmation (handshake 3)
	var code int
	err := pre_peer.ahmp_decoder.Decode(&code)
	if err != nil {
		// opponent killed the connection (or ahmp stream fail)
		pre_peer.connection.CloseWithError(AbyssQuicAhmpStreamFail, "abyss confirmation fail")
		n.backlogAppendError(pre_peer.remote_addr, is_dialing, err)
		return
	}

	new_peer, dial_err := n.registry.TryCompletingPeer(pre_peer)
	if dial_err != nil {
		switch dial_err.T {
		case DE_Redundant:
			pre_peer.connection.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
		case DE_UnknownPeer:
			pre_peer.connection.CloseWithError(AbyssQuicAuthenticationFail, "just rejected")
		}
		n.backlogAppendError(pre_peer.remote_addr, is_dialing, dial_err)
		return
	}

	n.backlog <- backLogEntry{
		peer: new_peer,
		err:  nil,
	}
}

func (n *AbyssNode) backlogAppendError(addr netip.AddrPort, is_dialing bool, err error) {
	var direction string
	if is_dialing {
		direction = "(outbound)"
	} else {
		direction = "(inbound)"
	}
	n.backlog <- backLogEntry{
		peer: nil,
		err:  errors.New(addr.String() + direction + err.Error()),
	}
}
