// Package ann (abyss net node) provides QUIC node that can establish
// abyss P2P connections and TLS client auth HTTPS connections.
// This implements ani (abyss new interface) for alpha release.
// TODO: AbyssNodeConfig for construction (backlog, firewall, logger, etc)
// Handshake failures result in errors returned from Accept().
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

// AbyssNode handles abyss/abyst handshakes, listening inbound connections.
// TODO: Close() should wait for ongoing handshake goroutines to terminate.
// This requires the goroutines to 1) check before executing, 2) check when terminate.
// TODO: abyss handshake does not timeout. Make it timeout, let the timeout duration adjustable.
// Issue: a node's identity is unvailed by dialing and checking if it decrypts the handshake.
// Do we assume that a peer with handshake encryption key cert already locates the peer? or not?
type AbyssNode struct {
	*sec.AbyssRootSecret
	*sec.TLSIdentity

	udpConn               *net.UDPConn
	transport             *quic.Transport
	listener              *quic.Listener
	local_addr_candidates []netip.AddrPort

	service_ctx        context.Context
	service_cancelfunc context.CancelFunc

	dial_stats         DialInfoMap
	verified_tls_certs *sec.VerifiedTlsCertMap

	peer_ctor *PeerConstructor
}

func NewAbyssNode(root_private_key sec.PrivateKey) (*AbyssNode, error) {
	root_secret, err := sec.NewAbyssRootSecrets(root_private_key)
	if err != nil {
		return nil, err
	}

	tls_identity, err := root_secret.NewTLSIdentity()
	if err != nil {
		return nil, err
	}

	dial_ctx, dial_cancelfunc := context.WithCancel(context.Background())

	return &AbyssNode{
		AbyssRootSecret: root_secret,
		TLSIdentity:     tls_identity,

		udpConn:               nil,
		transport:             nil,
		listener:              nil,
		local_addr_candidates: make([]netip.AddrPort, 0),

		service_ctx:        dial_ctx,
		service_cancelfunc: dial_cancelfunc,

		dial_stats:         MakeDialInfoMap(),
		verified_tls_certs: sec.NewVerifiedTlsCertMap(),
	}, nil
}

func newQuicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  time.Second * 20,
		KeepAlivePeriod: time.Second * 5,
		EnableDatagrams: true,
	}
}

func (n *AbyssNode) Listen() error {
	var err error
	n.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}

	n.transport = &quic.Transport{Conn: n.udpConn}
	n.listener, err = n.transport.Listen(n.NewServerTlsConf(n.verified_tls_certs), newQuicConfig())
	if err != nil {
		return err
	}

	bind_addr, ok := n.listener.Addr().(*net.UDPAddr)
	if !ok {
		return errors.New("failed to get listener bind address")
	}
	port := uint16(bind_addr.Port)

	// query all network interfaces.
	{
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range ifaces {
			// Skip disabled interfaces
			if iface.Flags&net.FlagUp == 0 {
				continue
			}

			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				// sugar - go standard library has varying spec over platforms.
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip == nil || ip.To4() == nil {
					continue
				}

				netip_ip, ok := netip.AddrFromSlice(ip.To4())
				if !ok {
					continue
				}
				n.local_addr_candidates = append(
					n.local_addr_candidates,
					netip.AddrPortFrom(netip_ip, port),
				)
			}
		}
	}
	return nil
}

// Serve is the main server loop of AbyssNode.
// It waits for incoming connections on quic.Listener in a loop.
func (n *AbyssNode) Serve() error {
	// start peer identity waiter cleaning loop.
	go func() {
		for {
			select {
			case <-n.service_ctx.Done():
				return
			case <-time.After(time.Minute * 3):
				n.dial_stats.CleaupWaiter()
			}
		}
	}()

	for {
		connection, err := n.listener.Accept(n.service_ctx)
		if err != nil {
			var remote_addr netip.AddrPort
			if connection != nil {
				a := connection.RemoteAddr().(*net.UDPAddr)
				remote_addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte(a.IP.To4())), uint16(a.Port))
			}
			switch v := err.(type) {
			case net.Error:
				if v.Timeout() {
					n.peer_ctor.AppendError(remote_addr, false, v)
					continue
				}
			case *quic.ApplicationError, *quic.TransportError, *quic.VersionNegotiationError:
				n.peer_ctor.AppendError(remote_addr, false, v)
				continue
			default:
			}
			return n.cleanUp(err)
		}

		switch connection.ConnectionState().TLS.NegotiatedProtocol {
		case sec.NextProtoAbyss:
			go n.serveAbyssInbound(connection)
		default:
			connection.CloseWithError(0, "unsupported application layer protocol")
		}
	}
}

func (n *AbyssNode) serveAbyssInbound(connection quic.Connection) {
	// get address (for logging)
	a := connection.RemoteAddr().(*net.UDPAddr)
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte(a.IP.To4())), uint16(a.Port))

	// get self-signed TLS certificate that the peer presented.
	tls_info := connection.ConnectionState().TLS
	client_tls_cert := tls_info.PeerCertificates[0]

	ahmp_stream, err := connection.AcceptStream(n.service_ctx)
	if err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to start AHMP")
		n.peer_ctor.AppendError(addr, false, err)
		return
	}
	ahmp_encoder := cbor.NewEncoder(ahmp_stream)
	ahmp_decoder := cbor.NewDecoder(ahmp_stream)

	// (handshake 1)
	// receive and decrypt peer's tls-binding certificate
	var handshake_1_message ahmp.RawHS1
	if err = ahmp_decoder.Decode(&handshake_1_message); err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to receie AHMP")
		n.peer_ctor.AppendError(addr, false, err)
		return
	}
	tls_binding_cert_derBytes, err := n.DecryptHandshake(handshake_1_message.EncryptedCertificate, handshake_1_message.EncryptedSecret)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.peer_ctor.AppendError(addr, false, err)
		return
	}
	tls_binding_cert, err := x509.ParseCertificate(tls_binding_cert_derBytes)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.peer_ctor.AppendError(addr, false, err)
		return
	}

	// retrieve known identity
	peer_id := tls_binding_cert.Issuer.CommonName
	peer_identity, err := n.dial_stats.Get(n.service_ctx, peer_id)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.peer_ctor.AppendError(addr, false, err)
		return
	}

	// verify abyss-tls binding
	err = peer_identity.VerifyTLSBinding(tls_binding_cert, client_tls_cert)
	if err != nil {
		connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
		n.peer_ctor.AppendError(addr, false, err)
		return
	}

	// (handshake 2)
	// send local tls-abyss binding cert
	if err = ahmp_encoder.Encode(n.TLSIdentity.AbyssBindingCertificate()); err != nil {
		connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to transmit AHMP")
		n.peer_ctor.AppendError(addr, true, err)
		return
	}

	n.peer_ctor.Append(n.service_ctx, &AuthenticatedConnection{
		identity:     peer_identity,
		is_dialing:   false,
		connection:   connection,
		remote_addr:  addr,
		ahmp_encoder: ahmp_encoder,
		ahmp_decoder: ahmp_decoder,
	})
}

func (n *AbyssNode) cleanUp(serve_err error) error {
	// TODO: wait for worker goroutine to terminate.
	l_err := n.listener.Close()
	t_err := n.transport.Close()
	u_err := n.udpConn.Close()
	return errors.Join(serve_err, l_err, t_err, u_err)
}

func (n *AbyssNode) LocalAddrCandidates() []netip.AddrPort { return n.local_addr_candidates }

func (n *AbyssNode) AppendKnownPeer(root_cert string, handshake_key_cert string) error {
	identity, err := sec.NewAbyssPeerIdentityFromPEM(root_cert, handshake_key_cert)
	if err != nil {
		return err
	}

	n.dial_stats.UpdatePeerInformation(identity)
	return nil
}
func (n *AbyssNode) AppendKnownPeerDer(root_cert []byte, handshake_key_cert []byte) error {
	identity, err := sec.NewAbyssPeerIdentityFromDER(root_cert, handshake_key_cert)
	if err != nil {
		return err
	}

	n.dial_stats.UpdatePeerInformation(identity)
	return nil
}

func (n *AbyssNode) EraseKnownPeer(id string) {
	n.dial_stats.Remove(id)
}

func (n *AbyssNode) Dial(id string, addr netip.AddrPort) error {
	// query identity (we should have it in advance)
	peer_identity, err := n.dial_stats.AskDialingPermissionAndGetIdentity(id, addr.Addr())
	if err != nil {
		return err
	}

	go func() {
		defer func() {
			n.dial_stats.ReportDialTermination(id, addr.Addr())
		}()

		// dial
		connection, err := n.transport.Dial(
			n.service_ctx,
			&net.UDPAddr{
				IP:   addr.Addr().AsSlice(),
				Port: int(addr.Port()),
			},
			n.TLSIdentity.NewAbyssClientTlsConf(),
			newQuicConfig(),
		)
		if err != nil {
			n.peer_ctor.AppendError(addr, true, err)
			if connection != nil {
				connection.CloseWithError(0, "dial error")
			}
			return
		}

		// get ephemeral TLS certificate
		tls_info := connection.ConnectionState().TLS
		client_tls_cert := tls_info.PeerCertificates[0]

		// open ahmp stream
		ahmp_stream, err := connection.OpenStreamSync(n.service_ctx)
		if err != nil {
			connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to start AHMP")
			n.peer_ctor.AppendError(addr, true, err)
			return
		}
		ahmp_encoder := cbor.NewEncoder(ahmp_stream)
		ahmp_decoder := cbor.NewDecoder(ahmp_stream)

		// (handshake 1)
		// send local tls-abyss binding cert encrypted with remote handshake key.
		encrypted_cert, aes_secret, err := peer_identity.EncryptHandshake(n.TLSIdentity.AbyssBindingCertificate())
		if err != nil {
			connection.CloseWithError(AbyssQuicCryptoFail, "abyss cryptograhic failure")
			n.peer_ctor.AppendError(addr, true, err)
			return
		}
		handshake_1_message := &ahmp.RawHS1{
			EncryptedCertificate: encrypted_cert,
			EncryptedSecret:      aes_secret,
		}
		err = ahmp_encoder.Encode(handshake_1_message)
		if err != nil {
			connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to transmit AHMP")
			n.peer_ctor.AppendError(addr, true, err)
			return
		}

		// (handshake 2)
		// receive server-side tls-abyss binding and verify
		var handshake_2_message []byte
		err = ahmp_decoder.Decode(&handshake_2_message)
		if err != nil {
			connection.CloseWithError(AbyssQuicAhmpStreamFail, "failed to receive AHMP")
			n.peer_ctor.AppendError(addr, true, err)
			return
		}
		handshake_2_payload_x509, err := x509.ParseCertificate(handshake_2_message)
		if err != nil {
			connection.CloseWithError(AbyssQuicAuthenticationFail, "failed to parse certificate")
			n.peer_ctor.AppendError(addr, true, err)
			return
		}
		err = peer_identity.VerifyTLSBinding(handshake_2_payload_x509, client_tls_cert)
		if err != nil {
			connection.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
			n.peer_ctor.AppendError(addr, true, err)
			return
		}

		n.peer_ctor.Append(n.service_ctx, &AuthenticatedConnection{
			identity:     peer_identity,
			is_dialing:   true,
			connection:   connection,
			remote_addr:  addr,
			ahmp_encoder: ahmp_encoder,
			ahmp_decoder: ahmp_decoder,
		})
	}()
	return nil
}

func (n *AbyssNode) Accept(ctx context.Context) (*AbyssPeer, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case backlog_entry := <-n.peer_ctor.BackLog:
		return backlog_entry.peer, backlog_entry.err
	}
}

// Close gracefully closes AbyssNode.
// * Issue: Close() may not return when backlog is full.
// This is because when backlog is full, backlog appending call blocks,
// and the connection handling goroutines cannot terminate.
// 1. cancel context
// 2. wait for accepter to terminate
// 3. consume backlog until all goroutines terminate
// 4. signal Serve loop
func (n *AbyssNode) Close() error {
	n.service_cancelfunc()
	return nil
}

// func T() {
// 	root_key, err := sec.NewRootPrivateKey()
// 	var n ani.IAbyssNode
// 	n, err = NewAbyssNode(root_key)
// }
