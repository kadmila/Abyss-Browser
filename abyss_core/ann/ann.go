// Package ann (abyss net node) provides QUIC node that can establish
// abyss P2P connections and TLS client auth HTTPS connections.
// This implements ani (abyss new interface) for alpha release.
// TODO: AbyssNodeConfig for construction (backlog, firewall, logger, etc)
package ann

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
)

// AbyssNode handles abyss/abyst handshakes, listening inbound connections.
// TODO: Close() should wait for ongoing handshake goroutines to terminate.
// This requires the goroutines to 1) check before executing, 2) check when terminate.
type AbyssNode struct {
	*sec.AbyssRootSecret
	*sec.TLSIdentity

	udpConn               *net.UDPConn
	transport             *quic.Transport
	listener              *quic.Listener
	local_addr_candidates []netip.AddrPort

	dial_ctx        context.Context
	dial_cancelfunc context.CancelFunc

	dial_stats         DialStatusMap
	verified_tls_certs *sec.VerifiedTlsCertMap
	backlog            chan *AbyssPeer

	backlog_join_mtx sync.Mutex

	peers            map[string]*AbyssConnection
	inbound_backlog  map[string]*InboundConnection
	outbound_backlog map[string]*OutboundConnection
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

		dial_ctx:        dial_ctx,
		dial_cancelfunc: dial_cancelfunc,

		dial_stats:         MakePeerStatusMap(),
		verified_tls_certs: sec.NewVerifiedTlsCertMap(),
		backlog:            make(chan *AbyssPeer, 128),

		peers:            make(map[string]*AbyssConnection),
		inbound_backlog:  make(map[string]*InboundConnection),
		outbound_backlog: make(map[string]*OutboundConnection),
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

func (n *AbyssNode) Serve() error {
	// TODO
	n.listener.Close()
	n.transport.Close()
	n.udpConn.Close()
	return nil
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

func (n *AbyssNode) Dial(id string, addr *netip.AddrPort) error {
	peer_identity, err := n.dial_stats.TryAppendDialingAndGetIdentity(id, addr.Addr())
	if err != nil {
		return err
	}

	go func() {
		var err error
		defer func() {
			if err != nil {
				n.dial_stats.ReportDialFailure(id, addr.Addr())
			}
		}()

		// dial
		conn, err := n.transport.Dial(
			n.dial_ctx,
			&net.UDPAddr{
				IP:   addr.Addr().AsSlice(),
				Port: int(addr.Port()),
			},
			n.TLSIdentity.NewAbyssClientTlsConf(),
			newQuicConfig(),
		)
		if err != nil {
			return
		}

		// get ephemeral TLS certificate
		tls_info := conn.ConnectionState().TLS
		client_tls_cert := tls_info.PeerCertificates[0]

		// open ahmp stream
		ahmp_stream, err := conn.OpenStreamSync(n.dial_ctx)
		if err != nil {
			conn.CloseWithError(AbyssQuicAhmpStreamFail, "failed to start AHMP")
			return
		}
		ahmp_encoder := cbor.NewEncoder(ahmp_stream)
		ahmp_decoder := cbor.NewDecoder(ahmp_stream)

		// send local tls-abyss binding cert encrypted with remote handshake key.
		encrypted_cert, aes_secret, err := peer_identity.EncryptHandshake(n.TLSIdentity.AbyssBindingCertificate())
		if err != nil {
			conn.CloseWithError(AbyssQuicCryptoFail, "abyss cryptograhic failure")
			return
		}
		handshake_1_payload := &ahmp.HS1{
			EncryptedCertificate: encrypted_cert,
			EncryptedSecret:      aes_secret,
		}
		err = ahmp_encoder.Encode(handshake_1_payload)
		if err != nil {
			conn.CloseWithError(AbyssQuicAhmpStreamFail, "failed to transmit AHMP")
			return
		}

		// receive accepter-side self-authentication
		var handshake_2_payload []byte
		err = ahmp_decoder.Decode(&handshake_2_payload)
		if err != nil {
			conn.CloseWithError(AbyssQuicAhmpStreamFail, "failed to receive AHMP")
			return
		}
		handshake_2_payload_x509, err := x509.ParseCertificate(handshake_2_payload)
		if err != nil {
			conn.CloseWithError(AbyssQuicAuthenticationFail, "failed to parse certificate")
			return
		}
		err = peer_identity.VerifyTLSBinding(handshake_2_payload_x509, client_tls_cert)
		if err != nil {
			conn.CloseWithError(AbyssQuicAuthenticationFail, "invalid certificate")
			return
		}

		n.OutboundConnectionJoin(id, conn, peer_identity)

		// wait for 1) inbound completion, or 2) peer disconnect
	}()
	return nil
}

func (n *AbyssNode) OutboundConnectionJoin(id string, connection quic.Connection, identity *sec.AbyssPeerIdentity) {
	n.backlog_join_mtx.Lock()
	defer n.backlog_join_mtx.Unlock()

	if _, ok := n.peers[id]; ok {
		conn.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
		return
	}

	outbound_conn, ok := n.outbound_backlog[id]
	if ok {
		conn.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
	}

	inbound_conn, ok := n.inbound_backlog[id]
	if ok {

	} else {
		n.outbound_backlog[id]
	}
}

func (n *AbyssNode) Accept(ctx context.Context) (*AbyssPeer, error) {
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

// TODO func (n *AbyssNode) NewAbystClient() (IAbystClient, error) {}

// TODO NewCollocatedHttp3Client() (http.Client, error)

func (n *AbyssNode) Close() error {
	n.dial_cancelfunc()
	return nil
}

// func T() {
// 	root_key, err := sec.NewRootPrivateKey()
// 	var n ani.IAbyssNode
// 	n, err = NewAbyssNode(root_key)
// }
