// Package ann (abyss net node) provides QUIC node that can establish
// abyss P2P connections and TLS client auth HTTPS connections.
// This implements ani (abyss new interface) for alpha release.
// TODO: AbyssNodeConfig for construction (backlog, firewall, logger, etc)
// Handshake failures result in errors returned from Accept().
package ann

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/abyst"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/config"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type backLogEntry struct {
	peer *AbyssPeer
	err  *HandshakeError
}

// AbyssNode handles abyss/abyst handshakes, listening inbound connections.
// TODO: Close() should wait for ongoing handshake goroutines to terminate.
// This requires the goroutines to 1) check before executing, 2) check when terminate.
// TODO: abyss handshake does not timeout. Make it timeout, let the timeout duration adjustable.
// Issue: a node's identity is unvailed by dialing and checking if it decrypts the handshake.
// Do we assume that a peer with handshake encryption key cert already locates the peer? or not?
type AbyssNode struct {
	*sec.AbyssRootSecret
	*sec.TLSIdentity

	udpConn   *net.UDPConn
	testConn  *DelayConn // debug
	transport *quic.Transport
	listener  *quic.Listener
	port      uint16

	service_ctx        context.Context
	service_cancelfunc context.CancelFunc

	registry *AbyssPeerRegistry

	backlog chan backLogEntry

	serve_wg sync.WaitGroup // For serveRoutine/dialRoutine

	close_check_mtx sync.Mutex
	close_cause     error

	abyst_hub *abyst.AbystGateway
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

	service_ctx, service_cancelfunc := context.WithCancel(context.Background())

	return &AbyssNode{
		AbyssRootSecret: root_secret,
		TLSIdentity:     tls_identity,

		udpConn:   nil,
		testConn:  nil,
		transport: nil,
		listener:  nil,

		service_ctx:        service_ctx,
		service_cancelfunc: service_cancelfunc,

		registry: NewAbyssPeerRegistry(),

		backlog: make(chan backLogEntry, 128),

		abyst_hub: abyst.NewAbystGateway(),
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

	// debug tool
	if config.DEBUG {
		n.testConn = NewDelayConn(n.udpConn, time.Millisecond*10, time.Millisecond*20)
		n.transport = &quic.Transport{Conn: n.testConn}
	} else {
		n.transport = &quic.Transport{Conn: n.udpConn}
	}
	// or
	//
	// normal

	n.listener, err = n.transport.Listen(n.NewServerTlsConf(n.registry), newQuicConfig())
	if err != nil {
		return err
	}

	bind_addr, ok := n.listener.Addr().(*net.UDPAddr)
	if !ok {
		return errors.New("failed to get listener bind address")
	}
	n.port = uint16(bind_addr.Port)

	// update handshake certificate
	if err := n.UpdateHandshakeInfo(n.LocalAddrCandidates()); err != nil {
		return err
	}
	return nil
}

// Serve is the main server loop of AbyssNode.
// It waits for incoming connections on quic.Listener in a loop.
func (n *AbyssNode) Serve() error {
	var err error
MAIN_LOOP:
	for {
		var connection *quic.Conn
		connection, err = n.listener.Accept(n.service_ctx)
		if err != nil {
			var addr netip.AddrPort
			if connection != nil {
				addr = connection.RemoteAddr().(*net.UDPAddr).AddrPort()
			}
			n.backlogPushErr(NewHandshakeError(
				err,
				addr,
				"",
				false,
				HS_Connection,
				HS_Fail_TransportFail,
			))
			// Currently, we don't recover from Accept() failure.
			// But, should we?
			break MAIN_LOOP
		}

		switch connection.ConnectionState().TLS.NegotiatedProtocol {
		case sec.NextProtoAbyss:
			n.serve_wg.Add(1)
			go n.serveRoutine(connection)
		case http3.NextProtoH3:
			// get ephemeral TLS certificate
			tls_info := connection.ConnectionState().TLS
			client_tls_cert := tls_info.PeerCertificates[0]
			peer_id, ok := n.registry.GetPeerIdFromTlsCertificate(client_tls_cert)
			if !ok {
				connection.CloseWithError(AbystQuicNoAbyss, "no abyss connection")
				break
			}
			n.abyst_hub.ServeConnection(connection, peer_id)
		default:
			connection.CloseWithError(0, "unsupported application layer protocol")
		}
	}
	n.close_check_mtx.Lock()
	n.close_cause = err
	n.close_check_mtx.Unlock()

	n.serve_wg.Wait()
	close(n.backlog)
	return n.cleanUp(err)
}

func (n *AbyssNode) cleanUp(serve_err error) error {
	// TODO: wait for worker goroutine to terminate.
	l_err := n.listener.Close()
	t_err := n.transport.Close()
	u_err := n.udpConn.Close()
	return errors.Join(serve_err, l_err, t_err, u_err)
}

func (n *AbyssNode) LocalAddrCandidates() []netip.AddrPort {
	result := make([]netip.AddrPort, 0)
	// query all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
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
			result = append(
				result,
				netip.AddrPortFrom(netip_ip, n.port),
			)
		}
	}
	return result
}

// AppendKnownPeer returns true if the peer is newly added
func (n *AbyssNode) AppendKnownPeer(root_cert string, handshake_info_cert string) (string, bool, error) {
	root_self_cert_der, _ := pem.Decode([]byte(root_cert))
	if root_self_cert_der == nil {
		return "", false, errors.New("failed to parse certificate")
	}
	handshake_info_cert_der, _ := pem.Decode([]byte(handshake_info_cert))
	if handshake_info_cert_der == nil {
		return "", false, errors.New("failed to parse certificate")
	}
	return n.AppendKnownPeerDer(root_self_cert_der.Bytes, handshake_info_cert_der.Bytes)
}

// AppendKnownPeerDer returns true if the peer is newly added
func (n *AbyssNode) AppendKnownPeerDer(root_cert []byte, handshake_info_cert []byte) (string, bool, error) {
	root_self_cert_x509, err := x509.ParseCertificate(root_cert)
	if err != nil {
		return "", false, err
	}
	handshake_info_cert_x509, err := x509.ParseCertificate(handshake_info_cert)
	if err != nil {
		return "", false, err
	}
	ok, err := n.registry.AddOrUpdatePeerIdentity(root_self_cert_x509, handshake_info_cert_x509)
	return root_self_cert_x509.Issuer.CommonName, ok, err
}

func (n *AbyssNode) EraseKnownPeer(id string) bool {
	return n.registry.TryRemovePeerIdentity(id)
}

// Dial synchronously check for dialing plausibility, and
// start a goroutine for handshake procedure.
func (n *AbyssNode) Dial(id string) error {
	// query identity and dialing permission
	// TODO: this should be separated.
	peer_identity, registry_status := n.registry.GetPeerIdentityIfDialable(id)
	switch registry_status {
	case RE_OK:
		// Proceed.
	case RE_Redundant:
		return NewHandshakeError(
			errors.New("redundant dial"),
			netip.AddrPort{},
			id,
			true,
			HS_Connection,
			HS_Fail_Redundant,
		)
	case RE_UnknownPeer:
		return NewHandshakeError(
			errors.New("unknown peer"),
			netip.AddrPort{},
			id,
			true,
			HS_Connection,
			HS_Fail_UnknownPeer,
		)
	}

	// Checks if AbyssNode is not yet closed, and also register for waitgroup for each goroutine.
	n.close_check_mtx.Lock()
	defer n.close_check_mtx.Unlock()

	if n.close_cause != nil {
		return n.close_cause
	}

	address_candidates := peer_identity.AddressCandidates()
	for _, addr := range address_candidates {
		n.serve_wg.Add(1)
		go n.dialRoutine(addr, peer_identity)
	}
	return nil
}

func (n *AbyssNode) Accept(ctx context.Context) (ani.IAbyssPeer, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case backlog_entry, ok := <-n.backlog:
		if !ok {
			// This lock is pretty much unnecessary (memory barrier due to channel close),
			// but just in case..
			n.close_check_mtx.Lock()
			err := n.close_cause
			n.close_check_mtx.Unlock()

			return nil, err
		}
		if backlog_entry.err != nil {
			return backlog_entry.peer, backlog_entry.err
		}
		return backlog_entry.peer, nil
	}
}

func (n *AbyssNode) ConfigAbystGateway(config string) error {
	return n.abyst_hub.SetInternalMuxFromJson(config)
}

func (n *AbyssNode) AbystDial(
	ctx context.Context,
	dial_subject string,
	_ *tls.Config, _ *quic.Config,
) (*quic.Conn, error) {
	peer_id := strings.Split(dial_subject, ".")[0]
	peer, ok := n.registry.GetPeer(peer_id)
	if !ok {
		return nil, errors.New("abyst: host unreachable")
	}
	netip_addr := peer.remote_addr
	earlyconn, err := n.transport.DialEarly(
		ctx,
		&net.UDPAddr{
			IP:   netip_addr.Addr().AsSlice(),
			Port: int(netip_addr.Port()),
		},
		n.TLSIdentity.NewAbystClientTlsConf(n.registry),
		newQuicConfig(),
	)
	return earlyconn, err
}

func (n *AbyssNode) NewAbystClient() *abyst.AbystClient {
	return &abyst.AbystClient{
		Client: &http.Client{
			Transport: &http3.Transport{
				TLSClientConfig: n.NewAbystClientTlsConf(n.registry),
				QUICConfig:      newQuicConfig(),
				Dial:            n.AbystDial,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // force no redirect
			},
		},
	}
}

func (n *AbyssNode) NewCollocatedHttp3Client() *http.Client {
	return &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: n.NewCollocatedH3TlsConf(),
			QUICConfig:      newQuicConfig(),
			Dial: func(ctx context.Context, addr string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
				udpAddr, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					return nil, err
				}
				return n.transport.DialEarly(ctx, udpAddr, n.NewCollocatedH3TlsConf(), nil)
			},
		},
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
