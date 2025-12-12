// Package ann (abyss net node) provides QUIC node that can establish
// abyss P2P connections and TLS client auth HTTPS connections.
// This implements ani (abyss new interface) for alpha release.
// TODO: AbyssNodeConfig for construction (backlog, firewall, logger, etc)
// Handshake failures result in errors returned from Accept().
package ann

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
)

type backLogEntry struct {
	peer *AbyssPeer
	err  error
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

	udpConn               *net.UDPConn
	testConn              *DelayConn // debug
	transport             *quic.Transport
	listener              *quic.Listener
	local_addr_candidates []netip.AddrPort

	service_ctx        context.Context
	service_cancelfunc context.CancelFunc

	dial_stats DialInfoMap
	registry   *AbyssPeerRegistry

	backlog chan backLogEntry
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
		testConn:              nil,
		transport:             nil,
		listener:              nil,
		local_addr_candidates: make([]netip.AddrPort, 0),

		service_ctx:        dial_ctx,
		service_cancelfunc: dial_cancelfunc,

		dial_stats:         MakeDialInfoMap(),
		verified_tls_certs: sec.NewVerifiedTlsCertMap(),

		backlog:         make(chan backLogEntry, 128),
		connected_peers: make(map[string]*AbyssPeer),
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
	n.testConn = NewDelayConn(n.udpConn, time.Millisecond*10, time.Millisecond*20)
	n.transport = &quic.Transport{Conn: n.testConn}
	// or
	// n.transport = &quic.Transport{Conn: n.udpConn}
	// normal

	n.listener, err = n.transport.Listen(n.NewServerTlsConf(n.verified_tls_certs), newQuicConfig())
	if err != nil {
		return err
	}

	bind_addr, ok := n.listener.Addr().(*net.UDPAddr)
	if !ok {
		return errors.New("failed to get listener bind address")
	}
	port := uint16(bind_addr.Port)

	// query all network interfaces to fill local_addr_candidates
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
	return nil
}

// Serve is the main server loop of AbyssNode.
// It waits for incoming connections on quic.Listener in a loop.
func (n *AbyssNode) Serve() error {
	// start peer identity waiter cleaning loop.
	waiter_clean_loop_termiate_ch := make(chan bool)
	go func() {
		for {
			select {
			case <-n.service_ctx.Done():
				waiter_clean_loop_termiate_ch <- true
				return
			case <-time.After(time.Minute * 3):
				n.dial_stats.CleaupWaiter()
			}
		}
	}()

	var err error
	for {
		var connection quic.Connection
		connection, err = n.listener.Accept(n.service_ctx)
		if err != nil {
			var remote_addr netip.AddrPort
			if connection != nil {
				a := connection.RemoteAddr().(*net.UDPAddr)
				remote_addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte(a.IP.To4())), uint16(a.Port))
			}
			switch v := err.(type) {
			case net.Error:
				if v.Timeout() {
					n.backlogAppendError(remote_addr, false, v)
					continue
				}
			case *quic.ApplicationError, *quic.TransportError, *quic.VersionNegotiationError:
				n.backlogAppendError(remote_addr, false, v)
				continue
			}
			break
		}

		switch connection.ConnectionState().TLS.NegotiatedProtocol {
		case sec.NextProtoAbyss:
			go n.serveRoutine(connection)
		default:
			connection.CloseWithError(0, "unsupported application layer protocol")
		}
	}

	<-waiter_clean_loop_termiate_ch
	return n.cleanUp(err)
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

// Dial synchronously check for dialing plausibility, and
// start a goroutine for handshake procedure.
func (n *AbyssNode) Dial(id string, addr netip.AddrPort) error {
	// query identity and dialing permission
	// TODO: this should be separated.
	peer_identity, err := n.dial_stats.AskDialingPermissionAndGetIdentity(id, addr.Addr())
	if err != nil {
		return err
	}

	go n.dialRoutine(id, addr, peer_identity)
	return nil
}

func (n *AbyssNode) Accept(ctx context.Context) (ani.IAbyssPeer, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case backlog_entry := <-n.backlog:
		return backlog_entry.peer, backlog_entry.err
	}
}

func (n *AbyssNode) NewAbystClient() (ani.IAbystClient, error) {
	return nil, nil
}

func (n *AbyssNode) NewCollocatedHttp3Client() (*http.Client, error) {
	return nil, nil
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
