// Package ann (abyss net node) provides QUIC node that can establish
// abyss P2P connections and TLS client auth HTTPS connections.
// This implements ani (abyss new interface) for alpha release.
// TODO: AbyssNodeConfig for construction (backlog, firewall, logger, etc)
package ann

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
)

type AbyssNode struct {
	*sec.AbyssRootSecret
	*sec.TLSIdentity

	udpConn               *net.UDPConn
	transport             *quic.Transport
	listener              *quic.Listener
	local_addr_candidates []netip.AddrPort

	dial_ctx        context.Context
	dial_cancelfunc context.CancelFunc

	HandshakeHandler
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

		HandshakeHandler: MakeHandshakeHandler(),
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
	n.HandshakeHandler.run()

	n.listener.Close()
	return nil
}

func (n *AbyssNode) LocalAddrCandidates() []netip.AddrPort { return n.local_addr_candidates }

// TODO func (n *AbyssNode) NewAbystClient() (IAbystClient, error) {}

// TODO NewCollocatedHttp3Client() (http.Client, error)

func (n *AbyssNode) Dial(id string, addr *netip.AddrPort) error {
	return n.dial(id, addr, n.transport)
}

func (n *AbyssNode) Close() error {
	n.dial_cancelfunc()
	return nil
}

// func T() {
// 	root_key, err := sec.NewRootPrivateKey()
// 	var n ani.IAbyssNode
// 	n, err = NewAbyssNode(root_key)
// }
