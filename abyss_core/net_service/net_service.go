package net_service

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"
)

type BetaNetService struct {
	ctx context.Context

	localIdentity   *RootSecrets
	local_aurl      *aurl.AURL
	addressSelector abyss.IAddressSelector

	quicTransport *quic.Transport
	tlsIdentity   *TLSIdentity
	abyssTlsConf  *tls.Config
	abystTlsConf  *tls.Config
	quicConf      *quic.Config

	preAccepter abyss.IPreAccepter

	peers *ContextedPeerMap

	abyssPeerCH chan abyss.IANDPeer //before actually using the peer, each thread must check IsConnected()

	abystServer *http3.Server
}

func NewBetaNetService(ctx context.Context, local_private_key PrivateKey, address_selector abyss.IAddressSelector, abyst_server *http3.Server) (*BetaNetService, error) {
	result := new(BetaNetService)

	result.ctx = ctx

	root_secret, err := NewRootIdentity(local_private_key)
	if err != nil {
		return nil, err
	}
	result.localIdentity = root_secret
	result.addressSelector = address_selector

	tls_identity, err := root_secret.NewTLSIdentity()
	if err != nil {
		return nil, err
	}
	result.tlsIdentity = tls_identity
	result.abyssTlsConf = NewDefaultTlsConf(tls_identity)

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	result.quicTransport = &quic.Transport{Conn: udpConn}
	result.quicConf = NewDefaultQuicConf()

	local_port := strconv.Itoa(udpConn.LocalAddr().(*net.UDPAddr).Port)
	local_ip := address_selector.LocalPrivateIPAddr().String()
	local_aurl, err := aurl.TryParse("abyss:" +
		root_secret.IDHash() +
		":" + local_ip + ":" + local_port +
		"|127.0.0.1:" + local_port)
	if err != nil {
		return nil, err
	}
	result.local_aurl = local_aurl

	result.peers = NewContextedPeerMap()

	result.abyssPeerCH = make(chan abyss.IANDPeer, 8)

	result.abystTlsConf = NewDefaultTlsConf(tls_identity)
	result.abystTlsConf.NextProtos = []string{http3.NextProtoH3} //abyst only.
	result.abystServer = abyst_server

	return result, nil
}

func NewDefaultTlsConf(tls_identity *TLSIdentity) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{tls_identity.tls_self_cert},
				PrivateKey:  tls_identity.priv_key,
			},
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) > 1 {
				return errors.New("too many TLS peer certificate")
			}
			cert := cs.PeerCertificates[0]
			if err := cert.CheckSignatureFrom(cert); err != nil {
				return errors.Join(errors.New("TLS Verify Failed"), err)
			}
			return nil
		},
		NextProtos:         []string{abyss.NextProtoAbyss, http3.NextProtoH3},
		ServerName:         "abyss",
		ClientAuth:         tls.RequireAnyClientCert,
		InsecureSkipVerify: true,
	}
}

func NewDefaultQuicConf() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                time.Hour,
		AllowConnectionWindowIncrease: func(conn quic.Connection, delta uint64) bool { return true },
		KeepAlivePeriod:               time.Second * 5,
		Allow0RTT:                     true,
		EnableDatagrams:               true,
	}
}

func (h *BetaNetService) LocalIdentity() abyss.IHostIdentity {
	return h.localIdentity
}
func (h *BetaNetService) LocalAURL() *aurl.AURL {
	return h.local_aurl
}

func (h *BetaNetService) HandlePreAccept(preaccept_handler abyss.IPreAccepter) {
	h.preAccepter = preaccept_handler
}

func (h *BetaNetService) ListenAndServe() error {
	listener, err := h.quicTransport.Listen(h.abyssTlsConf, h.quicConf)
	if err != nil {
		return err
	}
	//go h.constructingAbyssPeers(ctx)

	for {
		connection, err := listener.Accept(h.ctx)
		if err != nil {
			return err
		}
		switch connection.ConnectionState().TLS.NegotiatedProtocol {
		case abyss.NextProtoAbyss:
			go h.PrepareAbyssInbound(h.ctx, connection)
		case http3.NextProtoH3:
			go h.abystServer.ServeQUICConn(connection)
		default:
			connection.CloseWithError(0, "unknown TLS ALPN protocol ID")
		}
	}
}

func (h *BetaNetService) AppendKnownPeer(root_cert string, handshake_key_cert string) error {
	root_cert_block, _ := pem.Decode([]byte(root_cert))
	if root_cert_block == nil {
		return errors.New("failed to parse peer certificates")
	}
	handshake_key_cert_block, _ := pem.Decode([]byte(handshake_key_cert))
	if handshake_key_cert_block == nil {
		return errors.New("failed to parse peer certificates")
	}

	return h.AppendKnownPeerDer(root_cert_block.Bytes, handshake_key_cert_block.Bytes)
}
func (h *BetaNetService) AppendKnownPeerDer(root_cert []byte, handshake_key_cert []byte) error {
	//Future: allow updating handshake key? may not? unsure.
	peer_identity, err := NewPeerIdentity(root_cert, handshake_key_cert)
	if err != nil {
		return err
	}

	h.peers.Append(h.ctx, peer_identity.root_id_hash, NewAbyssPeer(*peer_identity))
	return nil
}

func (h *BetaNetService) GetAbyssPeerChannel() chan abyss.IANDPeer {
	return h.abyssPeerCH
}

func (h *BetaNetService) ConnectAbyssAsync(url *aurl.AURL) error {
	if url.Scheme != "abyss" {
		return errors.New("url scheme mismatch")
	}

	candidate_addresses := h.addressSelector.FilterAddressCandidates(url.Addresses)
	if len(candidate_addresses) == 0 {
		return errors.New("no valid IP address")
	}

	peer, ok := h.peers.Find(url.Hash)
	if !ok {
		return errors.New("unknown peer")
	}

	go h.PrepareAbyssOutbound(peer, candidate_addresses)
	return nil
}
func (h *BetaNetService) ConnectAbyst(peer_hash string) (quic.Connection, error) {
	if peer_hash == h.localIdentity.root_id_hash || peer_hash == "local" { //loopback
		connection, err := h.quicTransport.Dial(h.ctx, h.local_aurl.Addresses[len(h.local_aurl.Addresses)-1], h.abystTlsConf, h.quicConf)
		if err != nil {
			return nil, err
		}

		return connection, nil
	}

	peer, ok := h.peers.Find(peer_hash)
	if !ok {
		return nil, errors.New("no abyss connection")
	}
	if peer.state != PNCS_CONNECTED {
		return nil, errors.New("abyss connection closed and not reconnected")
	}
	connection, err := h.quicTransport.Dial(peer.ctx, peer.outbound_conn.RemoteAddr(), h.abystTlsConf, h.quicConf)
	if err != nil {
		return nil, err
	}

	return connection, nil
}
