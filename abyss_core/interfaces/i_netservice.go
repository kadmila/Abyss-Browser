package interfaces

import (
	"net"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"

	"github.com/quic-go/quic-go"
)

type IPreAccepter interface {
	PreAccept(peer_hash string, address *net.UDPAddr) (bool, int, string)
}

type AbystInboundSession struct {
	PeerHash   string
	Connection quic.Connection
}

// 1. AbyssAsync 'always' succeeds, resulting in IANDPeer -> if connection failed, IANDPeer methods return error.
// 2. Abyst may fail at any moment
type INetworkService interface {
	LocalIdentity() IHostIdentity
	LocalAURL() *aurl.AURL

	HandlePreAccept(preaccept_handler IPreAccepter) // if false, return status code and message

	ListenAndServe() error

	AppendKnownPeer(root_cert string, handshake_key_cert string) error
	AppendKnownPeerDer(root_cert []byte, handshake_key_cert []byte) error

	GetAbyssPeerChannel() chan IANDPeer //wait for established abyss mutual connection

	ConnectAbyssAsync(url *aurl.AURL) error                 //may return error if peer information has expired.
	ConnectAbyst(peer_hash string) (quic.Connection, error) //should take ~2 rtt.
}

type IAddressSelector interface {
	LocalPrivateIPAddr() net.IP
	FilterAddressCandidates(addresses []*net.UDPAddr) []*net.UDPAddr
}

// TLS ALPN code
const NextProtoAbyss = "abyss"
