// ani (abyss new interface) is a refined abyss interface set
// for abyss alpha release.
// This is designed for better testability and readability.
package ani

import (
	"context"
	"io"
	"net/http"
	"net/netip"
)

type IAbyssPeerIdentity interface {
	ID() string
	RootCertificate() string //pem
	RootCertificateDer() []byte
	HandshakeKeyCertificate() string //pem
	HandshakeKeyCertificateDer() []byte
}

// IAbyssNode defines an abyss node.
// It is constructed from ann.Listen() (IAbyssNode, error).
// It may implement abyst server internally.
type IAbyssNode interface {
	IAbyssPeerIdentity
	LocalIPs() []*netip.Addr
	Port() uint16

	Accept(context.Context) (IAbyssPeer, error)

	// Dial returns error only for unknown hash or invalid address.
	// When connected, the connection can be retrieved from Accept().
	Dial(hash string, addr *netip.AddrPort) error

	// AppendKnownPeer adds peer information for mutual auth.
	AppendKnownPeer(root_cert string, handshake_key_cert string) error
	AppendKnownPeerDer(root_cert []byte, handshake_key_cert []byte) error

	// NewAbystClient creates an instance of abyst client.
	NewAbystClient() (IAbystClient, error)

	// NewCollocatedHttpClient provides HTTP/3 client that runs on the same
	// QUIC host with the abyst node, with TLS client auth enabled.
	NewCollocatedHttp3Client() (http.Client, error)

	// Close internal loop.
	// After it returns, Accept() will only return error.
	// Incoming connections are rejected.
	Close() error
}

// IAbyssPeer is an interface for sending ahmp messages to a connected peer.
// Inbound messages are handled by internal handlers.
type IAbyssPeer interface {
	IAbyssPeerIdentity
	// Locations are the confirmed address candidates.
	// They accumulate after connection establishment.
	Locations() []*netip.AddrPort

	// RemoteAddr is the actual connection endpoint, among Locations.
	RemoteAddr() *netip.AddrPort

	// Sends ahmp messages. Encoding details are defined in ahmp package.
	Send(any) error

	Close() error
}

// IAbystClient is abyst http/3 client, with customized
// redirect/cache/cookie handling mechanism.
// This **not** compatible with standard http client, and only processes abyst: scheme.
type IAbystClient interface {
	Get(url string) (resp *http.Response, err error)
	Head(url string) (resp *http.Response, err error)
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
}
