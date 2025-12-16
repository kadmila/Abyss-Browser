// ani (abyss new interface) is a refined abyss interface set
// for abyss alpha release.
// This is designed for better testability and readability.
package ani

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
)

type IAbyssPeerIdentity interface {
	ID() string
	RootCertificate() string //pem
	RootCertificateDer() []byte
	HandshakeKeyCertificate() string //pem
	HandshakeKeyCertificateDer() []byte
	IssueTime() time.Time
}

// *Note*
// When a peer disconnects and re-connects the same peer,
// both peers do not accept the new connection before
// Close() is called for the old connection with the same peer.
// This is a design for better application-layer state management.

// IAbyssNode defines an abyss node.
// It is constructed from ann.Listen() (IAbyssNode, error).
// It may implement abyst server internally.
type IAbyssNode interface {
	IAbyssPeerIdentity

	// Listen binds network interface, starts service.
	// Do Not call Listen() and Serve() twice.
	// The AbyssNode is designed for single-use.
	Listen() error

	// Serve is the main service loop.
	// It returns when Close() is called or when it crashed.
	// Please file a bug report when it crashes.
	Serve() error

	// LocalAddrCandidates is the list of addresses for bound network interfaces.
	// The return value must not be mutated.
	LocalAddrCandidates() []netip.AddrPort

	// AppendKnownPeer adds peer information for mutual auth.
	// This is mendatory before Dial() and Accept().
	AppendKnownPeer(root_cert string, handshake_key_cert string) error
	AppendKnownPeerDer(root_cert []byte, handshake_key_cert []byte) error

	// EraseKnownPeer removes peer information.
	// The peer cannot be dialed until the peer information is re-provided.
	EraseKnownPeer(id string)

	// Dial returns error only for unknown hash or invalid address.
	// When connected, the connection can be retrieved from Accept().
	Dial(hash string, addr netip.AddrPort) error

	// Accept returns a newly established peer.
	Accept(ctx context.Context) (IAbyssPeer, error)

	// ConfigAbystGateway configures abyst gateway from a json string.
	// read (link will be here) for details.
	ConfigAbystGateway(config string) error

	// NewAbystClient creates an instance of abyst client.
	NewAbystClient() (IAbystClient, error)

	// NewCollocatedHttpClient provides HTTP/3 client that runs on the same
	// QUIC host with the abyst node, with TLS client auth enabled.
	NewCollocatedHttp3Client() (*http.Client, error)

	// Close terminates internal loop.
	// Even after Listen() failes, Close() should be called.
	// DO NOT reuse AbyssNode after Close().
	// After it returns, Accept() will only return error.
	// Incoming connections are rejected.
	// LocalAddrCandidates will be emptied.
	Close() error
}

type IAbystTlsCertChecker interface {
	GetPeerIdFromTlsCertificate(certificate *x509.Certificate) (string, bool)
}

// IAbyssPeer is an interface for sending ahmp messages to a connected peer.
// Inbound messages are handled by internal handlers.
type IAbyssPeer interface {
	IAbyssPeerIdentity

	// RemoteAddr is the actual connection endpoint, among RemoteAddrCandidates.
	RemoteAddr() netip.AddrPort

	// Send and Recv exchange ahmp messages. Encoding details are defined in ahmp package.
	// Warning: Nither of them are thread safe, but they are mutually thread-safe (isolated).
	Send(ahmp.AHMPMsgType, any) error
	Recv(*ahmp.AHMPMesage) error

	// Close disconnectes the peer and resets internal states.
	// Calling this is mendatory before dialing the same peer again.
	// The return value provides the cause of disconnection, where
	// nil is returned when the connection is gracefully closed by this call.
	// If the connection was closed before this call, the return value is
	// typically net.ErrClosed.
	// Calling Close() more than once is a no-op (returns nil) and discouraged,
	// though it is thread-safe.
	Close() error
}

// IAbystClient is abyst http/3 client, with customized
// redirect/cache/cookie handling mechanism.
// This **not** compatible with standard http client, and only processes abyst URL.
type IAbystClient interface {
	Get(url string) (resp *http.Response, err error)
	Head(url string) (resp *http.Response, err error)
	Post(url, contentType string, body io.Reader) (resp *http.Response, err error)
}
