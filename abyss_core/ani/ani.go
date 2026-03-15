// ani (abyss new interface) is a refined abyss interface set
// for abyss alpha release.
// This is designed for better testability and readability.
package ani

import (
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
	AddressCandidates() []netip.AddrPort
	IssueTime() time.Time
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
	Recv() (*ahmp.AHMPMessage, error)

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

type IAbystTlsCertChecker interface {
	GetPeerIdFromTlsCertificate(certificate *x509.Certificate) (string, bool)
}

// IAbystClient is abyst http/3 client, with customized
// redirect/cache/cookie handling mechanism.
// This **not** compatible with standard http client, and only processes abyst URL.
type IAbystClient interface {
	Get(id string, path string) (resp *http.Response, err error)
	Head(id string, path string) (resp *http.Response, err error)
	Post(id string, path, contentType string, body io.Reader) (resp *http.Response, err error)
}
