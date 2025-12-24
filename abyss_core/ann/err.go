package ann

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/quic-go/quic-go"
)

const (
	AbyssQuicRedundantConnection quic.ApplicationErrorCode = 0x1000
	AbyssQuicAhmpStreamFail      quic.ApplicationErrorCode = 0x1001
	AbyssQuicCryptoFail          quic.ApplicationErrorCode = 0x1002
	AbyssQuicAuthenticationFail  quic.ApplicationErrorCode = 0x1003
	AbyssQuicHandshakeTimeout    quic.ApplicationErrorCode = 0x1004

	AbyssQuicClose    quic.ApplicationErrorCode = 0x1100
	AbyssQuicOverride quic.ApplicationErrorCode = 0x1101
)

//// Enums For Error Types

// HandshakeStage represents the stage at which a handshake error occurred.
type HandshakeStage int

const (
	HS_Connection     HandshakeStage = iota + 1 // QUIC connection establishment
	HS_StreamSetup                              // AHMP stream creation
	HS_Handshake1                               // First handshake message (encrypted cert)
	HS_Handshake2                               // Second handshake message (binding cert)
	HS_Handshake3                               // Third handshake message (confirmation)
	HS_PeerCompletion                           // Peer registry completion
	HS_TieBreak                                 // Connection tie-breaking
)

func (s HandshakeStage) String() string {
	switch s {
	case HS_Connection:
		return "connection"
	case HS_StreamSetup:
		return "stream-setup"
	case HS_Handshake1:
		return "handshake-1"
	case HS_Handshake2:
		return "handshake-2"
	case HS_Handshake3:
		return "handshake-3"
	case HS_PeerCompletion:
		return "peer-completion"
	case HS_TieBreak:
		return "tie-break"
	default:
		return "unknown-stage"
	}
}

// AuthFailureReason specifies the reason for authentication failure.
type AuthFailureReason int

const (
	Auth_CryptoFail   AuthFailureReason = iota + 1 // Encryption/decryption failed
	Auth_CertInvalid                               // Certificate parsing failed
	Auth_BindingFail                               // TLS binding verification failed
	Auth_TieBreakFail                              // Tie-breaking crypto failed
)

func (r AuthFailureReason) String() string {
	switch r {
	case Auth_CryptoFail:
		return "crypto-failure"
	case Auth_CertInvalid:
		return "invalid-certificate"
	case Auth_BindingFail:
		return "binding-verification-failed"
	case Auth_TieBreakFail:
		return "tie-break-crypto-failed"
	default:
		return "unknown-auth-failure"
	}
}

// PeerStateReason specifies the reason for peer state error.
type PeerStateReason int

const (
	PeerState_Redundant PeerStateReason = iota + 1 // Duplicate connection
	PeerState_Unknown                              // Peer not in registry
	PeerState_Rejected                             // Peer rejected by policy
)

func (r PeerStateReason) String() string {
	switch r {
	case PeerState_Redundant:
		return "redundant-connection"
	case PeerState_Unknown:
		return "unknown-peer"
	case PeerState_Rejected:
		return "peer-rejected"
	default:
		return "unknown-peer-state"
	}
}

//// Error Types

type IHandshakeError interface {
	error
	Direction() string
	GetRemoteAddr() netip.AddrPort
	GetPeerID() string
	GetIsDialing() bool
	GetStage() HandshakeStage
	GetUnderlying() error
}

// HandshakeError is the base error type embedded in all handshake-related errors.
type HandshakeError struct {
	RemoteAddr netip.AddrPort // Address of the remote peer
	PeerID     string         // Peer identity (empty if unknown/unauthenticated)
	IsDialing  bool           // true: outbound (dial), false: inbound (serve)
	Stage      HandshakeStage // Stage at which the error occurred
	Underlying error          // Original underlying error
}

func (e *HandshakeError) Direction() string {
	if e.IsDialing {
		return "outbound"
	}
	return "inbound"
}
func (e *HandshakeError) GetRemoteAddr() netip.AddrPort { return e.RemoteAddr }
func (e *HandshakeError) GetPeerID() string             { return e.PeerID }
func (e *HandshakeError) GetIsDialing() bool            { return e.IsDialing }
func (e *HandshakeError) GetStage() HandshakeStage      { return e.Stage }
func (e *HandshakeError) GetUnderlying() error          { return e.Underlying }

// HandshakeNetworkError represents transient network/transport issues.
type HandshakeNetworkError struct {
	HandshakeError
	IsTimeout   bool // Whether this is a timeout error
	IsTransport bool // Whether this is a QUIC transport error
}

func (e *HandshakeNetworkError) Error() string {
	errType := "network"
	if e.IsTimeout {
		errType = "timeout"
	} else if e.IsTransport {
		errType = "transport"
	}
	return fmt.Sprintf("%s handshake %s error at %s from %s (peer: %s): %v",
		e.Direction(), errType, e.Stage, e.RemoteAddr, e.PeerID, e.Underlying)
}

// HandshakeProtocolError represents protocol-level failures.
type HandshakeProtocolError struct {
	HandshakeError
	IsAHMP        bool                       // AHMP encoding/decoding error
	QuicErrorCode *quic.ApplicationErrorCode // QUIC error code if applicable
}

func (e *HandshakeProtocolError) Error() string {
	errType := "protocol"
	if e.IsAHMP {
		errType = "AHMP"
	}
	msg := fmt.Sprintf("%s handshake %s error at %s from %s (peer: %s): %v",
		e.Direction(), errType, e.Stage, e.RemoteAddr, e.PeerID, e.Underlying)
	if e.QuicErrorCode != nil {
		msg += fmt.Sprintf(" [QUIC error code: 0x%x]", *e.QuicErrorCode)
	}
	return msg
}

// HandshakeAuthError represents authentication/cryptographic failures.
type HandshakeAuthError struct {
	HandshakeError
	Reason AuthFailureReason
}

func (e *HandshakeAuthError) Error() string {
	return fmt.Sprintf("%s handshake auth error (%s) at %s from %s (peer: %s): %v",
		e.Direction(), e.Reason, e.Stage, e.RemoteAddr, e.PeerID, e.Underlying)
}

// HandshakePeerStateError represents peer registry/state issues.
type HandshakePeerStateError struct {
	HandshakeError
	Reason PeerStateReason
}

func (e *HandshakePeerStateError) Error() string {
	return fmt.Sprintf("%s handshake peer-state error (%s) at %s from %s (peer: %s): %v",
		e.Direction(), e.Reason, e.Stage, e.RemoteAddr, e.PeerID, e.Underlying)
}

// Deprecated error types - will be removed in future versions
//
//go:generate stringer -type=Status
type AbyssOp int

const (
	AbyssOp_Dial AbyssOp = iota + 1
	AbyssOp_Listen
	AbyssOp_Application
)

func (op AbyssOp) String() string {
	switch op {
	case AbyssOp_Dial:
		return "Dial"
	case AbyssOp_Listen:
		return "Listen"
	case AbyssOp_Application:
		return "Application"
	default:
		panic("")
	}
}

// Deprecated: Use HandshakeError types instead
type AbyssError struct {
	Source     netip.AddrPort
	PeerID     string
	AbyssOp    AbyssOp
	FromRemote bool
	Err        error
}

func (e *AbyssError) Error() string {
	var b strings.Builder
	b.WriteString(e.Source.String())
	b.WriteString("(")
	if e.PeerID != "" {
		b.WriteString(e.PeerID)
	} else {
		b.WriteString("unknown")
	}
	b.WriteString(")")
	b.WriteString(e.AbyssOp.String())
	b.WriteString(">")
	b.WriteString(e.Err.Error())
	return b.String()
}

type DialErrorType int

const (
	DE_Redundant DialErrorType = iota + 1
	DE_UnknownPeer
)

// Deprecated: Use HandshakePeerStateError instead
type DialError struct {
	T DialErrorType
}

func (e *DialError) Error() string {
	switch e.T {
	case DE_Redundant:
		return "redundant"
	case DE_UnknownPeer:
		return "unknown peer"
	default:
		panic("")
	}
}
