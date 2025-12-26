package ann

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/quic-go/quic-go"
)

const (
	AbyssQuicRedundantConnection quic.ApplicationErrorCode = 0x1000
	AbyssQuicAhmpStreamFail      quic.ApplicationErrorCode = 0x1001
	AbyssQuicAhmpParseFail       quic.ApplicationErrorCode = 0x1002
	AbyssQuicCryptoFail          quic.ApplicationErrorCode = 0x1010
	AbyssQuicAuthenticationFail  quic.ApplicationErrorCode = 0x1011
	AbyssQuicHandshakeTimeout    quic.ApplicationErrorCode = 0x1020

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
	HS_TieBreak                                 // Connection tie-breaking
	HS_PeerCompletion                           // Peer registry completion
)

func (s HandshakeStage) String() string {
	switch s {
	case HS_Connection:
		return "connecting"
	case HS_StreamSetup:
		return "ahmp-stream-setup"
	case HS_Handshake1:
		return "handshake-1"
	case HS_Handshake2:
		return "handshake-2"
	case HS_Handshake3:
		return "handshake-3"
	case HS_TieBreak:
		return "tie-breaking"
	case HS_PeerCompletion:
		return "peer-completion"
	default:
		panic("HandshakeStage.String()")
	}
}

type HandshakeFailReason int

const (
	HS_Fail_TransportFail HandshakeFailReason = iota + 1 // QUIC error
	HS_Fail_Timeout
	HS_Fail_Cancelled
	HS_Fail_CryptoFail
	HS_Fail_ParserFail
	HS_Fail_InvalidCert
	HS_Fail_TieBreakFail
	HS_Fail_UnknownPeer
	HS_Fail_Redundant
)

func (r HandshakeFailReason) String() string {
	switch r {
	case HS_Fail_TransportFail:
		return "transport-failed"
	case HS_Fail_Timeout:
		return "timeout"
	case HS_Fail_CryptoFail:
		return "crytography-failure"
	case HS_Fail_ParserFail:
		return "parsing-failure"
	case HS_Fail_InvalidCert:
		return "invalid-certificate"
	case HS_Fail_TieBreakFail:
		return "peer-in-tie"
	case HS_Fail_UnknownPeer:
		return "unknown-peer"
	case HS_Fail_Redundant:
		return "redundant-peer"
	default:
		panic("HandshakeFailReason.String()")
	}
}

//// Handshake Error Type

type HandshakeError struct {
	Base       error          // Original error
	RemoteAddr netip.AddrPort // Address of the remote peer
	PeerID     string         // Peer identity (empty if unknown/unauthenticated)
	IsDialing  bool           // true: outbound (dial), false: inbound (serve)
	Stage      HandshakeStage
	Reason     HandshakeFailReason
}

func (e *HandshakeError) Error() string {
	var direction string
	if e.IsDialing {
		direction = "outbound"
	} else {
		direction = "inbound"
	}
	return fmt.Sprintf("%s handshake error(%s) during %s with %s (peer: %s): %v",
		direction, e.Reason, e.Stage, e.RemoteAddr, e.PeerID, e.Base)
}
func (e *HandshakeError) Unwrap() error {
	return e.Base
}

//// Helper

func NewHandshakeError(
	base error,
	addr netip.AddrPort,
	peer_id string,
	is_dialing bool,
	stage HandshakeStage,
	reason HandshakeFailReason,
) *HandshakeError {
	if errors.Is(base, context.DeadlineExceeded) {
		reason = HS_Fail_Timeout
	} else if errors.Is(base, context.Canceled) {
		reason = HS_Fail_Cancelled
	}
	return &HandshakeError{
		Base:       base,
		RemoteAddr: addr,
		PeerID:     peer_id,
		IsDialing:  is_dialing,
		Stage:      stage,
		Reason:     reason,
	}
}
