package ann

import (
	"net/netip"

	"github.com/quic-go/quic-go"
)

// Error constructors - these only construct errors, they don't push to backlog

// NewHandshakeNetworkError creates a HandshakeNetworkError.
func NewHandshakeNetworkError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
	isTimeout bool,
	isTransport bool,
) *HandshakeNetworkError {
	return &HandshakeNetworkError{
		HandshakeError: HandshakeError{
			RemoteAddr: addr,
			PeerID:     peerID,
			IsDialing:  isDialing,
			Stage:      stage,
			Underlying: err,
		},
		IsTimeout:   isTimeout,
		IsTransport: isTransport,
	}
}

// NewHandshakeProtocolError creates a HandshakeProtocolError.
func NewHandshakeProtocolError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
	isAHMP bool,
	quicErrorCode *quic.ApplicationErrorCode,
) *HandshakeProtocolError {
	return &HandshakeProtocolError{
		HandshakeError: HandshakeError{
			RemoteAddr: addr,
			PeerID:     peerID,
			IsDialing:  isDialing,
			Stage:      stage,
			Underlying: err,
		},
		IsAHMP:        isAHMP,
		QuicErrorCode: quicErrorCode,
	}
}

// NewHandshakeAuthError creates a HandshakeAuthError.
func NewHandshakeAuthError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
	reason AuthFailureReason,
) *HandshakeAuthError {
	return &HandshakeAuthError{
		HandshakeError: HandshakeError{
			RemoteAddr: addr,
			PeerID:     peerID,
			IsDialing:  isDialing,
			Stage:      stage,
			Underlying: err,
		},
		Reason: reason,
	}
}

// NewHandshakePeerStateError creates a HandshakePeerStateError.
func NewHandshakePeerStateError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
	reason PeerStateReason,
) *HandshakePeerStateError {
	return &HandshakePeerStateError{
		HandshakeError: HandshakeError{
			RemoteAddr: addr,
			PeerID:     peerID,
			IsDialing:  isDialing,
			Stage:      stage,
			Underlying: err,
		},
		Reason: reason,
	}
}

// NewHandshakePeerStateErrorFromDialError creates a HandshakePeerStateError from a DialError.
func NewHandshakePeerStateErrorFromDialError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	dialErr *DialError,
) *HandshakePeerStateError {
	var reason PeerStateReason
	switch dialErr.T {
	case DE_Redundant:
		reason = PeerState_Redundant
	case DE_UnknownPeer:
		reason = PeerState_Unknown
	default:
		reason = PeerState_Rejected
	}
	return NewHandshakePeerStateError(addr, peerID, isDialing, stage, dialErr, reason)
}

// Backlog push method

// backlogPushErr pushes an error to the backlog.
func (n *AbyssNode) backlogPushErr(err error) {
	n.backlog <- backLogEntry{
		peer: nil,
		err:  err,
	}
}
