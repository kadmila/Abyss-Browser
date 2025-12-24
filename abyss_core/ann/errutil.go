package ann

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/quic-go/quic-go"
)

// backlogPushNetworkError pushes a HandshakeNetworkError to the backlog.
func (n *AbyssNode) backlogPushNetworkError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
	isTimeout bool,
	isTransport bool,
) {
	handshakeErr := &HandshakeNetworkError{
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
	n.backlog <- backLogEntry{
		peer: nil,
		err:  handshakeErr,
	}
}

// backlogPushProtocolError pushes a HandshakeProtocolError to the backlog.
func (n *AbyssNode) backlogPushProtocolError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
	isAHMP bool,
	quicErrorCode *quic.ApplicationErrorCode,
) {
	handshakeErr := &HandshakeProtocolError{
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
	n.backlog <- backLogEntry{
		peer: nil,
		err:  handshakeErr,
	}
}

// backlogPushAuthError pushes a HandshakeAuthError to the backlog.
func (n *AbyssNode) backlogPushAuthError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
	reason AuthFailureReason,
) {
	handshakeErr := &HandshakeAuthError{
		HandshakeError: HandshakeError{
			RemoteAddr: addr,
			PeerID:     peerID,
			IsDialing:  isDialing,
			Stage:      stage,
			Underlying: err,
		},
		Reason: reason,
	}
	n.backlog <- backLogEntry{
		peer: nil,
		err:  handshakeErr,
	}
}

// backlogPushPeerStateError pushes a HandshakePeerStateError to the backlog.
func (n *AbyssNode) backlogPushPeerStateError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
	reason PeerStateReason,
) {
	handshakeErr := &HandshakePeerStateError{
		HandshakeError: HandshakeError{
			RemoteAddr: addr,
			PeerID:     peerID,
			IsDialing:  isDialing,
			Stage:      stage,
			Underlying: err,
		},
		Reason: reason,
	}
	n.backlog <- backLogEntry{
		peer: nil,
		err:  handshakeErr,
	}
}

// backlogPushDialError converts a DialError to appropriate HandshakePeerStateError and pushes to backlog.
func (n *AbyssNode) backlogPushDialError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	dialErr *DialError,
) {
	var reason PeerStateReason
	switch dialErr.T {
	case DE_Redundant:
		reason = PeerState_Redundant
	case DE_UnknownPeer:
		reason = PeerState_Unknown
	default:
		reason = PeerState_Rejected
	}
	n.backlogPushPeerStateError(addr, peerID, isDialing, stage, dialErr, reason)
}

// backlogPushGenericError analyzes a generic error and pushes the appropriate typed error to the backlog.
// This is a helper for migration from the old backlogAppendError function.
func (n *AbyssNode) backlogPushGenericError(
	addr netip.AddrPort,
	peerID string,
	isDialing bool,
	stage HandshakeStage,
	err error,
) {
	// Check for DialError
	var dialErr *DialError
	if errors.As(err, &dialErr) {
		n.backlogPushDialError(addr, peerID, isDialing, stage, dialErr)
		return
	}

	// Check for network timeout
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		n.backlogPushNetworkError(addr, peerID, isDialing, stage, err, true, false)
		return
	}

	// Check for QUIC errors
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		code := appErr.ErrorCode
		n.backlogPushProtocolError(addr, peerID, isDialing, stage, err, false, &code)
		return
	}

	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		n.backlogPushNetworkError(addr, peerID, isDialing, stage, err, false, true)
		return
	}

	var versionErr *quic.VersionNegotiationError
	if errors.As(err, &versionErr) {
		n.backlogPushProtocolError(addr, peerID, isDialing, stage, err, false, nil)
		return
	}

	// Check for context errors (timeout)
	if errors.Is(err, context.DeadlineExceeded) {
		n.backlogPushNetworkError(addr, peerID, isDialing, stage, err, true, false)
		return
	}

	// Default: treat as network error
	n.backlogPushNetworkError(addr, peerID, isDialing, stage, err, false, false)
}
