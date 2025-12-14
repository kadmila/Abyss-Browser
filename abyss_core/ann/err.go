package ann

import (
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

// TODO: custom error wrapper - to let users know
// can they ignore a failed Accept or not.
// type AbyssNetworkError struct{}
// type AbyssCryptoError struct{}

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
