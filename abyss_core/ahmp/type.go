// ahmp package provides definition of ahmp message types,
// and provide helper tools.
// While ann AbyssPeer interface seems to allow exchaning
// any type of messages,
// doing it is not acceptable in the standard abyss network.
// In standard abyss network, only the following set of messages
// can be exchanged.
package ahmp

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type AHMPMsgType int

type AHMPMesage struct {
	Type    AHMPMsgType     `cbor:"0,keyasint"`
	Payload cbor.RawMessage `cbor:"1,keyasint"`
}

// Abyss Neigbor Discovery (AND)
// 0x0000 ~ 0x0FFF
const (
	JN_T = iota
	JOK_T
	JDN_T
	JNI_T
	MEM_T
	SJN_T
	CRR_T
	RST_T
)

// Shared Object - AND extension
const (
	SOA_T = iota + 0x0100
	SOD_T
)

// other independent protocols: add 0x1000

func (t AHMPMsgType) String() string {
	switch t {
	case JN_T:
		return "JN"
	case JOK_T:
		return "JOK"
	case JDN_T:
		return "JDN"
	case JNI_T:
		return "JNI"
	case MEM_T:
		return "MEM"
	case SJN_T:
		return "SJN"
	case CRR_T:
		return "CRR"
	case RST_T:
		return "RST"
	case SOA_T:
		return "SOA"
	case SOD_T:
		return "SOD"
	default:
		return fmt.Sprintf("Undefine AHMPMsgType(%d)", int(t))
	}
}
