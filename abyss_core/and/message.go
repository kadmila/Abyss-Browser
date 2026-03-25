package and

import (
	"github.com/google/uuid"
)

///// AND

type JN struct {
	SenderSessionID uuid.UUID
	Path            string
}
type JOK struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	URL             string
	Neighbors       []ANDFullPeerSessionInfo
}
type JNI struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	Neighbor        ANDFullPeerSessionInfo
	Fwd             bool // whether this JNI can be forwarded by a SJN.
}
type MEM struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
}
type SJN struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	MemberInfos     []ANDIdentity
}
type CRR struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	MemberInfos     []ANDIdentity
}
type RST struct {
	SenderSessionID uuid.UUID //may nil.
	RecverSessionID uuid.UUID
	Code            int
	Message         string //optional
}

type SOA struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	Objects         []ObjectInfo
}
type SOD struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	ObjectIDs       []uuid.UUID
}

type INVAL struct {
	Err error
}
