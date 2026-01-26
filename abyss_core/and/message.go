package and

import (
	"time"

	"github.com/google/uuid"
)

///// AND

type JN struct {
	SenderSessionID uuid.UUID
	Path            string
	TimeStamp       time.Time
}
type JOK struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	URL             string
	TimeStamp       time.Time
	Neighbors       []ANDFullPeerSessionInfo
}
type JDN struct { // Do I ever need this? why not just use RST instead? - needs thinking
	RecverSessionID uuid.UUID
	Code            int
	Message         string
}
type JNI struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	Neighbor        ANDFullPeerSessionInfo
}
type MEM struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	TimeStamp       time.Time
}
type SJN struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	MemberInfos     []ANDPeerSessionIdentity
}
type CRR struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	MemberInfos     []ANDPeerSessionIdentity
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
