package ahmp

import (
	"time"

	"github.com/google/uuid"

	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"
)

type JN struct {
	SenderSessionID uuid.UUID
	Text            string
	TimeStamp       time.Time
}
type JOK struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	TimeStamp       time.Time
	Neighbors       []abyss.ANDFullPeerSessionIdentity
	Text            string
}
type JDN struct {
	RecverSessionID uuid.UUID
	Text            string
	Code            int
}
type JNI struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	Neighbor        abyss.ANDFullPeerSessionIdentity
}
type MEM struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	TimeStamp       time.Time
}
type SJN struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	MemberInfos     []abyss.ANDPeerSessionIdentity
}
type CRR struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	MemberInfos     []abyss.ANDPeerSessionIdentity
}
type RST struct {
	SenderSessionID uuid.UUID //may nil.
	RecverSessionID uuid.UUID
	Message         string //optional
}

type SOA struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	Objects         []abyss.ObjectInfo
}
type SOD struct {
	SenderSessionID uuid.UUID
	RecverSessionID uuid.UUID
	ObjectIDs       []uuid.UUID
}

type INVAL struct {
	Err error
}
