package interfaces

import (
	"context"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go/http3"
)

type IPathResolver interface {
	PathToSessionID(path string, peer_hash string) (uuid.UUID, bool)
}

type ObjectInfo struct {
	ID        uuid.UUID
	Addr      string
	Transform [7]float32
}

type IWorldMember interface {
	Hash() string
	SessionID() uuid.UUID
	AppendObjects(objects []ObjectInfo) bool
	DeleteObjects(objectIDs []uuid.UUID) bool
}

type EWorldMemberRequest struct {
	MemberHash string
	Accept     func()
	Decline    func(code int, message string)
}
type EWorldMemberReady struct {
	Member IWorldMember
}
type EMemberObjectAppend struct {
	PeerHash string
	Objects  []ObjectInfo
}
type EMemberObjectDelete struct {
	PeerHash  string
	ObjectIDs []uuid.UUID
}
type EWorldMemberLeave struct { //now, the peer must be closed as soon as possible.
	PeerHash string
}
type EWorldTerminate struct{}

type IAbyssWorld interface {
	SessionID() uuid.UUID
	URL() string
	GetEventChannel() chan any
}

type IAbyssHost interface {
	GetLocalAbyssURL() *aurl.AURL

	OpenOutboundConnection(abyss_url *aurl.AURL)

	//Abyss
	OpenWorld(web_url string) (IAbyssWorld, error)
	JoinWorld(ctx context.Context, abyss_url *aurl.AURL) (IAbyssWorld, error)
	LeaveWorld(world IAbyssWorld) //this does not wait for world-related resource cleanup.
	// Each world should wait for its world termination event.

	//Abyst
	GetAbystClientConnection(peer_hash string) (*http3.ClientConn, error)
}
