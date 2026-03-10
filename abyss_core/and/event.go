package and

import (
	"github.com/google/uuid"
)

// IANDEvent conveys event/request from AND to host.
// a session may close before ready, but never before request.
// No event should be pushed after JoinFail or WorldLeave.
// This must be a pointer for an EAND struct.
type IANDEvent any

type EANDWorldEnter struct {
	WSID uuid.UUID
	URL  string
}
type EANDSessionReady struct {
	WSID uuid.UUID
	ANDIdentity
}
type EANDSessionClose struct {
	WSID uuid.UUID
	ANDIdentity
}
type EANDWorldLeave struct {
	WSID    uuid.UUID
	Code    int
	Message string
}

/// shared object

type EANDObjectAppend struct {
	WSID uuid.UUID
	ANDIdentity
	Objects []ObjectInfo
}
type EANDObjectDelete struct {
	WSID uuid.UUID
	ANDIdentity
	ObjectIDs []uuid.UUID
}

/// debug

type EANDError struct {
	WSID  uuid.UUID
	Error error
}
