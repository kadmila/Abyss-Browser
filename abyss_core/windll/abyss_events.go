package main

/*
#cgo CFLAGS: -std=c99
#include <stdint.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"

	"github.com/kadmila/Abyss-Browser/abyss_core/ahost"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/watchdog"
)

// Event type constants matching C enum values
const (
	// AND Events
	AbyssEvent_WorldEnter = iota + 1
	AbyssEvent_SessionRequest
	AbyssEvent_SessionReady
	AbyssEvent_SessionClose
	AbyssEvent_ObjectAppend
	AbyssEvent_ObjectDelete
	AbyssEvent_WorldLeave

	// Host Events
	AbyssEvent_PeerConnected
	AbyssEvent_PeerDisconnected
)

// getEventType maps Go event types to C enum values
func getEventType(event any) int {
	switch event.(type) {
	case and.EANDWorldEnter:
		return AbyssEvent_WorldEnter
	case and.EANDSessionRequest:
		return AbyssEvent_SessionRequest
	case and.EANDSessionReady:
		return AbyssEvent_SessionReady
	case and.EANDSessionClose:
		return AbyssEvent_SessionClose
	case and.EANDObjectAppend:
		return AbyssEvent_ObjectAppend
	case and.EANDObjectDelete:
		return AbyssEvent_ObjectDelete
	case and.EANDWorldLeave:
		return AbyssEvent_WorldLeave
	case ahost.EPeerConnected:
		return AbyssEvent_PeerConnected
	case ahost.EPeerDisconnected:
		return AbyssEvent_PeerDisconnected
	default:
		panic("unexpected Abyss event")
	}
}

//export Event_WorldEnter_Query
func Event_WorldEnter_Query(
	h_event C.uintptr_t,
	world_handle_out *C.uintptr_t,
	world_session_id_buf *C.char,
	url_buf_ptr *C.char, url_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDWorldEnter)

	// Create world handle (only created here)
	watchdog.CountHandleExport()
	*world_handle_out = C.uintptr_t(cgo.NewHandle(event.World))

	// Copy world session ID (16 bytes)
	world_session_id := event.World.SessionID()
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, world_session_id[:])

	// Copy URL to buffer
	url_bytes := []byte(event.URL)
	return TryMarshalBytes(url_buf_ptr, url_buf_len, url_bytes)
}

//export CloseWorld
func CloseWorld(h_world C.uintptr_t) {
	handle := cgo.Handle(h_world)
	deleteHandle(handle)
}

//export Event_SessionRequest_Query
func Event_SessionRequest_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDSessionRequest)

	// Copy world session ID (16 bytes)
	world_session_id := event.World.SessionID()
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, world_session_id[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.Peer.ID())
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_SessionReady_Query
func Event_SessionReady_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDSessionReady)

	// Copy world session ID (16 bytes)
	world_session_id := event.World.SessionID()
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, world_session_id[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.Peer.ID())
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_SessionClose_Query
func Event_SessionClose_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDSessionClose)

	// Copy world session ID (16 bytes)
	world_session_id := event.World.SessionID()
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, world_session_id[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.Peer.ID())
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_ObjectAppend_Query
func Event_ObjectAppend_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
	object_count_out *C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDObjectAppend)

	// Copy world session ID (16 bytes)
	world_session_id := event.World.SessionID()
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, world_session_id[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Set object count
	*object_count_out = C.int(len(event.Objects))

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.Peer.ID())
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_ObjectAppend_GetObjects
func Event_ObjectAppend_GetObjects(
	h_event C.uintptr_t,
	object_id_bufs **C.char,
	object_transform_bufs **C.float,
	object_addr_bufs **C.char, object_addr_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDObjectAppend)

	count := len(event.Objects)
	id_buf_ptrs := (*[1 << 20]*C.char)(unsafe.Pointer(object_id_bufs))[:count]
	transform_buf_ptrs := (*[1 << 20]*C.float)(unsafe.Pointer(object_transform_bufs))[:count]
	addr_buf_ptrs := (*[1 << 20]*C.char)(unsafe.Pointer(object_addr_bufs))[:count]

	for i, obj := range event.Objects {
		// Copy UUID bytes (16 bytes)
		id_slice := (*[16]byte)(unsafe.Pointer(id_buf_ptrs[i]))[:]
		copy(id_slice, obj.ID[:])

		// Copy transform array (7 floats)
		transform_slice := (*[7]float32)(unsafe.Pointer(transform_buf_ptrs[i]))[:]
		copy(transform_slice, obj.Transform[:])

		// Copy address to buffer
		addr_bytes := []byte(obj.Addr)
		result := TryMarshalBytes(addr_buf_ptrs[i], object_addr_buf_len, addr_bytes)
		if result != 0 {
			return BUFFER_OVERFLOW
		}
	}

	return 0
}

//export Event_ObjectDelete_Query
func Event_ObjectDelete_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
	object_count_out *C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDObjectDelete)

	// Copy world session ID (16 bytes)
	world_session_id := event.World.SessionID()
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, world_session_id[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Set object count
	*object_count_out = C.int(len(event.ObjectIDs))

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.Peer.ID())
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_ObjectDelete_GetObjectIDs
func Event_ObjectDelete_GetObjectIDs(
	h_event C.uintptr_t,
	object_id_bufs **C.char,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDObjectDelete)

	count := len(event.ObjectIDs)
	id_buf_ptrs := (*[1 << 20]*C.char)(unsafe.Pointer(object_id_bufs))[:count]

	for i, objID := range event.ObjectIDs {
		// Copy UUID bytes (16 bytes)
		id_slice := (*[16]byte)(unsafe.Pointer(id_buf_ptrs[i]))[:]
		copy(id_slice, objID[:])
	}

	return 0
}

//export Event_WorldLeave_Query
func Event_WorldLeave_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	code_out *C.int,
	message_buf_ptr *C.char, message_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(and.EANDWorldLeave)

	// Copy world session ID (16 bytes)
	world_session_id := event.World.SessionID()
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, world_session_id[:])

	// Set code
	*code_out = C.int(event.Code)

	// Copy message to buffer
	message_bytes := []byte(event.Message)
	return TryMarshalBytes(message_buf_ptr, message_buf_len, message_bytes)
}

//export Event_PeerConnected_Query
func Event_PeerConnected_Query(
	h_event C.uintptr_t,
	peer_handle_out *C.uintptr_t,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(ahost.EPeerConnected)

	// Create peer handle (only created here)
	watchdog.CountHandleExport()
	*peer_handle_out = C.uintptr_t(cgo.NewHandle(event.Peer))

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.Peer.ID())
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export ClosePeer
func ClosePeer(h_peer C.uintptr_t) {
	handle := cgo.Handle(h_peer)
	deleteHandle(handle)
}

//export Event_PeerDisconnected_Query
func Event_PeerDisconnected_Query(
	h_event C.uintptr_t,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(ahost.EPeerDisconnected)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}
