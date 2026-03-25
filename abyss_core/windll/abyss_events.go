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
)

// Event type constants matching C enum values
const (
	// AND Events
	AbyssEvent_WorldEnter = iota + 1
	AbyssEvent_SessionReady
	AbyssEvent_SessionClose
	AbyssEvent_ObjectAppend
	AbyssEvent_ObjectDelete
	AbyssEvent_WorldLeave

	// Host Events
	AbyssEvent_PeerConnected
	AbyssEvent_PeerDisconnected
	AbyssEvent_PeerFound
	AbyssEvent_PeerForgot
)

// getEventType maps Go event types to C enum values
func getEventType(event any) int {
	switch event.(type) {
	case *and.EANDWorldEnter:
		return AbyssEvent_WorldEnter
	case *and.EANDSessionReady:
		return AbyssEvent_SessionReady
	case *and.EANDSessionClose:
		return AbyssEvent_SessionClose
	case *and.EANDObjectAppend:
		return AbyssEvent_ObjectAppend
	case *and.EANDObjectDelete:
		return AbyssEvent_ObjectDelete
	case *and.EANDWorldLeave:
		return AbyssEvent_WorldLeave
	case *ahost.EPeerConnected:
		return AbyssEvent_PeerConnected
	case *ahost.EPeerDisconnected:
		return AbyssEvent_PeerDisconnected
	case *ahost.EPeerFound:
		return AbyssEvent_PeerFound
	case *ahost.EPeerForgot:
		return AbyssEvent_PeerForgot
	default:
		panic("unexpected Abyss event")
	}
}

//export Event_WorldEnter_Query
func Event_WorldEnter_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	url_buf_ptr *C.char, url_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*and.EANDWorldEnter)

	// Copy world session ID (16 bytes)
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, event.WSID[:])

	// Copy URL to buffer
	url_bytes := []byte(event.URL)
	return TryMarshalBytes(url_buf_ptr, url_buf_len, url_bytes)
}

//export Event_SessionReady_Query
func Event_SessionReady_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
	peer_session_id_buf *C.char,
) C.int {
	event := cgo.Handle(h_event).Value().(*and.EANDSessionReady)

	// Copy world session ID (16 bytes)
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, event.WSID[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_SessionClose_Query
func Event_SessionClose_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
	peer_session_id_buf *C.char,
) C.int {
	event := cgo.Handle(h_event).Value().(*and.EANDSessionClose)

	// Copy world session ID (16 bytes)
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, event.WSID[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_ObjectAppend_Query
func Event_ObjectAppend_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
	peer_session_id_buf *C.char,
	object_count_out *C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*and.EANDObjectAppend)

	// Copy world session ID (16 bytes)
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, event.WSID[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Set object count
	*object_count_out = C.int(len(event.Objects))

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_ObjectAppend_QueryObjectAddrLength
func Event_ObjectAppend_QueryObjectAddrLength(
	h_event C.uintptr_t,
	object_addr_length_buf *C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*and.EANDObjectAppend)

	object_addr_lenghth_slice := (*[1 << 28]C.int)(unsafe.Pointer(object_addr_length_buf))[:len(event.Objects)]

	sum := 0
	for i, entry := range event.Objects {
		object_addr_lenghth_slice[i] = C.int(len(entry.Addr))
		sum += len(entry.Addr)
	}

	return C.int(sum)
}

//export Event_ObjectAppend_GetObjects
func Event_ObjectAppend_GetObjects(
	h_event C.uintptr_t,
	object_id_bufs **C.char,
	object_transform_bufs **C.float,
	object_addr_bufs **C.char, object_addr_buf_lens *C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*and.EANDObjectAppend)

	count := len(event.Objects)
	id_buf_ptrs := (*[1 << 28]*C.char)(unsafe.Pointer(object_id_bufs))[:count]
	transform_buf_ptrs := (*[1 << 28]*C.float)(unsafe.Pointer(object_transform_bufs))[:count]
	addr_buf_ptrs := (*[1 << 28]*C.char)(unsafe.Pointer(object_addr_bufs))[:count]
	addr_buf_lens := (*[1 << 28]C.int)(unsafe.Pointer(object_addr_buf_lens))[:count]

	for i, obj := range event.Objects {
		// Copy UUID bytes (16 bytes)
		id_slice := (*[16]byte)(unsafe.Pointer(id_buf_ptrs[i]))[:]
		copy(id_slice, obj.ID[:])

		// Copy transform array (7 floats)
		transform_slice := (*[7]float32)(unsafe.Pointer(transform_buf_ptrs[i]))[:]
		copy(transform_slice, obj.Transform[:])

		// Copy address to buffer
		addr_bytes := []byte(obj.Addr)
		result := TryMarshalBytes(addr_buf_ptrs[i], addr_buf_lens[i], addr_bytes)
		if result < 0 {
			return result
		}
	}

	return 0
}

//export Event_ObjectDelete_Query
func Event_ObjectDelete_Query(
	h_event C.uintptr_t,
	world_session_id_buf *C.char,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
	peer_session_id_buf *C.char,
	object_count_out *C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*and.EANDObjectDelete)

	// Copy world session ID (16 bytes)
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, event.WSID[:])

	// Copy peer session ID (16 bytes)
	peer_session_id_bytes := event.SessionID[:]
	peer_session_id_slice := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	copy(peer_session_id_slice, peer_session_id_bytes)

	// Set object count
	*object_count_out = C.int(len(event.ObjectIDs))

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_ObjectDelete_GetObjectIDs
func Event_ObjectDelete_GetObjectIDs(
	h_event C.uintptr_t,
	object_id_bufs **C.char,
) C.int {
	event := cgo.Handle(h_event).Value().(*and.EANDObjectDelete)

	count := len(event.ObjectIDs)
	id_buf_ptrs := (*[1 << 28]*C.char)(unsafe.Pointer(object_id_bufs))[:count]

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
	event := cgo.Handle(h_event).Value().(*and.EANDWorldLeave)

	// Copy world session ID (16 bytes)
	world_session_id_slice := (*[16]byte)(unsafe.Pointer(world_session_id_buf))[:]
	copy(world_session_id_slice, event.WSID[:])

	// Set code
	*code_out = C.int(event.Code)

	// Copy message to buffer
	message_bytes := []byte(event.Message)
	return TryMarshalBytes(message_buf_ptr, message_buf_len, message_bytes)
}

//export Event_PeerConnected_Query
func Event_PeerConnected_Query(
	h_event C.uintptr_t,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*ahost.EPeerConnected)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_PeerDisconnected_Query
func Event_PeerDisconnected_Query(
	h_event C.uintptr_t,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*ahost.EPeerDisconnected)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_PeerFound_Query
func Event_PeerFound_Query(
	h_event C.uintptr_t,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*ahost.EPeerFound)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}

//export Event_PeerForgot_Query
func Event_PeerForgot_Query(
	h_event C.uintptr_t,
	peer_id_buf_ptr *C.char, peer_id_buf_len C.int,
) C.int {
	event := cgo.Handle(h_event).Value().(*ahost.EPeerForgot)

	// Copy peer ID to buffer
	peer_id_bytes := []byte(event.PeerID)
	return TryMarshalBytes(peer_id_buf_ptr, peer_id_buf_len, peer_id_bytes)
}
