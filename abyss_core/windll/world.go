package main

/*
#cgo CFLAGS: -std=c99
#include <stdint.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahost"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

//export World_AcceptSession
func World_AcceptSession(
	h_host C.uintptr_t,
	h_world C.uintptr_t,
	h_peer C.uintptr_t,
	peer_session_id_buf *C.char,
) {
	host := cgo.Handle(h_host).Value().(*ahost.AbyssHost)
	world := cgo.Handle(h_world).Value().(*and.World)
	peer := cgo.Handle(h_peer).Value().(ani.IAbyssPeer)

	// Parse UUID from buffer (16 bytes)
	peer_session_id_bytes := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	peer_session_id, _ := uuid.FromBytes(peer_session_id_bytes)

	host.AcceptWorldSession(world, peer, peer_session_id)
}

//export World_DeclineSession
func World_DeclineSession(
	h_host C.uintptr_t,
	h_world C.uintptr_t,
	h_peer C.uintptr_t,
	peer_session_id_buf *C.char,
	code C.int,
	message_buf_ptr *C.char, message_buf_len C.int,
) {
	host := cgo.Handle(h_host).Value().(*ahost.AbyssHost)
	world := cgo.Handle(h_world).Value().(*and.World)
	peer := cgo.Handle(h_peer).Value().(ani.IAbyssPeer)

	// Parse UUID from buffer (16 bytes)
	peer_session_id_bytes := (*[16]byte)(unsafe.Pointer(peer_session_id_buf))[:]
	peer_session_id, _ := uuid.FromBytes(peer_session_id_bytes)

	// Parse message string
	message_bytes, _ := TryUnmarshalBytes(message_buf_ptr, message_buf_len)
	message := string(message_bytes)

	host.DeclineWorldSession(world, peer, peer_session_id, int(code), message)
}

//export World_Close
func World_Close(
	h_host C.uintptr_t,
	h_world C.uintptr_t,
) {
	host := cgo.Handle(h_host).Value().(*ahost.AbyssHost)
	world := cgo.Handle(h_world).Value().(*and.World)

	host.CloseWorld(world)
}
