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

//export World_ObjectAppend
func World_ObjectAppend(
	h_host C.uintptr_t,
	h_world C.uintptr_t,
	peer_count C.int,
	h_peers *C.uintptr_t,
	peer_session_id_bufs **C.char,
	object_count C.int,
	object_id_bufs **C.char,
	object_transform_bufs **C.float,
	object_addr_bufs **C.char, object_addr_buf_len C.int,
) {
	host := cgo.Handle(h_host).Value().(*ahost.AbyssHost)
	world := cgo.Handle(h_world).Value().(*and.World)

	// Parse peer handles array
	peers := make([]ani.IAbyssPeer, peer_count)
	h_peers_slice := (*[1 << 28]C.uintptr_t)(unsafe.Pointer(h_peers))[:peer_count]
	for i := 0; i < int(peer_count); i++ {
		peers[i] = cgo.Handle(h_peers_slice[i]).Value().(ani.IAbyssPeer)
	}

	// Parse peer session IDs array (each is 16 bytes)
	peer_session_ids := make([]uuid.UUID, peer_count)
	peer_session_id_bufs_slice := (*[1 << 28]*C.char)(unsafe.Pointer(peer_session_id_bufs))[:peer_count]
	for i := 0; i < int(peer_count); i++ {
		peer_session_id_bytes := (*[16]byte)(unsafe.Pointer(peer_session_id_bufs_slice[i]))[:]
		peer_session_ids[i], _ = uuid.FromBytes(peer_session_id_bytes)
	}

	// Parse objects array
	objects := make([]and.ObjectInfo, object_count)
	object_id_bufs_slice := (*[1 << 28]*C.char)(unsafe.Pointer(object_id_bufs))[:object_count]
	object_transform_bufs_slice := (*[1 << 28]*C.float)(unsafe.Pointer(object_transform_bufs))[:object_count]
	object_addr_bufs_slice := (*[1 << 28]*C.char)(unsafe.Pointer(object_addr_bufs))[:object_count]

	for i := 0; i < int(object_count); i++ {
		// Parse object ID (16 bytes)
		object_id_bytes := (*[16]byte)(unsafe.Pointer(object_id_bufs_slice[i]))[:]
		objects[i].ID, _ = uuid.FromBytes(object_id_bytes)

		// Parse transform ([7]float32)
		transform_ptr := (*[7]float32)(unsafe.Pointer(object_transform_bufs_slice[i]))
		objects[i].Transform = *transform_ptr

		// Parse address (aurl)
		addr_bytes, _ := TryUnmarshalBytes(object_addr_bufs_slice[i], object_addr_buf_len)
		objects[i].Addr = string(addr_bytes)
	}

	host.WorldObjectAppend(world, peers, peer_session_ids, objects)
}

//export World_ObjectDelete
func World_ObjectDelete(
	h_host C.uintptr_t,
	h_world C.uintptr_t,
	peer_count C.int,
	h_peers *C.uintptr_t,
	peer_session_id_bufs **C.char,
	object_count C.int,
	object_id_bufs **C.char,
) {
	host := cgo.Handle(h_host).Value().(*ahost.AbyssHost)
	world := cgo.Handle(h_world).Value().(*and.World)

	// Parse peer handles array
	peers := make([]ani.IAbyssPeer, peer_count)
	h_peers_slice := (*[1 << 28]C.uintptr_t)(unsafe.Pointer(h_peers))[:peer_count]
	for i := 0; i < int(peer_count); i++ {
		peers[i] = cgo.Handle(h_peers_slice[i]).Value().(ani.IAbyssPeer)
	}

	// Parse peer session IDs array (each is 16 bytes)
	peer_session_ids := make([]uuid.UUID, peer_count)
	peer_session_id_bufs_slice := (*[1 << 28]*C.char)(unsafe.Pointer(peer_session_id_bufs))[:peer_count]
	for i := 0; i < int(peer_count); i++ {
		peer_session_id_bytes := (*[16]byte)(unsafe.Pointer(peer_session_id_bufs_slice[i]))[:]
		peer_session_ids[i], _ = uuid.FromBytes(peer_session_id_bytes)
	}

	// Parse object IDs array (each is 16 bytes)
	object_ids := make([]uuid.UUID, object_count)
	object_id_bufs_slice := (*[1 << 28]*C.char)(unsafe.Pointer(object_id_bufs))[:object_count]
	for i := 0; i < int(object_count); i++ {
		object_id_bytes := (*[16]byte)(unsafe.Pointer(object_id_bufs_slice[i]))[:]
		object_ids[i], _ = uuid.FromBytes(object_id_bytes)
	}

	host.WorldObjectDelete(world, peers, peer_session_ids, object_ids)
}
