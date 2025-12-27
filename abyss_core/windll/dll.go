package main

/*
#cgo CFLAGS: -std=c99
#include <stdint.h>
*/
import "C"
import (
	"errors"
	"net/netip"
	"runtime/cgo"
	"strings"

	"github.com/kadmila/Abyss-Browser/abyss_core/ahost"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
	"github.com/kadmila/Abyss-Browser/abyss_core/watchdog"
	"golang.org/x/crypto/ssh"
)

const (
	EOF               = -1
	INVALID_ARGUMENTS = -2
	BUFFER_OVERFLOW   = -3
	REMOTE_ERROR      = -4
)

//// **INIT() must be called before anything**

//export Init
func Init() C.int {
	watchdog.Init()
	return 0
}

//// Important helpers

// marshalError exports error handle
func marshalError(err error) C.uintptr_t {
	if err == nil {
		return 0
	}

	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(err))
}

// deleteHandle frees the handle and reports to the watchdog.
// handle.Delete() must never be called directly.
func deleteHandle(handle cgo.Handle) {
	handle.Delete()
	watchdog.CountHandleRelease()
}

///// main APIs

//export GetErrorBodyLength
func GetErrorBodyLength(h_error C.uintptr_t) C.int {
	err := (cgo.Handle(h_error)).Value().(error)
	return C.int(len(err.Error()))
}

//export GetErrorBody
func GetErrorBody(h_error C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	err := (cgo.Handle(h_error)).Value().(error)
	return TryMarshalBytes(buf_ptr, buf_len, []byte(err.Error()))
}

//export CloseError
func CloseError(h_error C.uintptr_t) {
	handle := cgo.Handle(h_error)
	inner := handle.Value()
	err, ok := inner.(error)
	if !ok || err == nil {
		panic("invalid handle")
	}
	deleteHandle(handle)
}

//export NewHost
func NewHost(root_key_ptr *C.char, root_key_len C.int, out *C.uintptr_t) C.uintptr_t {
	key_bytes, ok := TryUnmarshalBytes(root_key_ptr, root_key_len)
	if !ok {
		return marshalError(errors.New("nil arguments"))
	}

	root_priv_key, err := ssh.ParseRawPrivateKey(key_bytes)
	if err != nil {
		return marshalError(err)
	}
	root_priv_key_casted, ok := root_priv_key.(sec.PrivateKey)
	if !ok {
		return marshalError(errors.New("unsupported root key"))
	}

	host, err := ahost.NewAbyssHost(root_priv_key_casted)
	if err != nil {
		return marshalError(err)
	}

	watchdog.CountHandleExport()
	*out = C.uintptr_t(cgo.NewHandle(host))
	return 0
}

//export CloseHost
func CloseHost(h C.uintptr_t) {
	handle := cgo.Handle(h)
	handle.Value().(*ahost.AbyssHost).Close()
	deleteHandle(handle)
}

//export Host_Run
func Host_Run(h C.uintptr_t) {
	go cgo.Handle(h).Value().(*ahost.AbyssHost).Main()
}

//export Host_WaitForEvent
func Host_WaitForEvent(
	h C.uintptr_t, event_type_out *C.int, event_handle_out *C.uintptr_t,
) C.uintptr_t {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	event, ok := <-host.GetEventCh()
	if !ok {
		return marshalError(errors.New("Host Event Channel Closed"))
	}

	*event_type_out = C.int(getEventType(event))

	watchdog.CountHandleExport()
	*event_handle_out = C.uintptr_t(cgo.NewHandle(event))
	return 0
}

//export CloseEvent
func CloseEvent(h C.uintptr_t) {
	handle := cgo.Handle(h)
	deleteHandle(handle)
}

func Host_ExposeWorldForJoin(
	h C.uintptr_t, h_world C.uintptr_t,
	path_ptr *C.char, path_len C.int,
) C.uintptr_t {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	world := cgo.Handle(h).Value().(*and.World)
	path, ok := TryUnmarshalBytes(path_ptr, path_len)
	if !ok {
		return marshalError(errors.New("nil arguments"))
	}
	host.ExposeWorldForJoin(world, string(path))
	return 0
}

//export Host_HideWorld
func Host_HideWorld(h C.uintptr_t, h_world C.uintptr_t) {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	world := cgo.Handle(h_world).Value().(*and.World)
	host.HideWorld(world)
}

//export Host_LocalAddrCandidates
func Host_LocalAddrCandidates(h C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	addr_texts := functional.Filter(host.LocalAddrCandidates(), func(addr netip.AddrPort) string {
		return addr.String()
	})
	return TryMarshalBytes(buf_ptr, buf_len, []byte(strings.Join(addr_texts, "\n")))
}

//export Host_ID
func Host_ID(h C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	return TryMarshalBytes(buf_ptr, buf_len, []byte(host.ID()))
}

//export Host_RootCertificate
func Host_RootCertificate(h C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	return TryMarshalBytes(buf_ptr, buf_len, []byte(host.RootCertificate()))
}

//export Host_HandshakeKeyCertificate
func Host_HandshakeKeyCertificate(h C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	return TryMarshalBytes(buf_ptr, buf_len, []byte(host.HandshakeKeyCertificate()))
}

//export Host_AppendKnownPeer
func Host_AppendKnownPeer(h C.uintptr_t,
	root_cert_ptr *C.char, root_cert_len C.int,
	handshake_key_cert_ptr *C.char, handshake_key_cert_len C.int,
) C.uintptr_t {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	root_cert, r_ok := TryUnmarshalBytes(root_cert_ptr, root_cert_len)
	handshake_key_cert, hs_ok := TryUnmarshalBytes(handshake_key_cert_ptr, handshake_key_cert_len)
	if !(r_ok && hs_ok) {
		return marshalError(errors.New("nil arguments"))
	}
	return marshalError(host.AppendKnownPeer(string(root_cert), string(handshake_key_cert)))
}

//export Host_EraseKnownPeer
func Host_EraseKnownPeer(h C.uintptr_t, id_ptr *C.char, id_len C.int) C.uintptr_t {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	id, ok := TryUnmarshalBytes(id_ptr, id_len)
	if !ok {
		return marshalError(errors.New("nil arguments"))
	}
	host.EraseKnownPeer(string(id))
	return 0
}

//export Host_Dial
func Host_Dial(h C.uintptr_t,
	id_ptr *C.char, id_len C.int,
	addr_ptr *C.char, addr_len C.int,
) C.uintptr_t {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	id, id_ok := TryUnmarshalBytes(id_ptr, id_len)
	addr, addr_ok := TryUnmarshalBytes(addr_ptr, addr_len)
	if !(id_ok && addr_ok) {
		return marshalError(errors.New("nil arguments"))
	}
	addr_parsed, err := netip.ParseAddrPort(string(addr))
	if err != nil {
		return marshalError(err)
	}
	return marshalError(host.Dial(string(id), addr_parsed))
}

//export Host_ConfigAbystGateway
func Host_ConfigAbystGateway(
	h C.uintptr_t, config_ptr *C.char, config_len C.int,
) C.uintptr_t {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	config, ok := TryUnmarshalBytes(config_ptr, config_len)
	if !ok {
		return marshalError(errors.New("nil arguments"))
	}
	return marshalError(host.ConfigAbystGateway(string(config)))
}

//export Host_NewAbystClient
func Host_NewAbystClient(h C.uintptr_t, out *C.uintptr_t) C.uintptr_t {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	client, err := host.NewAbystClient()
	if err != nil {
		return marshalError(err)
	}

	watchdog.CountHandleExport()
	*out = C.uintptr_t(cgo.NewHandle(client))
	return 0
}

//export CloseAbyssClient
func CloseAbyssClient(h C.uintptr_t) {
	handle := cgo.Handle(h)
	// TODO: cleanup (if required)
	deleteHandle(handle)
}

//export Host_NewCollocatedHttp3Client
func Host_NewCollocatedHttp3Client(h C.uintptr_t, out *C.uintptr_t) C.uintptr_t {
	host := cgo.Handle(h).Value().(*ahost.AbyssHost)
	client, err := host.NewCollocatedHttp3Client()
	if err != nil {
		return marshalError(err)
	}

	watchdog.CountHandleExport()
	*out = C.uintptr_t(cgo.NewHandle(client))
	return 0
}

//export CloseAbyssClientCollocatedHttp3Client
func CloseAbyssClientCollocatedHttp3Client(h C.uintptr_t) {
	handle := cgo.Handle(h)
	// TODO: cleanup (if required)
	deleteHandle(handle)
}
