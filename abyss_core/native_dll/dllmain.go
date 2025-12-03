package main

/*
#cgo CFLAGS: -std=c99
#include <stdint.h>
*/
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime/cgo"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/watchdog"

	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"

	abyss_host "github.com/kadmila/Abyss-Browser/abyss_core/host"

	abyss_net "github.com/kadmila/Abyss-Browser/abyss_core/net_service"

	abyss_and "github.com/kadmila/Abyss-Browser/abyss_core/and"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"

	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ssh"
)

const (
	EOF               = -1
	ERROR             = -1
	INVALID_ARGUMENTS = -2
	BUFFER_OVERFLOW   = -3
	REMOTE_ERROR      = -4
	INVALID_HANDLE    = -99
)

func marshalError(err error) C.uintptr_t {
	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(err))
}

//export Init
func Init() C.int {
	watchdog.Init()
	return 0
}

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

type IDestructable interface {
	Destuct()
}

//export CloseAbyssHandle
func CloseAbyssHandle(handle C.uintptr_t) {
	if handle == 0 {
		watchdog.CountNullHandleRelease()
		return
	}

	inner := cgo.Handle(handle).Value()
	if inner_decon, ok := inner.(IDestructable); ok {
		inner_decon.Destuct()
	}
	cgo.Handle(handle).Delete()
	watchdog.CountHandleRelease()
}

//export NewSimplePathResolver
func NewSimplePathResolver() C.uintptr_t {
	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(abyss_host.NewSimplePathResolver()))
}

//export SimplePathResolver_SetMapping
func SimplePathResolver_SetMapping(h C.uintptr_t, path_ptr *C.char, path_len C.int, world_ID *C.char, err_out *C.uintptr_t) {
	path_resolver, ok := cgo.Handle(h).Value().(*abyss_host.SimplePathResolver)
	if !ok {
		*err_out = marshalError(errors.New("invalid handle"))
		return
	}

	var path string
	if path_len == 0 {
		path = ""
	} else {
		path_buf, ok := TryUnmarshalBytes(path_ptr, path_len)
		if !ok {
			*err_out = marshalError(errors.New("failed to parse path_buf"))
			return
		}
		path = string(path_buf)
	}

	var world_uuid uuid.UUID
	data, ok := TryUnmarshalBytes(world_ID, 16)
	if !ok {
		*err_out = marshalError(errors.New("failed to parse world_ID"))
		return
	}
	copy(world_uuid[:], data)

	if !path_resolver.TrySetMapping(path, world_uuid) {
		*err_out = marshalError(errors.New("mapping from same path already exists"))
	}
}

//export SimplePathResolver_DeleteMapping
func SimplePathResolver_DeleteMapping(h C.uintptr_t, path_ptr *C.char, path_len C.int) C.int {
	var path string
	if path_len == 0 {
		path = ""
	} else {
		path_buf, ok := TryUnmarshalBytes(path_ptr, path_len)
		if !ok {
			return INVALID_ARGUMENTS
		}
		path = string(path_buf)
	}
	path_resolver, ok := cgo.Handle(h).Value().(*abyss_host.SimplePathResolver)
	if !ok {
		return INVALID_HANDLE
	}
	path_resolver.DeleteMapping(path)
	return 0
}

//export NewSimpleAbystServer
func NewSimpleAbystServer(path_ptr *C.char, path_len C.int) C.uintptr_t {
	path_buf, ok := TryUnmarshalBytes(path_ptr, path_len)
	if !ok {
		return 0
	}
	path := string(path_buf)
	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(&http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			watchdog.Info("abyst request: " + r.URL.String())

			if r.URL.Path == "/" {
				// Serve main.aml for root path
				http.ServeFile(w, r, filepath.Join(path, "main.aml"))
				return
			}

			// Construct the full file path
			fullPath := filepath.Join(path, r.URL.Path)

			// Check if it's a directory
			info, err := os.Stat(fullPath)
			if err != nil || info.IsDir() {
				http.NotFound(w, r)
				return
			}

			// Serve the file normally
			http.FileServer(http.Dir(path)).ServeHTTP(w, r)
		}),
	}))
}

//export NewHost
func NewHost(root_priv_key_pem_ptr *C.char, root_priv_key_pem_len C.int, h_path_resolver C.uintptr_t, h_abyst_server C.uintptr_t) C.uintptr_t {
	abyst_server, ok := cgo.Handle(h_abyst_server).Value().(*http3.Server)
	if !ok {
		watchdog.Error(errors.New("invalid handle for abyst_server"))
		return 0
	}

	root_priv_key_pem, ok := TryUnmarshalBytes(root_priv_key_pem_ptr, root_priv_key_pem_len)
	if !ok {
		return 0
	}

	root_priv_key, err := ssh.ParseRawPrivateKey(root_priv_key_pem)
	if err != nil {
		watchdog.Error(err)
		return 0
	}
	root_priv_key_casted, ok := root_priv_key.(abyss_net.PrivateKey)
	if !ok {
		watchdog.Error(errors.New("unsupported private key type"))
		return 0
	}

	path_resolver, ok := cgo.Handle(h_path_resolver).Value().(*abyss_host.SimplePathResolver)
	if !ok {
		watchdog.Error(errors.New("invalid handle for path resolver"))
		return 0
	}

	addr_selector, err := abyss_net.NewBetaAddressSelector()
	if err != nil {
		watchdog.Error(err)
		return 0
	}
	net_service, err := abyss_net.NewBetaNetService(context.Background(), root_priv_key_casted, addr_selector, abyst_server)
	if err != nil {
		watchdog.Error(err)
		return 0
	}

	host := abyss_host.NewAbyssHost(
		net_service,
		abyss_and.NewAND(net_service.LocalIdentity().IDHash()),
		path_resolver,
	)
	go host.ListenAndServe(context.Background())

	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(host))
}

//export Host_GetLocalAbyssURL
func Host_GetLocalAbyssURL(h C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	host, ok := cgo.Handle(h).Value().(*abyss_host.AbyssHost)
	if !ok {
		return INVALID_HANDLE
	}

	return TryMarshalBytes(buf_ptr, buf_len, []byte(host.GetLocalAbyssURL().ToString()))
}

//export Host_GetCertificates
func Host_GetCertificates(h C.uintptr_t, root_cert_buf_ptr *C.char, root_cert_len *C.int, hs_key_cert_buf_ptr *C.char, hs_key_cert_len *C.int) C.int {
	host, ok := cgo.Handle(h).Value().(*abyss_host.AbyssHost)
	if !ok {
		return INVALID_HANDLE
	}

	host_identity := host.NetworkService.LocalIdentity()
	root_cert := []byte(host_identity.RootCertificate())
	hs_cert := []byte(host_identity.HandshakeKeyCertificate())
	root_cert_buf := TryMarshalBytes(root_cert_buf_ptr, *root_cert_len, root_cert)
	res2 := TryMarshalBytes(hs_key_cert_buf_ptr, *hs_key_cert_len, hs_cert)
	if root_cert_buf <= 0 || res2 <= 0 {
		*root_cert_len = C.int(len(root_cert))
		*hs_key_cert_len = C.int(len(hs_cert))
		return INVALID_ARGUMENTS
	}

	return 0
}

//export Host_AppendKnownPeer
func Host_AppendKnownPeer(h C.uintptr_t, root_cert_buf_ptr *C.char, root_cert_len C.int, hs_key_cert_buf_ptr *C.char, hs_key_cert_len C.int, err_out *C.uintptr_t) {
	host, ok := cgo.Handle(h).Value().(*abyss_host.AbyssHost)
	if !ok {
		*err_out = marshalError(errors.New("invalid handle"))
		return
	}

	root_cert_buf, ok := TryUnmarshalBytes(root_cert_buf_ptr, root_cert_len)
	if !ok {
		*err_out = marshalError(errors.New("invalid root_cer_buf"))
		return
	}
	hs_key_cert_buf, ok := TryUnmarshalBytes(hs_key_cert_buf_ptr, hs_key_cert_len)
	if !ok {
		*err_out = marshalError(errors.New("invalid hs_key_cert_buf"))
		return
	}
	err := host.NetworkService.AppendKnownPeer(string(root_cert_buf), string(hs_key_cert_buf))
	if err != nil {
		*err_out = marshalError(err)
	}
}

//export Host_OpenOutboundConnection
func Host_OpenOutboundConnection(h C.uintptr_t, abyss_url_ptr *C.char, abyss_url_len C.int) C.int {
	host, ok := cgo.Handle(h).Value().(*abyss_host.AbyssHost)
	if !ok {
		return INVALID_HANDLE
	}

	abyss_url_buf, ok := TryUnmarshalBytes(abyss_url_ptr, abyss_url_len)
	if !ok {
		return INVALID_ARGUMENTS
	}
	aurl, err := aurl.TryParse(string(abyss_url_buf))
	if err != nil {
		return INVALID_ARGUMENTS
	}
	host.OpenOutboundConnection(aurl)
	return 0
}

type WorldExport struct {
	inner    abyss.IAbyssWorld
	origin   abyss.IAbyssHost
	event_ch chan any
}

//export Host_OpenWorld
func Host_OpenWorld(h C.uintptr_t, url_ptr *C.char, url_len C.int) C.uintptr_t {
	host, ok := cgo.Handle(h).Value().(*abyss_host.AbyssHost)
	if !ok {
		watchdog.Error(errors.New("invalid handle"))
		return 0
	}

	url_buf, ok := TryUnmarshalBytes(url_ptr, url_len)
	if !ok {
		return 0
	}
	world, err := host.OpenWorld(string(url_buf))
	if err != nil {
		watchdog.Error(err)
		return 0
	}

	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(&WorldExport{
		inner:    world,
		origin:   host,
		event_ch: world.GetEventChannel(),
	}))
}

//export Host_JoinWorld
func Host_JoinWorld(h C.uintptr_t, url_ptr *C.char, url_len C.int, timeout_ms C.int) C.uintptr_t {
	host, ok := cgo.Handle(h).Value().(*abyss_host.AbyssHost)
	if !ok {
		watchdog.Error(errors.New("invalid handle"))
		return 0
	}

	url_buf, ok := TryUnmarshalBytes(url_ptr, url_len)
	if !ok {
		watchdog.Info("failed to unmarshal url")
		return 0
	}
	aurl, err := aurl.TryParse(string(url_buf))
	if err != nil {
		watchdog.Error(err)
		return 0
	}

	ctx, ctx_cancel := context.WithTimeout(context.Background(), time.Duration(timeout_ms)*time.Millisecond)
	defer ctx_cancel()
	world, err := host.JoinWorld(ctx, aurl)
	if err != nil {
		watchdog.Error(err)
		return 0
	}

	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(&WorldExport{
		inner:    world,
		origin:   host,
		event_ch: world.GetEventChannel(),
	}))
}

//export Host_WriteANDStatisticsLogFile
func Host_WriteANDStatisticsLogFile(h C.uintptr_t) C.int {
	host, ok := cgo.Handle(h).Value().(*abyss_host.AbyssHost)
	if !ok {
		return INVALID_HANDLE
	}

	os.WriteFile("and_stat.txt", []byte(host.GetStatistics()), 0644)
	return 0
}

//export World_GetSessionID
func World_GetSessionID(h C.uintptr_t, world_ID_out *C.char) C.int {
	world, ok := cgo.Handle(h).Value().(*WorldExport)
	if !ok {
		return INVALID_HANDLE
	}
	dest, ok := TryUnmarshalBytes(world_ID_out, 16)
	if !ok {
		return INVALID_ARGUMENTS
	}
	world_ID := world.inner.SessionID()
	copy(dest, world_ID[:])
	return 0
}

type ObjectAppendData struct {
	peer_hash string
	body_json string
}

type ObjectDeleteData struct {
	peer_hash string
	body_json string
}

//export World_GetURL
func World_GetURL(h C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	world, ok := cgo.Handle(h).Value().(*WorldExport)
	if !ok {
		return INVALID_HANDLE
	}
	return TryMarshalBytes(buf_ptr, buf_len, []byte(world.inner.URL()))
}

//export World_WaitEvent
func World_WaitEvent(h C.uintptr_t, event_type_out *C.int) C.uintptr_t {
	world, ok := cgo.Handle(h).Value().(*WorldExport)
	if !ok {
		watchdog.Error(errors.New("invalid handle"))
		return 0
	}

	event_any := <-world.event_ch

	switch event := event_any.(type) {
	case abyss.EWorldMemberRequest:
		*event_type_out = 1
		watchdog.CountHandleExport()
		return C.uintptr_t(cgo.NewHandle(&event))
	case abyss.EWorldMemberReady:
		*event_type_out = 2
		watchdog.CountHandleExport()
		return C.uintptr_t(cgo.NewHandle(event.Member))
	case abyss.EMemberObjectAppend:
		*event_type_out = 3
		data, _ := json.Marshal(functional.Filter(event.Objects, func(i abyss.ObjectInfo) struct {
			ID        string
			Addr      string
			Transform [7]float32
		} {
			return struct {
				ID        string
				Addr      string
				Transform [7]float32
			}{
				ID:        hex.EncodeToString(i.ID[:]),
				Addr:      i.Addr,
				Transform: i.Transform,
			}
		}))
		watchdog.CountHandleExport()
		return C.uintptr_t(cgo.NewHandle(&ObjectAppendData{
			peer_hash: event.PeerHash,
			body_json: string(data),
		}))
	case abyss.EMemberObjectDelete:
		*event_type_out = 4
		data, _ := json.Marshal(functional.Filter(event.ObjectIDs, func(u uuid.UUID) string {
			return hex.EncodeToString(u[:])
		}))
		watchdog.CountHandleExport()
		return C.uintptr_t(cgo.NewHandle(&ObjectDeleteData{
			peer_hash: event.PeerHash,
			body_json: string(data),
		}))
	case abyss.EWorldMemberLeave:
		*event_type_out = 5
		watchdog.CountHandleExport()
		return C.uintptr_t(cgo.NewHandle(&event))
	case abyss.EWorldTerminate:
		*event_type_out = 6
		return 0
	default:
		watchdog.Error(errors.New("internal fault"))
		*event_type_out = -1
		return 0
	}
}

//export WorldPeerRequest_GetHash
func WorldPeerRequest_GetHash(h C.uintptr_t, buf *C.char, buf_len C.int) C.int {
	event, ok := cgo.Handle(h).Value().(*abyss.EWorldMemberRequest)
	if !ok {
		return INVALID_HANDLE
	}

	return TryMarshalBytes(buf, buf_len, []byte(event.MemberHash))
}

//export WorldPeerRequest_Accept
func WorldPeerRequest_Accept(h C.uintptr_t) C.int {
	event, ok := cgo.Handle(h).Value().(*abyss.EWorldMemberRequest)
	if !ok {
		return INVALID_HANDLE
	}

	event.Accept()
	return 0
}

//export WorldPeerRequest_Decline
func WorldPeerRequest_Decline(h C.uintptr_t, code C.int, msg *C.char, msglen C.int) C.int {
	var msg_str string
	if msglen == 0 {
		msg_str = ""
	} else {
		msg_buf, ok := TryUnmarshalBytes(msg, msglen)
		if !ok {
			return INVALID_ARGUMENTS
		}
		msg_str = string(msg_buf)
	}
	event, ok := cgo.Handle(h).Value().(*abyss.EWorldMemberRequest)
	if !ok {
		return INVALID_HANDLE
	}

	event.Decline(int(code), msg_str)
	return 0
}

//export WorldPeer_GetHash
func WorldPeer_GetHash(h C.uintptr_t, buf *C.char, buf_len C.int) C.int {
	peer, ok := cgo.Handle(h).Value().(abyss.IWorldMember)
	if !ok {
		return INVALID_HANDLE
	}

	return TryMarshalBytes(buf, buf_len, []byte(peer.Hash()))
}

//export WorldPeer_AppendObjects
func WorldPeer_AppendObjects(h C.uintptr_t, json_ptr *C.char, json_len C.int) C.int {
	peer, ok := cgo.Handle(h).Value().(abyss.IWorldMember)
	if !ok {
		return INVALID_HANDLE
	}

	json_data, ok := TryUnmarshalBytes(json_ptr, json_len)
	if !ok {
		return INVALID_ARGUMENTS
	}
	var raw_object_infos []struct {
		ID        string
		Addr      string
		Transform [7]float32
	}
	err := json.Unmarshal(json_data, &raw_object_infos)
	if err != nil {
		watchdog.Error(err)
		return INVALID_ARGUMENTS
	}
	res, _, err := functional.Filter_until_err(raw_object_infos, func(i struct {
		ID        string
		Addr      string
		Transform [7]float32
	}) (abyss.ObjectInfo, error) {
		bytes, err := hex.DecodeString(i.ID)
		if err != nil {
			return abyss.ObjectInfo{}, err
		}
		return abyss.ObjectInfo{
			ID:        uuid.UUID(bytes),
			Addr:      i.Addr,
			Transform: i.Transform,
		}, nil
	})
	if err != nil {
		watchdog.Error(err)
		return INVALID_ARGUMENTS
	}

	peer.AppendObjects(res)
	return 0
}

//export WorldPeer_DeleteObjects
func WorldPeer_DeleteObjects(h C.uintptr_t, json_ptr *C.char, json_len C.int) C.int {
	peer, ok := cgo.Handle(h).Value().(abyss.IWorldMember)
	if !ok {
		return INVALID_HANDLE
	}

	json_data, ok := TryUnmarshalBytes(json_ptr, json_len)
	if !ok {
		return INVALID_ARGUMENTS
	}
	var raw_object_ids []string
	err := json.Unmarshal(json_data, &raw_object_ids)
	if err != nil {
		watchdog.Error(err)
		return INVALID_ARGUMENTS
	}
	res, _, err := functional.Filter_until_err(raw_object_ids, func(i string) (uuid.UUID, error) {
		bytes, err := hex.DecodeString(i)
		if err != nil {
			return uuid.Nil, err
		}
		return uuid.UUID(bytes), nil
	})
	if err != nil {
		watchdog.Error(err)
		return INVALID_ARGUMENTS
	}

	peer.DeleteObjects(res)
	return 0
}

//export WorldPeerObjectAppend_GetHead
func WorldPeerObjectAppend_GetHead(h C.uintptr_t, peer_hash_out *C.char, body_len *C.int) C.int {
	data, ok := cgo.Handle(h).Value().(*ObjectAppendData)
	if !ok {
		return INVALID_HANDLE
	}

	*body_len = C.int(len(data.body_json))
	return TryMarshalBytes(peer_hash_out, 128, []byte(data.peer_hash))
}

//export WorldPeerObjectAppend_GetBody
func WorldPeerObjectAppend_GetBody(h C.uintptr_t, buf *C.char, buf_len C.int) C.int {
	data, ok := cgo.Handle(h).Value().(*ObjectAppendData)
	if !ok {
		return INVALID_HANDLE
	}

	return TryMarshalBytes(buf, buf_len, []byte(data.body_json))
}

//export WorldPeerObjectDelete_GetHead
func WorldPeerObjectDelete_GetHead(h C.uintptr_t, peer_hash_out *C.char, body_len *C.int) C.int {
	data, ok := cgo.Handle(h).Value().(*ObjectDeleteData)
	if !ok {
		return INVALID_HANDLE
	}

	*body_len = C.int(len(data.body_json))
	return TryMarshalBytes(peer_hash_out, 128, []byte(data.peer_hash))
}

//export WorldPeerObjectDelete_GetBody
func WorldPeerObjectDelete_GetBody(h C.uintptr_t, buf *C.char, buf_len C.int) C.int {
	data, ok := cgo.Handle(h).Value().(*ObjectDeleteData)
	if !ok {
		return INVALID_HANDLE
	}

	return TryMarshalBytes(buf, buf_len, []byte(data.body_json))
}

//export WorldPeerLeave_GetHash
func WorldPeerLeave_GetHash(h C.uintptr_t, buf *C.char, buf_len C.int) C.int {
	event, ok := cgo.Handle(h).Value().(*abyss.EWorldMemberLeave)
	if !ok {
		return INVALID_HANDLE
	}

	return TryMarshalBytes(buf, buf_len, []byte(event.PeerHash))
}

//export WorldLeave
func WorldLeave(h C.uintptr_t) C.int {
	world, ok := cgo.Handle(h).Value().(*WorldExport)
	if !ok {
		return INVALID_HANDLE
	}

	world.origin.LeaveWorld(world.inner)
	return 0
}

type AbystClientExport struct {
	inner *http3.ClientConn
}

func (c *AbystClientExport) Destuct() {
	c.inner.CloseWithError(0, "abyst client disconnected")
}

//export Host_GetAbystClientConnection
func Host_GetAbystClientConnection(h C.uintptr_t, peer_hash_ptr *C.char, peer_hash_len C.int, timeout_ms C.int, err_out *C.uintptr_t) C.uintptr_t {
	host, ok := cgo.Handle(h).Value().(*abyss_host.AbyssHost)
	if !ok {
		*err_out = marshalError(errors.New("invalid handle"))
		return 0
	}

	peer_hash_buf, ok := TryUnmarshalBytes(peer_hash_ptr, peer_hash_len)
	if !ok {
		return 0
	}
	http_client, err := host.GetAbystClientConnection(string(peer_hash_buf))
	if err != nil {
		*err_out = marshalError(err)
		return 0
	}

	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(&AbystClientExport{
		inner: http_client,
	}))
}

type AbystResponseExport struct {
	inner *http.Response
}

func (w *AbystResponseExport) Destruct() {
	w.inner.Body.Close()
}

//export AbystClient_Request
func AbystClient_Request(h C.uintptr_t, method C.int, path_ptr *C.char, path_len C.int, err_out *C.uintptr_t) C.uintptr_t {
	client, ok := cgo.Handle(h).Value().(*AbystClientExport)
	if !ok {
		*err_out = marshalError(errors.New("invalid handle"))
		return 0
	}
	var method_string string
	switch method {
	case 0:
		method_string = http.MethodGet
	default:
		watchdog.CountHandleExport()
		return C.uintptr_t(cgo.NewHandle(&AbystResponseExport{
			inner: &http.Response{
				Status:     "400 Bad Request",
				StatusCode: 400,
			},
		}))
	}

	var path_string string
	if path_len == 0 {
		path_string = ""
	} else {
		path_buf, ok := TryUnmarshalBytes(path_ptr, path_len)
		if !ok {
			return 0
		}
		path_string = string(path_buf)
	}
	request, err := http.NewRequest(method_string, "https://a.abyst/"+path_string, nil)
	if err != nil {
		*err_out = marshalError(err)
		return 0
	}
	response, err := client.inner.RoundTrip(request)
	if err != nil {
		*err_out = marshalError(err)
		return 0
	}

	watchdog.CountHandleExport()
	return C.uintptr_t(cgo.NewHandle(&AbystResponseExport{
		inner: response,
	}))
}

//export AbyssResponse_GetHeaders
func AbyssResponse_GetHeaders(h C.uintptr_t, buf *C.char, buf_len C.int) C.int {
	response, ok := cgo.Handle(h).Value().(*AbystResponseExport)
	if !ok {
		return INVALID_HANDLE
	}

	data := make(map[string]any)
	data["Code"] = response.inner.StatusCode
	data["Status"] = response.inner.Status
	if response.inner.Header != nil {
		data["Header"] = response.inner.Header
	}

	json_bytes, err := json.Marshal(data)
	if err != nil {
		data := make(map[string]any)
		data["Code"] = 422
		data["Status"] = "Unprocessable Entity"
		json_bytes, _ := json.Marshal(data)
		return TryMarshalBytes(buf, buf_len, json_bytes)
	}
	return TryMarshalBytes(buf, buf_len, json_bytes)
}

//export AbyssResponse_GetContentLength
func AbyssResponse_GetContentLength(h C.uintptr_t) C.int {
	response, ok := cgo.Handle(h).Value().(*AbystResponseExport)
	if !ok {
		return INVALID_HANDLE
	}

	if response.inner.ContentLength < 0 || response.inner.ContentLength > 1024*1024*1024 {
		return REMOTE_ERROR
	}

	return C.int(response.inner.ContentLength)
}

//export AbystResponse_ReadBody
func AbystResponse_ReadBody(h C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	response, ok := cgo.Handle(h).Value().(*AbystResponseExport)
	if !ok {
		return INVALID_HANDLE
	}

	if buf_len <= 0 || buf_len > 1024*1024*1024 { //over 1GiB - must be some error.
		return INVALID_ARGUMENTS
	}

	buf, ok := TryUnmarshalBytes(buf_ptr, buf_len)
	if !ok {
		return INVALID_ARGUMENTS
	}
	read_len, err := response.inner.Body.Read(buf)
	if read_len == 0 && err != nil {
		return EOF
	}

	return C.int(read_len)
}

//export AbystResponse_ReadBodyAll
func AbystResponse_ReadBodyAll(h C.uintptr_t, buf_ptr *C.char, buf_len C.int) C.int {
	response, ok := cgo.Handle(h).Value().(*AbystResponseExport)
	if !ok {
		return INVALID_HANDLE
	}

	if int(buf_len) < int(response.inner.ContentLength) {
		return BUFFER_OVERFLOW
	}

	buf, ok := TryUnmarshalBytes(buf_ptr, buf_len)
	if !ok {
		return INVALID_ARGUMENTS
	}
	readlen := 0
	for {
		n, err := response.inner.Body.Read(buf[readlen:])
		if err == io.EOF {
			readlen += n
			break
		}
		if err != nil {
			watchdog.Error(err)
			return ERROR
		}
		readlen += n
	}

	return C.int(readlen)
}

//TODO: enable some external binding for abyst server. we may expect all abyst local hosts are just available some elsewhere. enable forwarding

func main() {}
