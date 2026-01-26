package main

/*
#cgo CFLAGS: -std=c99
#include <stdint.h>
#include <windows.h>

#ifndef _WAITER_CALLBACK_T

typedef void (*waiter_callback_t)(uintptr_t);
static inline void call_waiter_callback(waiter_callback_t cb, uintptr_t value) {
	cb(value);
}

#define _WAITER_CALLBACK_T
#endif
*/
import "C"

import (
	"bytes"
	"errors"
	"net/http"
	"runtime/cgo"

	"github.com/kadmila/Abyss-Browser/abyss_core/watchdog"
)

//export Http3Client_Get
func Http3Client_Get(
	h_client C.uintptr_t,
	url_ptr *C.char, url_len C.int,
	result_handle_out *C.uintptr_t,
	waiter_callback C.waiter_callback_t,
	waiter_callback_arg C.uintptr_t,
) C.uintptr_t {
	client, ok := cgo.Handle(h_client).Value().(*http.Client)
	url_bytes, ok := TryUnmarshalBytes(url_ptr, url_len)
	if !ok {
		C.call_waiter_callback(waiter_callback, waiter_callback_arg)
		return marshalError(errors.New("nil arguments"))
	}
	url := string(url_bytes)

	result := &HttpIOResult{}
	watchdog.CountHandleExport()
	*result_handle_out = C.uintptr_t(cgo.NewHandle(result))

	go func() {
		resp, err := client.Get(url)
		result.response = resp
		result.err = err

		C.call_waiter_callback(waiter_callback, waiter_callback_arg)
	}()

	return 0
}

//export Http3Client_Post
func Http3Client_Post(
	h_client C.uintptr_t,
	h_event C.HANDLE,
	url_ptr *C.char, url_len C.int,
	content_type_ptr *C.char, content_type_len C.int,
	body_ptr *C.char, body_len C.int,
	result_handle_out *C.uintptr_t,
) C.uintptr_t {
	client := cgo.Handle(h_client).Value().(*http.Client)
	url, url_ok := TryUnmarshalBytes(url_ptr, url_len)
	content_type, content_type_ok := TryUnmarshalBytes(content_type_ptr, content_type_len)
	body, body_ok := TryUnmarshalBytes(body_ptr, body_len)
	if !(url_ok && content_type_ok && body_ok) {
		return marshalError(errors.New("nil arguments"))
	}

	result := &HttpIOResult{}
	watchdog.CountHandleExport()
	*result_handle_out = C.uintptr_t(cgo.NewHandle(result))

	go func() {
		resp, err := client.Post(
			string(url),
			string(content_type),
			bytes.NewReader(body),
		)
		result.response = resp
		result.err = err
		C.SetEvent(h_event)
	}()

	return 0
}

//export Http3Client_Head
func Http3Client_Head(
	h_client C.uintptr_t,
	h_event C.HANDLE,
	url_ptr *C.char, url_len C.int,
	result_handle_out *C.uintptr_t,
) C.uintptr_t {
	client := cgo.Handle(h_client).Value().(*http.Client)
	url, ok := TryUnmarshalBytes(url_ptr, url_len)
	if !ok {
		return marshalError(errors.New("nil arguments"))
	}

	result := &HttpIOResult{}
	watchdog.CountHandleExport()
	*result_handle_out = C.uintptr_t(cgo.NewHandle(result))

	go func() {
		resp, err := client.Head(string(url))
		result.response = resp
		result.err = err
		C.SetEvent(h_event)
	}()

	return 0
}
