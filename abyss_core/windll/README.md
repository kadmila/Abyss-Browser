# Windll - DLL Export API Reference

This package exports C-compatible functions for the Abyss Browser DLL (`abyssnet.dll`).

## Build

```powershell
# From abyss_core directory
.\build_dll.ps1          # Release build
.\build_dll_debug.ps1    # Debug build
```

Output: `abyssnet.dll` and `abyssnet.h`

## Quick Example: HTTP Client Usage

### AbystClient (Peer-to-Peer)

```c
// 1. Initialize and create host
Init();
uintptr_t host;
NewHost(key_bytes, key_len, &host);
Host_Run(host);

// 2. Connect to peer
Host_Dial(host, peer_id, peer_id_len);

// 3. Create Abyst client and make request to peer
uintptr_t abyst_client = Host_NewAbystClient(host);
uintptr_t response;
if (AbystClient_Get(abyst_client, peer_id, peer_id_len, "/api/data", 9, &response) == 0) {
    int status = HttpResponse_StatusCode(response);
    char body[4096];
    int body_len = HttpResponse_ReadBody(response, body, sizeof(body));
    CloseHttpResponse(response);
}

CloseAbyssClient(abyst_client);
CloseHost(host);
```

### CollocatedHttp3Client (Standard HTTPS)

```c
// 1. Initialize and create host
Init();
uintptr_t host;
NewHost(key_bytes, key_len, &host);
Host_Run(host);

// 2. Create HTTP/3 client (reuses host's QUIC transport)
uintptr_t http3_client = Host_NewCollocatedHttp3Client(host);

// 3. Make standard HTTPS request
uintptr_t response;
if (Http3Client_Get(http3_client, "https://example.com/api", 23, &response) == 0) {
    int status = HttpResponse_StatusCode(response);
    char body[4096];
    int body_len = HttpResponse_ReadBody(response, body, sizeof(body));
    CloseHttpResponse(response);
}

CloseAbyssClientCollocatedHttp3Client(http3_client);
CloseHost(host);
```

## Return Codes

```c
#define EOF               -1
#define INVALID_ARGUMENTS -2
#define BUFFER_OVERFLOW   -3
#define REMOTE_ERROR      -4
```

## Initialization

### Init
```c
int Init();
```
**Must be called before any other function.** Initializes the watchdog and internal state.

**Returns:** `0` on success

---

## Error Handling

### GetErrorBodyLength
```c
int GetErrorBodyLength(uintptr_t h_error);
```
Get the length of an error message.

**Parameters:**
- `h_error`: Error handle

**Returns:** Length of error message in bytes

### GetErrorBody
```c
int GetErrorBody(uintptr_t h_error, char* buf_ptr, int buf_len);
```
Copy error message to buffer.

**Parameters:**
- `h_error`: Error handle
- `buf_ptr`: Output buffer
- `buf_len`: Buffer length

**Returns:** Number of bytes written, or negative error code

### CloseError
```c
void CloseError(uintptr_t h_error);
```
Release an error handle.

**Parameters:**
- `h_error`: Error handle to release

---

## Host Management

### NewHost
```c
uintptr_t NewHost(char* root_key_ptr, int root_key_len, uintptr_t* out);
```
Create a new Abyss host.

**Parameters:**
- `root_key_ptr`: SSH private key bytes (OpenSSH format)
- `root_key_len`: Key length
- `out`: Output host handle

**Returns:** `0` on success, or error handle

### CloseHost
```c
void CloseHost(uintptr_t h);
```
Close and release a host handle.

**Parameters:**
- `h`: Host handle

### Host_Run
```c
void Host_Run(uintptr_t h);
```
Start the host service loop in a background goroutine.

**Parameters:**
- `h`: Host handle

### Host_WaitForEvent
```c
uintptr_t Host_WaitForEvent(uintptr_t h, int* event_type_out, uintptr_t* event_handle_out);
```
Wait for and retrieve the next host event (blocking).

**Parameters:**
- `h`: Host handle
- `event_type_out`: Output event type (see Event Types)
- `event_handle_out`: Output event handle

**Returns:** `0` on success, or error handle

---

## Host Information

### Host_ID
```c
int Host_ID(uintptr_t h, char* buf_ptr, int buf_len);
```
Get the host's peer ID.

**Parameters:**
- `h`: Host handle
- `buf_ptr`: Output buffer
- `buf_len`: Buffer length

**Returns:** Number of bytes written, or negative error code

### Host_LocalAddrCandidates
```c
int Host_LocalAddrCandidates(uintptr_t h, char* buf_ptr, int buf_len);
```
Get local address candidates (newline-separated).

**Parameters:**
- `h`: Host handle
- `buf_ptr`: Output buffer
- `buf_len`: Buffer length

**Returns:** Number of bytes written, or negative error code

### Host_RootCertificate
```c
int Host_RootCertificate(uintptr_t h, char* buf_ptr, int buf_len);
```
Get the host's root certificate (PEM format).

**Parameters:**
- `h`: Host handle
- `buf_ptr`: Output buffer
- `buf_len`: Buffer length

**Returns:** Number of bytes written, or negative error code

### Host_HandshakeKeyCertificate
```c
int Host_HandshakeKeyCertificate(uintptr_t h, char* buf_ptr, int buf_len);
```
Get the host's handshake key certificate (PEM format).

**Parameters:**
- `h`: Host handle
- `buf_ptr`: Output buffer
- `buf_len`: Buffer length

**Returns:** Number of bytes written, or negative error code

---

## Peer Management

### Host_AppendKnownPeer
```c
uintptr_t Host_AppendKnownPeer(
    uintptr_t h,
    char* root_cert_ptr, int root_cert_len,
    char* handshake_info_cert_ptr, int handshake_info_cert_len
);
```
Add a peer's certificates to the known peers list.

**Parameters:**
- `h`: Host handle
- `root_cert_ptr`: Peer's root certificate (PEM)
- `root_cert_len`: Certificate length
- `handshake_info_cert_ptr`: Peer's handshake certificate (PEM)
- `handshake_info_cert_len`: Certificate length

**Returns:** `0` on success, or error handle

### Host_EraseKnownPeer
```c
uintptr_t Host_EraseKnownPeer(uintptr_t h, char* id_ptr, int id_len);
```
Remove a peer from the known peers list.

**Parameters:**
- `h`: Host handle
- `id_ptr`: Peer ID string
- `id_len`: ID length

**Returns:** `0` on success, or error handle

### Host_Dial
```c
uintptr_t Host_Dial(uintptr_t h, char* id_ptr, int id_len);
```
Dial a connection to a peer.

**Parameters:**
- `h`: Host handle
- `id_ptr`: Peer ID string
- `id_len`: ID length

**Returns:** `0` on success, or error handle

---

## Abyst Gateway (HTTP/3)

### Host_ConfigAbystGateway
```c
uintptr_t Host_ConfigAbystGateway(uintptr_t h, char* config_ptr, int config_len);
```
Configure the Abyst gateway with JSON configuration.

**Parameters:**
- `h`: Host handle
- `config_ptr`: JSON configuration string
- `config_len`: Configuration length

**Returns:** `0` on success, or error handle

**Example config:**
```json
{
  "api": "http://localhost:8080",
  "static": "dir:///./public"
}
```

### Host_NewAbystClient
```c
uintptr_t Host_NewAbystClient(uintptr_t h);
```
Create an Abyst client (peer-to-peer HTTP/3 client).

**Parameters:**
- `h`: Host handle

**Returns:** Abyst client handle

### CloseAbyssClient
```c
void CloseAbyssClient(uintptr_t h);
```
Release an Abyst client handle.

**Parameters:**
- `h`: Abyst client handle

---

## AbystClient Operations

### AbystClient_Get
```c
uintptr_t AbystClient_Get(
    uintptr_t h_client,
    char* peer_id_ptr, int peer_id_len,
    char* path_ptr, int path_len,
    uintptr_t* response_handle_out
);
```
Perform HTTP GET request to a peer via Abyst protocol.

**Parameters:**
- `h_client`: Abyst client handle (from `Host_NewAbystClient`)
- `peer_id_ptr`: Target peer ID string
- `peer_id_len`: Peer ID length
- `path_ptr`: Request path (e.g., "/api/data")
- `path_len`: Path length
- `response_handle_out`: Output HTTP response handle

**Returns:** `0` on success, or error handle

**Note:** Response must be closed with `CloseHttpResponse` when done.

### AbystClient_Post
```c
uintptr_t AbystClient_Post(
    uintptr_t h_client,
    char* peer_id_ptr, int peer_id_len,
    char* path_ptr, int path_len,
    char* content_type_ptr, int content_type_len,
    char* body_ptr, int body_len,
    uintptr_t* response_handle_out
);
```
Perform HTTP POST request to a peer via Abyst protocol.

**Parameters:**
- `h_client`: Abyst client handle
- `peer_id_ptr`: Target peer ID string
- `peer_id_len`: Peer ID length
- `path_ptr`: Request path
- `path_len`: Path length
- `content_type_ptr`: Content-Type header (e.g., "application/json")
- `content_type_len`: Content-Type length
- `body_ptr`: Request body data
- `body_len`: Body length
- `response_handle_out`: Output HTTP response handle

**Returns:** `0` on success, or error handle

### AbystClient_Head
```c
uintptr_t AbystClient_Head(
    uintptr_t h_client,
    char* peer_id_ptr, int peer_id_len,
    char* path_ptr, int path_len,
    uintptr_t* response_handle_out
);
```
Perform HTTP HEAD request to a peer via Abyst protocol.

**Parameters:**
- `h_client`: Abyst client handle
- `peer_id_ptr`: Target peer ID string
- `peer_id_len`: Peer ID length
- `path_ptr`: Request path
- `path_len`: Path length
- `response_handle_out`: Output HTTP response handle

**Returns:** `0` on success, or error handle

---

## HTTP Response Handling

### HttpResponse_StatusCode
```c
int HttpResponse_StatusCode(uintptr_t h_response);
```
Get the HTTP status code from a response.

**Parameters:**
- `h_response`: HTTP response handle

**Returns:** HTTP status code (e.g., 200, 404, 500)

### HttpResponse_GetHeader
```c
int HttpResponse_GetHeader(
    uintptr_t h_response,
    char* key_ptr, int key_len,
    char* value_buf_ptr, int value_buf_len
);
```
Get a header value from the response.

**Parameters:**
- `h_response`: HTTP response handle
- `key_ptr`: Header key (e.g., "Content-Type")
- `key_len`: Key length
- `value_buf_ptr`: Output buffer for header value
- `value_buf_len`: Buffer length

**Returns:** Number of bytes written, or negative error code

### HttpResponse_ReadBody
```c
int HttpResponse_ReadBody(
    uintptr_t h_response,
    char* buf_ptr, int buf_len
);
```
Read the entire response body.

**Parameters:**
- `h_response`: HTTP response handle
- `buf_ptr`: Output buffer for body data
- `buf_len`: Buffer length

**Returns:** Number of bytes written, or negative error code

**Note:** Reads entire body into memory. Returns `REMOTE_ERROR` if read fails.

### CloseHttpResponse
```c
void CloseHttpResponse(uintptr_t h_response);
```
Close and release an HTTP response handle.

**Parameters:**
- `h_response`: HTTP response handle

**Note:** Also closes the response body if still open.

---

## Collocated HTTP/3 Client

### Host_NewCollocatedHttp3Client
```c
uintptr_t Host_NewCollocatedHttp3Client(uintptr_t h);
```
Create a standard HTTP/3 client that reuses the host's QUIC transport.

**Parameters:**
- `h`: Host handle

**Returns:** HTTP/3 client handle

### CloseAbyssClientCollocatedHttp3Client
```c
void CloseAbyssClientCollocatedHttp3Client(uintptr_t h);
```
Release a collocated HTTP/3 client handle.

**Parameters:**
- `h`: HTTP/3 client handle

---

## Collocated HTTP/3 Client Operations

### Http3Client_Get
```c
uintptr_t Http3Client_Get(
    uintptr_t h_client,
    char* url_ptr, int url_len,
    uintptr_t* response_handle_out
);
```
Perform standard HTTP/3 GET request to any URL.

**Parameters:**
- `h_client`: HTTP/3 client handle (from `Host_NewCollocatedHttp3Client`)
- `url_ptr`: Full URL string (e.g., "https://example.com/api")
- `url_len`: URL length
- `response_handle_out`: Output HTTP response handle

**Returns:** `0` on success, or error handle

**Note:** Unlike AbystClient, this uses standard URLs (not peer IDs).

### Http3Client_Post
```c
uintptr_t Http3Client_Post(
    uintptr_t h_client,
    char* url_ptr, int url_len,
    char* content_type_ptr, int content_type_len,
    char* body_ptr, int body_len,
    uintptr_t* response_handle_out
);
```
Perform standard HTTP/3 POST request.

**Parameters:**
- `h_client`: HTTP/3 client handle
- `url_ptr`: Full URL string
- `url_len`: URL length
- `content_type_ptr`: Content-Type header (e.g., "application/json")
- `content_type_len`: Content-Type length
- `body_ptr`: Request body data
- `body_len`: Body length
- `response_handle_out`: Output HTTP response handle

**Returns:** `0` on success, or error handle

### Http3Client_Head
```c
uintptr_t Http3Client_Head(
    uintptr_t h_client,
    char* url_ptr, int url_len,
    uintptr_t* response_handle_out
);
```
Perform standard HTTP/3 HEAD request.

**Parameters:**
- `h_client`: HTTP/3 client handle
- `url_ptr`: Full URL string
- `url_len`: URL length
- `response_handle_out`: Output HTTP response handle

**Returns:** `0` on success, or error handle

---

## Event Types

```c
enum AbyssEventType {
    AbyssEvent_WorldEnter = 1,
    AbyssEvent_SessionRequest,
    AbyssEvent_SessionReady,
    AbyssEvent_SessionClose,
    AbyssEvent_ObjectAppend,
    AbyssEvent_ObjectDelete,
    AbyssEvent_WorldLeave,
    AbyssEvent_PeerConnected,
    AbyssEvent_PeerDisconnected
};
```

### CloseEvent
```c
void CloseEvent(uintptr_t h_event);
```
Release an event handle.

**Parameters:**
- `h_event`: Event handle

---

## Event Queries

### Event_WorldEnter_Query
```c
int Event_WorldEnter_Query(
    uintptr_t h_event,
    char* world_session_id_buf,
    char* url_buf_ptr, int url_buf_len
);
```
Query WorldEnter event data.

**Parameters:**
- `h_event`: Event handle
- `world_session_id_buf`: Output world session ID (16 bytes)
- `url_buf_ptr`: Output URL buffer
- `url_buf_len`: Buffer length

**Returns:** Number of bytes written to URL buffer, or negative error code

**Note:** World handles are ONLY returned from `Host_OpenWorld` and `Host_JoinWorld`. This event only provides the world session ID for reference.

### Event_SessionRequest_Query
```c
int Event_SessionRequest_Query(
    uintptr_t h_event,
    char* world_session_id_buf,
    char* peer_session_id_buf,
    char* peer_id_buf_ptr, int peer_id_buf_len
);
```
Query SessionRequest event data.

**Parameters:**
- `h_event`: Event handle
- `world_session_id_buf`: Output world session ID (16 bytes)
- `peer_session_id_buf`: Output peer session ID (16 bytes)
- `peer_id_buf_ptr`: Output peer ID buffer
- `peer_id_buf_len`: Buffer length

**Returns:** Number of bytes written to peer ID buffer, or negative error code

### Event_SessionReady_Query
```c
int Event_SessionReady_Query(
    uintptr_t h_event,
    char* world_session_id_buf,
    char* peer_session_id_buf,
    char* peer_id_buf_ptr, int peer_id_buf_len
);
```
Query SessionReady event data (same parameters as SessionRequest).

### Event_SessionClose_Query
```c
int Event_SessionClose_Query(
    uintptr_t h_event,
    char* world_session_id_buf,
    char* peer_session_id_buf,
    char* peer_id_buf_ptr, int peer_id_buf_len
);
```
Query SessionClose event data (same parameters as SessionRequest).

### Event_ObjectAppend_Query
```c
int Event_ObjectAppend_Query(
    uintptr_t h_event,
    char* world_session_id_buf,
    char* peer_session_id_buf,
    char* peer_id_buf_ptr, int peer_id_buf_len,
    int* object_count_out
);
```
Query ObjectAppend event data.

**Parameters:**
- `h_event`: Event handle
- `world_session_id_buf`: Output world session ID (16 bytes)
- `peer_session_id_buf`: Output peer session ID (16 bytes)
- `peer_id_buf_ptr`: Output peer ID buffer
- `peer_id_buf_len`: Buffer length
- `object_count_out`: Output object count

**Returns:** Number of bytes written to peer ID buffer, or negative error code

### Event_ObjectAppend_GetObjects
```c
int Event_ObjectAppend_GetObjects(
    uintptr_t h_event,
    char** object_id_bufs,
    float** object_transform_bufs,
    char** object_addr_bufs, int object_addr_buf_len
);
```
Get objects from ObjectAppend event.

**Parameters:**
- `h_event`: Event handle
- `object_id_bufs`: Array of pointers to ID buffers (16 bytes each)
- `object_transform_bufs`: Array of pointers to transform buffers (7 floats each)
- `object_addr_bufs`: Array of pointers to address buffers
- `object_addr_buf_len`: Address buffer length (per object)

**Returns:** `0` on success, or `BUFFER_OVERFLOW`

### Event_ObjectDelete_Query
```c
int Event_ObjectDelete_Query(
    uintptr_t h_event,
    char* world_session_id_buf,
    char* peer_session_id_buf,
    char* peer_id_buf_ptr, int peer_id_buf_len,
    int* object_count_out
);
```
Query ObjectDelete event data (same parameters as ObjectAppend).

### Event_ObjectDelete_GetObjectIDs
```c
int Event_ObjectDelete_GetObjectIDs(
    uintptr_t h_event,
    char** object_id_bufs
);
```
Get object IDs from ObjectDelete event.

**Parameters:**
- `h_event`: Event handle
- `object_id_bufs`: Array of pointers to ID buffers (16 bytes each)

**Returns:** `0` on success

### Event_WorldLeave_Query
```c
int Event_WorldLeave_Query(
    uintptr_t h_event,
    char* world_session_id_buf,
    int* code_out,
    char* message_buf_ptr, int message_buf_len
);
```
Query WorldLeave event data.

**Parameters:**
- `h_event`: Event handle
- `world_session_id_buf`: Output world session ID (16 bytes)
- `code_out`: Output leave code
- `message_buf_ptr`: Output message buffer
- `message_buf_len`: Buffer length

**Returns:** Number of bytes written to message buffer, or negative error code

### Event_PeerConnected_Query
```c
int Event_PeerConnected_Query(
    uintptr_t h_event,
    uintptr_t* peer_handle_out,
    char* peer_id_buf_ptr, int peer_id_buf_len
);
```
Query PeerConnected event data.

**Parameters:**
- `h_event`: Event handle
- `peer_handle_out`: Output peer handle
- `peer_id_buf_ptr`: Output peer ID buffer
- `peer_id_buf_len`: Buffer length

**Returns:** Number of bytes written to peer ID buffer, or negative error code

### Event_PeerDisconnected_Query
```c
int Event_PeerDisconnected_Query(
    uintptr_t h_event,
    char* peer_id_buf_ptr, int peer_id_buf_len
);
```
Query PeerDisconnected event data.

**Parameters:**
- `h_event`: Event handle
- `peer_id_buf_ptr`: Output peer ID buffer
- `peer_id_buf_len`: Buffer length

**Returns:** Number of bytes written to peer ID buffer, or negative error code

---

## World Management

### Host_OpenWorld
```c
uintptr_t Host_OpenWorld(
    uintptr_t h_host,
    char* world_url_ptr, int world_url_len,
    uintptr_t* world_handle_out
);
```
Create and open a new world with the specified URL.

**Parameters:**
- `h_host`: Host handle
- `world_url_ptr`: World URL string (e.g., "abyss://example.com/world")
- `world_url_len`: URL string length
- `world_handle_out`: Output world handle

**Returns:** `0` on success, or error handle

**Events:** Fires `AbyssEvent_WorldEnter` event immediately. The world handle is ONLY available from `world_handle_out`, not from the event query.

### Host_JoinWorld
```c
uintptr_t Host_JoinWorld(
    uintptr_t h_host,
    uintptr_t h_peer,
    char* path_ptr, int path_len,
    uintptr_t* world_handle_out
);
```
Join an existing world hosted by a peer.

**Parameters:**
- `h_host`: Host handle
- `h_peer`: Connected peer handle (must be obtained from `AbyssEvent_PeerConnected`)
- `path_ptr`: World path on the peer (e.g., "/")
- `path_len`: Path string length
- `world_handle_out`: Output world handle (only set on success)

**Returns:** `0` on success, or error handle

**Events:** 
- The remote host will receive `AbyssEvent_SessionRequest` 
- Upon acceptance, fires `AbyssEvent_WorldEnter` locally

### Host_ExposeWorldForJoin
```c
uintptr_t Host_ExposeWorldForJoin(
    uintptr_t h_host,
    uintptr_t h_world,
    char* path_ptr, int path_len
);
```
Expose a world at a specific path so other peers can join it.

**Parameters:**
- `h_host`: Host handle
- `h_world`: World handle (from `Host_OpenWorld`)
- `path_ptr`: Path to expose the world at (e.g., "/")
- `path_len`: Path string length

**Returns:** `0` on success, or error handle

**Note:** Must be called before other peers can join the world via `Host_JoinWorld`.

### CloseWorld
```c
void CloseWorld(uintptr_t h_world);
```
Release a world handle.

**Parameters:**
- `h_world`: World handle

### World_AcceptSession
```c
void World_AcceptSession(
    uintptr_t h_host,
    uintptr_t h_world,
    uintptr_t h_peer,
    char* peer_session_id_buf
);
```
Accept a session request.

**Parameters:**
- `h_host`: Host handle
- `h_world`: World handle
- `h_peer`: Peer handle
- `peer_session_id_buf`: Peer session ID (16 bytes)

### World_DeclineSession
```c
void World_DeclineSession(
    uintptr_t h_host,
    uintptr_t h_world,
    uintptr_t h_peer,
    char* peer_session_id_buf,
    int code,
    char* message_buf_ptr, int message_buf_len
);
```
Decline a session request.

**Parameters:**
- `h_host`: Host handle
- `h_world`: World handle
- `h_peer`: Peer handle
- `peer_session_id_buf`: Peer session ID (16 bytes)
- `code`: Decline code
- `message_buf_ptr`: Decline message
- `message_buf_len`: Message length

### World_Close
```c
void World_Close(uintptr_t h_host, uintptr_t h_world);
```
Close a world.

**Parameters:**
- `h_host`: Host handle
- `h_world`: World handle

### World_ObjectAppend
```c
void World_ObjectAppend(
    uintptr_t h_host,
    uintptr_t h_world,
    int peer_count,
    uintptr_t* h_peers,
    char** peer_session_id_bufs,
    int object_count,
    char** object_id_bufs,
    float** object_transform_bufs,
    char** object_addr_bufs, int object_addr_buf_len
);
```
Append objects to a world.

**Parameters:**
- `h_host`: Host handle
- `h_world`: World handle
- `peer_count`: Number of peers
- `h_peers`: Array of peer handles
- `peer_session_id_bufs`: Array of session ID buffers (16 bytes each)
- `object_count`: Number of objects
- `object_id_bufs`: Array of object ID buffers (16 bytes each)
- `object_transform_bufs`: Array of transform buffers (7 floats each)
- `object_addr_bufs`: Array of address buffers
- `object_addr_buf_len`: Address buffer length (per object)

### World_ObjectDelete
```c
void World_ObjectDelete(
    uintptr_t h_host,
    uintptr_t h_world,
    int peer_count,
    uintptr_t* h_peers,
    char** peer_session_id_bufs,
    int object_count,
    char** object_id_bufs
);
```
Delete objects from a world.

**Parameters:**
- `h_host`: Host handle
- `h_world`: World handle
- `peer_count`: Number of peers
- `h_peers`: Array of peer handles
- `peer_session_id_bufs`: Array of session ID buffers (16 bytes each)
- `object_count`: Number of objects
- `object_id_bufs`: Array of object ID buffers (16 bytes each)

---

## Peer Handle Management

### ClosePeer
```c
void ClosePeer(uintptr_t h_peer);
```
Release a peer handle.

**Parameters:**
- `h_peer`: Peer handle

---

## Notes

- All handles must be explicitly released using their corresponding `Close*` functions
- Buffer functions return the number of bytes written, or a negative error code
- UUID buffers are always 16 bytes (binary format)
- Transform arrays are 7 floats: `[position.x, position.y, position.z, rotation.x, rotation.y, rotation.z, rotation.w]`
- String buffers use UTF-8 encoding
