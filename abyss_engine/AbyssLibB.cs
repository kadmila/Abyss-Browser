using AbyssCLI.AML.Event;
using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Reflection.Metadata;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using static AbyssCLI.AbyssLibB;

#nullable enable
namespace AbyssCLI;

/// <summary>
/// New version of AbyssLib with improved API based on abyssnet.h header.
/// </summary>
public static class AbyssLibB
{
    private const string DllName = "abyssnet.dll";

    public const int UrlMaxLength = 4096;
    public const int PeerIdMaxLength = 100;
    public const int GeneralTextMaxLength = 1024;

    #region P/Invoke Declarations

    [LibraryImport(DllName)] private static extern int Init();
    [LibraryImport(DllName)] private static extern int GetErrorBodyLength(IntPtr h_error);
    [LibraryImport(DllName)] private static extern unsafe int GetErrorBody(IntPtr h_error, byte* buf_ptr, int buf_len);
    [LibraryImport(DllName)] private static extern void CloseError(IntPtr h_error);

    [LibraryImport(DllName)] private static extern unsafe IntPtr NewHost(byte* root_key_ptr, int root_key_len, IntPtr* host_out);
    [LibraryImport(DllName)] private static extern void CloseHost(IntPtr h);
    [LibraryImport(DllName)] private static extern IntPtr Host_Bind(IntPtr h);
    [LibraryImport(DllName)] private static extern void Host_Serve(IntPtr h);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Host_WaitForEvent(IntPtr h, int* event_type_out, IntPtr* event_handle_out);
    [LibraryImport(DllName)] private static extern void CloseEvent(IntPtr h);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Host_OpenWorld(IntPtr h, byte* world_url_ptr, int world_url_len, IntPtr* world_handle_out);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Host_JoinWorld(IntPtr h, IntPtr h_peer, byte* path_ptr, int path_len, IntPtr* world_handle_out);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Host_ExposeWorldForJoin(IntPtr h, IntPtr h_world, byte* path_ptr, int path_len);
    [LibraryImport(DllName)] private static extern void Host_HideWorld(IntPtr h, IntPtr h_world);
    [LibraryImport(DllName)] private static extern unsafe int Host_LocalAddrCandidates(IntPtr h, byte* buf_ptr, int buf_len);
    [LibraryImport(DllName)] private static extern unsafe int Host_ID(IntPtr h, byte* buf_ptr, int buf_len);
    [LibraryImport(DllName)] private static extern unsafe int Host_RootCertificate(IntPtr h, byte* buf_ptr, int buf_len);
    [LibraryImport(DllName)] private static extern unsafe int Host_HandshakeKeyCertificate(IntPtr h, byte* buf_ptr, int buf_len);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Host_AppendKnownPeer(IntPtr h, byte* root_cert_ptr, int root_cert_len, byte* handshake_info_cert_ptr, int handshake_info_cert_len);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Host_EraseKnownPeer(IntPtr h, byte* id_ptr, int id_len);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Host_Dial(IntPtr h, byte* id_ptr, int id_len);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Host_ConfigAbystGateway(IntPtr h, byte* config_ptr, int config_len);
    [LibraryImport(DllName)] private static extern IntPtr Host_NewAbystClient(IntPtr h);
    [LibraryImport(DllName)] private static extern void CloseAbyssClient(IntPtr h);
    [LibraryImport(DllName)] private static extern IntPtr Host_NewCollocatedHttp3Client(IntPtr h);
    [LibraryImport(DllName)] private static extern void CloseAbyssClientCollocatedHttp3Client(IntPtr h);

    [LibraryImport(DllName)] private static extern void ClosePeer(IntPtr h_peer);

    [LibraryImport(DllName)] private static extern unsafe IntPtr AbystClient_Get(IntPtr h_client, byte* peer_id_ptr, int peer_id_len, byte* path_ptr, int path_len, IntPtr* result_handle_out, CompleteTaskCompletionSourceCallback waiter_callback, IntPtr waiter_callback_arg);
    [LibraryImport(DllName)] private static extern unsafe IntPtr AbystClient_Post(IntPtr h_client, IntPtr h_event, byte* peer_id_ptr, int peer_id_len, byte* path_ptr, int path_len, byte* content_type_ptr, int content_type_len, byte* body_ptr, int body_len, IntPtr* result_handle_out);
    [LibraryImport(DllName)] private static extern unsafe IntPtr AbystClient_Head(IntPtr h_client, IntPtr h_event, byte* peer_id_ptr, int peer_id_len, byte* path_ptr, int path_len, IntPtr* result_handle_out);

    [LibraryImport(DllName)] private static extern unsafe IntPtr Http3Client_Get(IntPtr h_client, byte* url_ptr, int url_len, IntPtr* result_handle_out, CompleteTaskCompletionSourceCallback waiter_callback, IntPtr waiter_callback_arg);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Http3Client_Post(IntPtr h_client, IntPtr h_event, byte* url_ptr, int url_len, byte* content_type_ptr, int content_type_len, byte* body_ptr, int body_len, IntPtr* result_handle_out);
    [LibraryImport(DllName)] private static extern unsafe IntPtr Http3Client_Head(IntPtr h_client, IntPtr h_event, byte* url_ptr, int url_len, IntPtr* result_handle_out);

    [LibraryImport(DllName)] private static extern void CloseHttpIOResult(IntPtr h_result);
    [LibraryImport(DllName)] private static extern unsafe IntPtr HttpIOResult_Unpack(IntPtr h_result, IntPtr* response_handle_out);
    [LibraryImport(DllName)] private static extern int HttpResponse_StatusCode(IntPtr h_response);
    [LibraryImport(DllName)] private static extern unsafe int HttpResponse_GetHeader(IntPtr h_response, byte* key_ptr, int key_len, byte* value_buf_ptr, int value_buf_len);
    [LibraryImport(DllName)] private static extern unsafe int HttpResponse_GetAllHeaders(IntPtr h_response, byte* buf_ptr, int buf_len);
    [LibraryImport(DllName)] private static extern unsafe int HttpResponse_ReadBody(IntPtr h_response, byte* buf_ptr, int buf_len);
    [LibraryImport(DllName)] private static extern void CloseHttpResponse(IntPtr h_response);

    [LibraryImport(DllName)] private static extern unsafe void World_AcceptSession(IntPtr h_host, IntPtr h_world, byte* peer_id_buf_ptr, int peer_id_buf_len, byte* peer_session_id_buf);
    [LibraryImport(DllName)] private static extern unsafe void World_DeclineSession(IntPtr h_host, IntPtr h_world, byte* peer_id_buf_ptr, int peer_id_buf_len, byte* peer_session_id_buf, int code, byte* message_buf_ptr, int message_buf_len);
    [LibraryImport(DllName)] private static extern void World_Close(IntPtr h_host, IntPtr h_world);
    [LibraryImport(DllName)] private static extern unsafe void World_ObjectAppend(IntPtr h_host, IntPtr h_world, int peer_count, IntPtr* h_peers, byte** peer_session_id_bufs, int object_count, byte** object_id_bufs, float** object_transform_bufs, byte** object_addr_bufs, int* object_addr_buf_lens);
    [LibraryImport(DllName)] private static extern unsafe void World_ObjectDelete(IntPtr h_host, IntPtr h_world, int peer_count, IntPtr* h_peers, byte** peer_session_id_bufs, int object_count, byte** object_id_bufs);

    // Event query functions
    [LibraryImport(DllName)] private static extern unsafe int Event_WorldEnter_Query(IntPtr h_event, byte* world_session_id_buf, byte* url_buf_ptr, int url_buf_len);
    [LibraryImport(DllName)] private static extern unsafe int Event_SessionRequest_Query(IntPtr h_event, byte* world_session_id_buf, byte* peer_id_buf_ptr, int peer_id_buf_len, byte* peer_session_id_buf);
    [LibraryImport(DllName)] private static extern unsafe int Event_SessionReady_Query(IntPtr h_event, byte* world_session_id_buf, byte* peer_id_buf_ptr, int peer_id_buf_len, byte* peer_session_id_buf);
    [LibraryImport(DllName)] private static extern unsafe int Event_SessionClose_Query(IntPtr h_event, byte* world_session_id_buf, byte* peer_id_buf_ptr, int peer_id_buf_len, byte* peer_session_id_buf);
    [LibraryImport(DllName)] private static extern unsafe int Event_ObjectAppend_Query(IntPtr h_event, byte* world_session_id_buf, byte* peer_id_buf_ptr, int peer_id_buf_len, byte* peer_session_id_buf, int* object_count_out);
    [LibraryImport(DllName)] private static extern unsafe int Event_ObjectAppend_QueryObjectAddrLength(IntPtr h_event, int* object_addr_length_buf);
    [LibraryImport(DllName)] private static extern unsafe int Event_ObjectAppend_GetObjects(IntPtr h_event, byte** object_id_bufs, float** object_transform_bufs, byte** object_addr_bufs, int* object_addr_buf_lens);
    [LibraryImport(DllName)] private static extern unsafe int Event_ObjectDelete_Query(IntPtr h_event, byte* world_session_id_buf, byte* peer_id_buf_ptr, int peer_id_buf_len, byte* peer_session_id_buf, int* object_count_out);
    [LibraryImport(DllName)] private static extern unsafe int Event_ObjectDelete_GetObjectIDs(IntPtr h_event, byte** object_id_bufs);
    [LibraryImport(DllName)] private static extern unsafe int Event_WorldLeave_Query(IntPtr h_event, byte* world_session_id_buf, int* code_out, byte* message_buf_ptr, int message_buf_len);
    [LibraryImport(DllName)] private static extern unsafe int Event_PeerConnected_Query(IntPtr h_event, IntPtr* peer_handle_out, byte* peer_id_buf_ptr, int peer_id_buf_len);
    [LibraryImport(DllName)] private static extern unsafe int Event_PeerDisconnected_Query(IntPtr h_event, byte* peer_id_buf_ptr, int peer_id_buf_len);

    #endregion

    #region Initialization

    public static int Initialize() => Init();

    #endregion

    #region Error

    public class Error
    {
        public string Message { get; }

        public Error(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
            {
                Message = string.Empty;
                return;
            }

            unsafe
            {
                int msgLen = GetErrorBodyLength(handle);
                byte[] buf = new byte[msgLen];
                fixed (byte* bufPtr = buf)
                {
                    int len = GetErrorBody(handle, bufPtr, buf.Length);
                    if (len != buf.Length)
                    {
                        throw new InternalBufferOverflowException("fatal DLL corruption: failed to get error body");
                    }
                    Message = Encoding.UTF8.GetString(buf);
                }
                CloseError(handle);
            }
        }
    }

    #endregion

    #region Host

    public class Host : IDisposable
    {
        private IntPtr _handle;
        public string ID { get; }
        public string RootCertificate { get; }

        public bool IsValid => _handle != IntPtr.Zero;

        private Host(IntPtr handle)
        {
            _handle = handle;

            unsafe
            {
                byte[] buf = new byte[PeerIdMaxLength];
                fixed (byte* bufPtr = buf)
                {
                    int len = Host_ID(_handle, bufPtr, buf.Length);
                    ID = len > 0 ? Encoding.UTF8.GetString(buf, 0, len) : string.Empty;
                }
            }

            unsafe
            {
                byte[] buf = new byte[4096];
                fixed (byte* bufPtr = buf)
                {
                    int len = Host_RootCertificate(_handle, bufPtr, buf.Length);
                    RootCertificate = len > 0 ? Encoding.UTF8.GetString(buf, 0, len) : string.Empty;
                }
            }
        }

        public static (Host?, Error?) Create(byte[] rootKey)
        {
            unsafe
            {
                fixed (byte* keyPtr = rootKey)
                {
                    IntPtr hostHandle;
                    IntPtr errHandle = NewHost(keyPtr, rootKey.Length, &hostHandle);
                    if (errHandle != IntPtr.Zero)
                        return (null, new Error(errHandle));
                    return (new Host(hostHandle), null);
                }
            }
        }

        public Error? Bind()
        {
            IntPtr errHandle = Host_Bind(_handle);
            if (errHandle != IntPtr.Zero)
                return new Error(errHandle);
            return null;
        }

        public void Serve() => Host_Serve(_handle);

        public (dynamic? Event, Error?) WaitForEvent()
        {
            unsafe
            {
                int eventType;
                IntPtr eventHandle;
                IntPtr errHandle = Host_WaitForEvent(_handle, &eventType, &eventHandle);
                if (errHandle != IntPtr.Zero)
                    return (null, new Error(errHandle));

                dynamic? ev = (EventType)eventType switch
                {
                    EventType.WorldEnter => new EWorldEnter(eventHandle),
                    EventType.SessionRequest => new ESessionRequest(eventHandle),
                    EventType.SessionReady => new ESessionReady(eventHandle),
                    EventType.SessionClose => new ESessionClose(eventHandle),
                    EventType.ObjectAppend => new EObjectAppend(eventHandle),
                    EventType.ObjectDelete => new EObjectDelete(eventHandle),
                    EventType.WorldLeave => new EWorldLeave(eventHandle),
                    EventType.PeerConnected => new EPeerConnected(eventHandle),
                    EventType.PeerDisconnected => new EPeerDisconnected(eventHandle),
                    _ => null
                };
                return (ev, null);
            }
        }

        public (World?, Error?) OpenWorld(string worldUrl)
        {
            byte[] urlBytes = Encoding.UTF8.GetBytes(worldUrl);
            unsafe
            {
                fixed (byte* urlPtr = urlBytes)
                {
                    IntPtr worldHandle;
                    IntPtr errHandle = Host_OpenWorld(_handle, urlPtr, urlBytes.Length, &worldHandle);
                    if (errHandle != IntPtr.Zero)
                        return (null, new Error(errHandle));
                    return (new World(worldHandle, this), null);
                }
            }
        }

        public (World?, Error?) JoinWorld(Peer peer, string path)
        {
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            unsafe
            {
                fixed (byte* pathPtr = pathBytes)
                {
                    IntPtr worldHandle;
                    IntPtr errHandle = Host_JoinWorld(_handle, peer.Handle, pathPtr, pathBytes.Length, &worldHandle);
                    if (errHandle != IntPtr.Zero)
                        return (null, new Error(errHandle));
                    return (new World(worldHandle, this), null);
                }
            }
        }

        public Error? ExposeWorldForJoin(World world, string path)
        {
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            unsafe
            {
                fixed (byte* pathPtr = pathBytes)
                {
                    IntPtr errHandle = Host_ExposeWorldForJoin(_handle, world.Handle, pathPtr, pathBytes.Length);
                    if (errHandle != IntPtr.Zero)
                        return new Error(errHandle);
                    return null;
                }
            }
        }

        public void HideWorld(World world) => Host_HideWorld(_handle, world.Handle);

        public string GetLocalAddrCandidates()
        {
            unsafe
            {
                byte[] buf = new byte[4096];
                fixed (byte* bufPtr = buf)
                {
                    int len = Host_LocalAddrCandidates(_handle, bufPtr, buf.Length);
                    return len > 0 ? Encoding.UTF8.GetString(buf, 0, len) : string.Empty;
                }
            }
        }

        public string GetHandshakeKeyCertificate()
        {
            unsafe
            {
                byte[] buf = new byte[4096];
                fixed (byte* bufPtr = buf)
                {
                    int len = Host_HandshakeKeyCertificate(_handle, bufPtr, buf.Length);
                    return len > 0 ? Encoding.UTF8.GetString(buf, 0, len) : string.Empty;
                }
            }
        }

        public Error? AppendKnownPeer(byte[] rootCert, byte[] handshakeInfoCert)
        {
            unsafe
            {
                fixed (byte* rootPtr = rootCert)
                fixed (byte* hsPtr = handshakeInfoCert)
                {
                    IntPtr errHandle = Host_AppendKnownPeer(_handle, rootPtr, rootCert.Length, hsPtr, handshakeInfoCert.Length);
                    if (errHandle != IntPtr.Zero)
                        return new Error(errHandle);
                    return null;
                }
            }
        }

        public Error? EraseKnownPeer(string id)
        {
            byte[] idBytes = Encoding.UTF8.GetBytes(id);
            unsafe
            {
                fixed (byte* idPtr = idBytes)
                {
                    IntPtr errHandle = Host_EraseKnownPeer(_handle, idPtr, idBytes.Length);
                    if (errHandle != IntPtr.Zero)
                        return new Error(errHandle);
                    return null;
                }
            }
        }

        public Error? Dial(string id)
        {
            byte[] idBytes = Encoding.UTF8.GetBytes(id);
            unsafe
            {
                fixed (byte* idPtr = idBytes)
                {
                    IntPtr errHandle = Host_Dial(_handle, idPtr, idBytes.Length);
                    if (errHandle != IntPtr.Zero)
                        return new Error(errHandle);
                    return null;
                }
            }
        }

        public Error? ConfigAbystGateway(string config)
        {
            byte[] configBytes = Encoding.UTF8.GetBytes(config);
            unsafe
            {
                fixed (byte* configPtr = configBytes)
                {
                    IntPtr errHandle = Host_ConfigAbystGateway(_handle, configPtr, configBytes.Length);
                    if (errHandle != IntPtr.Zero)
                        return new Error(errHandle);
                    return null;
                }
            }
        }

        public AbystClient NewAbystClient()
        {
            IntPtr clientHandle = Host_NewAbystClient(_handle);
            return new AbystClient(clientHandle);
        }

        public Http3Client NewCollocatedHttp3Client()
        {
            IntPtr clientHandle = Host_NewCollocatedHttp3Client(_handle);
            return new Http3Client(clientHandle);
        }

        internal IntPtr Handle => _handle;

        public void Dispose()
        {
            if (_handle != IntPtr.Zero)
            {
                CloseHost(_handle);
                _handle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~Host() => Dispose();
    }

    #endregion

    #region Event Types

    public enum EventType
    {
        None = 0,
        WorldEnter = 1,
        SessionRequest = 2,
        SessionReady = 3,
        SessionClose = 4,
        ObjectAppend = 5,
        ObjectDelete = 6,
        WorldLeave = 7,
        PeerConnected = 8,
        PeerDisconnected = 9,
    }

    public class EWorldEnter
    {
        public Guid WSID { get; }
        public string URL { get; }

        public EWorldEnter(IntPtr handle) {
            unsafe
            {
                byte[] worldSessionId = new byte[16];
                byte[] urlBuf = new byte[UrlMaxLength];
                fixed (byte* wsidPtr = worldSessionId)
                fixed (byte* urlPtr = urlBuf)
                {
                    int urlLen = Event_WorldEnter_Query(handle, wsidPtr, urlPtr, urlBuf.Length);
                    if (urlLen < 0)
                        throw new InternalBufferOverflowException("Event_WorldEnter_Query");
                    WSID = new Guid(worldSessionId);
                    URL = Encoding.UTF8.GetString(urlBuf, 0, urlLen);
                }
            }
            CloseEvent(handle);
        }
    }

    public class ESessionRequest
    {
        public Guid WSID { get; }
        public Guid PeerWSID { get; }
        public string PeerID { get; }
        public ESessionRequest(IntPtr handle)
        {
            byte[] worldSessionId = new byte[16];
            byte[] peerSessionId = new byte[16];
            byte[] peerIdBuf = new byte[PeerIdMaxLength];
            unsafe
            {
                fixed (byte* wsidPtr = worldSessionId)
                fixed (byte* psidPtr = peerSessionId)
                fixed (byte* pidPtr = peerIdBuf)
                {
                    int peerIdLen = Event_SessionRequest_Query(handle, wsidPtr, pidPtr, peerIdBuf.Length, psidPtr);
                    if (peerIdLen < 0)
                        throw new InternalBufferOverflowException("Event_SessionRequest_Query");
                    WSID = new Guid(worldSessionId);
                    PeerWSID = new Guid(peerSessionId);
                    PeerID = Encoding.UTF8.GetString(peerIdBuf, 0, peerIdLen);
                }
            }
            CloseEvent(handle);
        }
    }

    public class ESessionReady
    {
        public Guid WSID
        {
            get;
        }
        public Guid PeerWSID
        {
            get;
        }
        public string PeerID
        {
            get;
        }
        public ESessionReady(IntPtr handle)
        {
            byte[] worldSessionId = new byte[16];
            byte[] peerSessionId = new byte[16];
            byte[] peerIdBuf = new byte[PeerIdMaxLength];
            unsafe
            {
                fixed (byte* wsidPtr = worldSessionId)
                fixed (byte* psidPtr = peerSessionId)
                fixed (byte* pidPtr = peerIdBuf)
                {
                    int peerIdLen = Event_SessionReady_Query(handle, wsidPtr, pidPtr, peerIdBuf.Length, psidPtr);
                    if (peerIdLen < 0)
                        throw new InternalBufferOverflowException("Event_SessionReady_Query");
                    WSID = new Guid(worldSessionId);
                    PeerWSID = new Guid(peerSessionId);
                    PeerID = Encoding.UTF8.GetString(peerIdBuf, 0, peerIdLen);
                }
            }
            CloseEvent(handle);
        }
    }

    public class ESessionClose
    {
        public Guid WSID
        {
            get;
        }
        public Guid PeerWSID
        {
            get;
        }
        public string PeerID
        {
            get;
        }
        public ESessionClose(IntPtr handle)
        {
            byte[] worldSessionId = new byte[16];
            byte[] peerSessionId = new byte[16];
            byte[] peerIdBuf = new byte[PeerIdMaxLength];
            unsafe
            {
                fixed (byte* wsidPtr = worldSessionId)
                fixed (byte* psidPtr = peerSessionId)
                fixed (byte* pidPtr = peerIdBuf)
                {
                    int peerIdLen = Event_SessionClose_Query(handle, wsidPtr, pidPtr, peerIdBuf.Length, psidPtr);
                    if (peerIdLen < 0)
                        throw new InternalBufferOverflowException("Event_SessionClose_Query");
                    WSID = new Guid(worldSessionId);
                    PeerWSID = new Guid(peerSessionId);
                    PeerID = Encoding.UTF8.GetString(peerIdBuf, 0, peerIdLen);
                }
            }
            CloseEvent(handle);
        }
    }
    public class ObjectInfo
    {
        public Guid Id { get; init; } = Guid.Empty;
        public float[] Transform { get; init; } = [];
        public string Address { get; init; } = string.Empty;
    }
    public class EObjectAppend
    {
        public Guid WSID { get; }
        public Guid PeerWSID { get; }
        public string PeerID { get; }
        public ObjectInfo[] Objects { get; }
        public EObjectAppend(IntPtr handle)
        {
            byte[] worldSessionId = new byte[16];
            byte[] peerSessionId = new byte[16];
            byte[] peerIdBuf = new byte[PeerIdMaxLength];
            int objectCount;
            unsafe
            {
                fixed (byte* wsidPtr = worldSessionId)
                fixed (byte* psidPtr = peerSessionId)
                fixed (byte* pidPtr = peerIdBuf)
                {
                    int peerIdLen = Event_ObjectAppend_Query(handle, wsidPtr, pidPtr, peerIdBuf.Length, psidPtr, &objectCount);
                    if (peerIdLen < 0)
                        throw new InternalBufferOverflowException("Event_ObjectAppend_Query");
                    WSID = new Guid(worldSessionId);
                    PeerWSID = new Guid(peerSessionId);
                    PeerID = Encoding.UTF8.GetString(peerIdBuf, 0, peerIdLen);
                    Objects = new ObjectInfo[objectCount];
                }
            }

            int[] objectAddrLen = new int[objectCount];
            int objectAddrLenTotal;
            unsafe
            {
                fixed(int* objAdrLenPtr =  objectAddrLen)
                {
                    objectAddrLenTotal = Event_ObjectAppend_QueryObjectAddrLength(handle, objAdrLenPtr);
                }
            }

            var objectIdBuffers = new byte[16 * objectCount];
            var transformBuffers = new float[7 * objectCount];
            var objectAddrBuffers = new byte[objectAddrLenTotal];
            unsafe
            {
                fixed (byte* objIdPtr = objectIdBuffers)
                fixed (float* trPtr = transformBuffers)
                fixed (byte* objAddrPtr = objectAddrBuffers)
                {
                    var objIdDp = new byte*[objectCount];
                    var trDp = new float*[objectCount];
                    var objAddrDp = new byte*[objectCount];

                    var objAddrPos = 0;
                    for (int i = 0; i < objectCount; i++)
                    {
                        objIdDp[i] = objIdPtr + (16 * i);
                        trDp[i] = trPtr + (7 * i);
                        objAddrDp[i] = objAddrPtr + objAddrPos;
                        objAddrPos += objectAddrLen[i];
                    }

                    fixed (byte** objIdDpPtr = objIdDp)
                    fixed (float** trDpPtr = trDp)
                    fixed (byte** objAddrDpPtr = objAddrDp)
                    fixed (int* objAddrLenPtr =  objectAddrLen)
                    {
                        var result = Event_ObjectAppend_GetObjects(handle, objIdDpPtr, trDpPtr, objAddrDpPtr, objAddrLenPtr);
                        if (result != 0)
                        {
                            throw new InternalBufferOverflowException("Event_ObjectAppend_GetObjects");
                        }
                    }
                }

                {
                    var objAddrPos = 0;
                    for (int i = 0; i < objectCount; i++)
                    {
                        Objects[i] = new ObjectInfo
                        {
                            Id = new Guid(new ReadOnlySpan<byte>(objectIdBuffers, i * 16, 16)),
                            Transform = transformBuffers.AsSpan(i * 7, 7).ToArray(),
                            Address = Encoding.UTF8.GetString(objectAddrBuffers, objAddrPos, objectAddrLen[i]).TrimEnd('\0'),
                        };
                        objAddrPos += objectAddrLen[i];
                    }
                }
            }
            CloseEvent(handle);
        }
    }
    public class EObjectDelete
    {
        public Guid WSID { get; }
        public Guid PeerWSID { get; }
        public string PeerID { get; }
        public Guid[] ObjectIDs { get; }
        public EObjectDelete(IntPtr handle)
        {
            byte[] worldSessionId = new byte[16];
            byte[] peerSessionId = new byte[16];
            byte[] peerIdBuf = new byte[PeerIdMaxLength];
            int objectCount;
            unsafe
            {
                fixed (byte* wsidPtr = worldSessionId)
                fixed (byte* psidPtr = peerSessionId)
                fixed (byte* pidPtr = peerIdBuf)
                {
                    int peerIdLen = Event_ObjectAppend_Query(handle, wsidPtr, pidPtr, peerIdBuf.Length, psidPtr, &objectCount);
                    if (peerIdLen < 0)
                        throw new InternalBufferOverflowException("Event_ObjectAppend_Query");
                    WSID = new Guid(worldSessionId);
                    PeerWSID = new Guid(peerSessionId);
                    PeerID = Encoding.UTF8.GetString(peerIdBuf, 0, peerIdLen);
                    ObjectIDs = new Guid[objectCount];
                }

                var objectIdBuffers = new byte[16 * objectCount];
                fixed (byte* objIdPtr = objectIdBuffers)
                {
                    var objIdDp = new byte*[objectCount];

                    for (int i = 0; i < objectCount; i++)
                    {
                        objIdDp[i] = objIdPtr + (16 * i);
                    }

                    fixed (byte** objIdDpPtr = objIdDp)
                    {
                        var result = Event_ObjectDelete_GetObjectIDs(handle, objIdDpPtr);
                        if (result != 0)
                        {
                            throw new InternalBufferOverflowException("Event_ObjectAppend_GetObjects");
                        }
                    }
                }

                for (int i = 0; i < objectCount; i++)
                {
                    ObjectIDs[i] = new Guid(new ReadOnlySpan<byte>(objectIdBuffers, i * 16, 16));
                }
            }
            CloseEvent(handle);
        }
    }

    public class EWorldLeave
    {
        public Guid WSID { get; }
        public string Message { get; }
        public int Code { get; }
        public EWorldLeave(IntPtr handle)
        {
            int code;
            byte[] worldSessionId = new byte[16];
            byte[] messageBuf = new byte[GeneralTextMaxLength];
            unsafe
            {
                fixed (byte* wsidPtr = worldSessionId)
                fixed (byte* msgPtr = messageBuf)
                {
                    int msgLen = Event_WorldLeave_Query(handle, wsidPtr, &code, msgPtr, messageBuf.Length);
                    if (msgLen < 0)
                        throw new InternalBufferOverflowException("Event_WorldLeave_Query");
                    WSID = new Guid(worldSessionId);
                    Message = Encoding.UTF8.GetString(messageBuf, 0, msgLen);
                    Code = code;
                }
            }
            CloseEvent(handle);
        }
    }

    public class EPeerConnected
    {
        public Peer Peer { get; }
        public EPeerConnected(IntPtr handle)
        {
            unsafe
            {
                byte[] peerIdBuf = new byte[PeerIdMaxLength];
                IntPtr peerHandle;
                fixed (byte* pidPtr = peerIdBuf)
                {
                    int peerIdLen = Event_PeerConnected_Query(handle, &peerHandle, pidPtr, peerIdBuf.Length);
                    if (peerIdLen < 0)
                        throw new InternalBufferOverflowException("Event_PeerConnected_Query");
                    Peer = new Peer(peerHandle, Encoding.UTF8.GetString(peerIdBuf, 0, peerIdLen));
                }
            }
            CloseEvent(handle);
        }
    }

    public class EPeerDisconnected
    {
        public string PeerID { get; }
        public EPeerDisconnected(IntPtr handle)
        {
            unsafe
            {
                byte[] peerIdBuf = new byte[PeerIdMaxLength];
                fixed (byte* pidPtr = peerIdBuf)
                {
                    int peerIdLen = Event_PeerDisconnected_Query(handle, pidPtr, peerIdBuf.Length);
                    if (peerIdLen < 0)
                        throw new InternalBufferOverflowException("Event_PeerDisconnected_Query");
                    PeerID = Encoding.UTF8.GetString(peerIdBuf, 0, peerIdLen);
                }
            }
            CloseEvent(handle);
        }
    }

    #endregion

    #region Peer

    public class Peer : IDisposable
    {
        private IntPtr _handle;
        public string ID { get; }

        internal Peer(IntPtr handle, string id)
        {
            _handle = handle;
            ID = id;
        }

        public bool IsValid => _handle != IntPtr.Zero;
        internal IntPtr Handle => _handle;

        public void Dispose()
        {
            if (_handle == IntPtr.Zero) return;
            ClosePeer(_handle);
            _handle = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        ~Peer() => Dispose();
    }

    #endregion

    #region World

    public class World : IDisposable
    {
        private IntPtr _handle;
        private readonly Host _host;

        internal World(IntPtr handle, Host host)
        {
            _handle = handle;
            _host = host;
        }

        public bool IsValid => _handle != IntPtr.Zero;
        internal IntPtr Handle => _handle;

        public void AcceptSession(string peer_id, Guid peerWSID)
        {
            var pidBytes = Encoding.UTF8.GetBytes(peer_id);
            var psidBytes = peerWSID.ToByteArray();
            unsafe
            {
                fixed (byte* pidPtr = pidBytes)
                fixed (byte* psidPtr = psidBytes)
                {
                    World_AcceptSession(_host.Handle, _handle, pidPtr, pidBytes.Length, psidPtr);
                }
            }
        }

        public void DeclineSession(Peer peer, string peer_id, Guid peerWSID, int code, string message)
        {
            var pidBytes = Encoding.UTF8.GetBytes(peer_id);
            var psidBytes = peerWSID.ToByteArray();
            byte[] msgBytes = Encoding.UTF8.GetBytes(message);
            unsafe
            {
                fixed (byte* pidPtr = pidBytes)
                fixed (byte* psidPtr = psidBytes)
                fixed (byte* msgPtr = msgBytes)
                {
                    World_DeclineSession(_host.Handle, _handle, pidPtr, pidBytes.Length, psidPtr, code, msgPtr, msgBytes.Length);
                }
            }
        }

        public void ObjectAppend((Peer, Guid)[] targets, ObjectInfo[] info)
        {
            unsafe
            {
                var peerCount = targets.Length;
                var objectCount = info.Length;

                // Prepare peer handles and session IDs
                var peerHandles = new IntPtr[peerCount];
                var peerSessionIdBytes = new byte[16 * peerCount];
                for (int i = 0; i < peerCount; i++)
                {
                    peerHandles[i] = targets[i].Item1.Handle;
                    var sessionIdBytes = targets[i].Item2.ToByteArray();
                    Array.Copy(sessionIdBytes, 0, peerSessionIdBytes, i * 16, 16);
                }

                // Prepare object data
                var objectIdBytes = new byte[16 * objectCount];
                var transformBytes = new float[7 * objectCount];
                var objectAddrBytes = new byte[objectCount][];
                var objectAddrBytesTotal = 0;
                for (int i = 0; i < objectCount; i++)
                {
                    var idBytes = info[i].Id.ToByteArray();
                    Array.Copy(idBytes, 0, objectIdBytes, i * 16, 16);

                    var transform = info[i].Transform;
                    Array.Copy(transform, 0, transformBytes, i * 7, 7);

                    var addrBytes = Encoding.UTF8.GetBytes(info[i].Address);
                    if (addrBytes.Length > UrlMaxLength)
                        throw new ArgumentException($"Object address too long: {addrBytes.Length} > {UrlMaxLength}");
                    objectAddrBytes[i] = addrBytes;
                    objectAddrBytesTotal += addrBytes.Length;
                }

                // Second iteration - concatenate address utf-8 bytes
                var objectAddrBytesCombined = new byte[objectAddrBytesTotal];
                var currentPos = 0;
                foreach (var item in objectAddrBytes)
                {
                    Array.Copy(item, 0, objectAddrBytesCombined, currentPos, item.Length);
                }

                // Pin and create pointer arrays
                fixed (IntPtr* peerPtrs = peerHandles)
                fixed (byte* sessionIdPtr = peerSessionIdBytes)
                fixed (byte* objIdPtr = objectIdBytes)
                fixed (float* trPtr = transformBytes)
                fixed (byte* objAddrPtr = objectAddrBytesCombined)
                {
                    var sessionIdDp = new byte*[peerCount];
                    var objIdDp = new byte*[objectCount];
                    var trDp = new float*[objectCount];
                    var objAddrDp = new byte*[objectCount];
                    var objAddrLenSp = new int[objectCount];

                    for (int i = 0; i < peerCount; i++)
                    {
                        sessionIdDp[i] = sessionIdPtr + (16 * i);
                    }

                    var objectAddrPos = 0;
                    for (int i = 0; i < objectCount; i++)
                    {
                        objIdDp[i] = objIdPtr + (16 * i);
                        trDp[i] = trPtr + (16 * i);
                        objAddrDp[i] = objAddrPtr + objectAddrPos;

                        var objAddrLength = objectAddrBytes[i].Length;
                        objAddrLenSp[i] = objAddrLength;
                        objectAddrPos += objAddrLength;
                    }

                    fixed (byte** sessionIdDpPtr = sessionIdDp)
                    fixed (byte** objIdDpPtr = objIdDp)
                    fixed (float** trDpPtr = trDp)
                    fixed (byte** objAddrDpPtr = objAddrDp)
                    fixed (int* objAddrLenSpPtr = objAddrLenSp)
                    {
                        World_ObjectAppend(_host.Handle, _handle, peerCount, peerPtrs, sessionIdDpPtr, 
                                         objectCount, objIdDpPtr, trDpPtr, objAddrDpPtr, objAddrLenSpPtr);
                    }
                }
            }
        }

        public void ObjectDelete((Peer, Guid)[] targets, Guid[] info)
        {
            unsafe
            {
                var peerCount = targets.Length;
                var objectCount = info.Length;

                // Prepare peer handles and session IDs
                var peerHandles = new IntPtr[peerCount];
                var peerSessionIdBytes = new byte[16 * peerCount];
                for (int i = 0; i < peerCount; i++)
                {
                    peerHandles[i] = targets[i].Item1.Handle;
                    var sessionIdBytes = targets[i].Item2.ToByteArray();
                    Array.Copy(sessionIdBytes, 0, peerSessionIdBytes, i * 16, 16);
                }

                // Prepare object IDs
                var objectIdBytes = new byte[16 * objectCount];
                for (int i = 0; i < objectCount; i++)
                {
                    var idBytes = info[i].ToByteArray();
                    Array.Copy(idBytes, 0, objectIdBytes, i * 16, 16);
                }

                // Pin and create pointer arrays
                fixed (IntPtr* peerPtrs = peerHandles)
                fixed (byte* sessionIdPtr = peerSessionIdBytes)
                fixed (byte* objIdPtr = objectIdBytes)
                {
                    var sessionIdDp = new byte*[peerCount];
                    var objIdDp = new byte*[objectCount];

                    for (int i = 0; i < peerCount; i++)
                    {
                        sessionIdDp[i] = sessionIdPtr + (16 * i);
                    }

                    for (int i = 0; i < objectCount; i++)
                    {
                        objIdDp[i] = objIdPtr + (16 * i);
                    }

                    fixed (byte** sessionIdDpPtr = sessionIdDp)
                    fixed (byte** objIdDpPtr = objIdDp)
                    {
                        World_ObjectDelete(_host.Handle, _handle, peerCount, peerPtrs, sessionIdDpPtr, 
                                        objectCount, objIdDpPtr);
                    }
                }
            }
        }
        
        public void Dispose()
        {
            if (_handle == IntPtr.Zero) return;
            World_Close(_host.Handle, _handle);
            _handle = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        ~World() => Dispose();
    }

    #endregion

    #region Synchronization Primitives

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void CompleteTaskCompletionSourceCallback(IntPtr waiter);

    internal class EventWaiter
    {
        readonly TaskCompletionSource<bool> tcs;
        GCHandle handle;
        public IntPtr HandlePtr { get; }
        public EventWaiter()
        {
            tcs = new TaskCompletionSource<bool>();
            handle = GCHandle.Alloc(tcs, GCHandleType.Normal);
            HandlePtr = GCHandle.ToIntPtr(handle);
        }
        public async Task Wait() // This must ba called, exactly once
        {
            _ = await tcs.Task;
            handle.Free();
        }
        public static void Callback(IntPtr h_tcs)
        {
            var handle = GCHandle.FromIntPtr(h_tcs);
            var tcs = (TaskCompletionSource<bool>?)handle.Target
                ?? throw new NullReferenceException("CompleteTaskCompletionSource: TaskCompletionSource is null");

            tcs.SetResult(true);
        }
    }

    #endregion


    #region AbystClient

    public class AbystClient : IDisposable
    {
        private IntPtr _handle;

        internal AbystClient(IntPtr handle) => _handle = handle;

        public bool IsValid => _handle != IntPtr.Zero;

        public async Task<(HttpResponse?, Error?)> Get(string peerId, string path)
        {
            var waiter = new EventWaiter();

            var (result, primary_error) = Get_nowait(peerId, path, waiter.HandlePtr);
            await waiter.Wait();
            if (result == null)
                return (null, primary_error);
            
            var (response, error) = result.Unpack();
            result.Dispose(); // destroy temporary HttpIOResult

            return (response, error);
        }

        private (HttpIOResult?, Error?) Get_nowait(string peerId, string path, IntPtr waiterHandle)
        {
            byte[] peerIdBytes = Encoding.UTF8.GetBytes(peerId);
            byte[] pathBytes = Encoding.UTF8.GetBytes(path);
            unsafe
            {
                fixed (byte* peerIdPtr = peerIdBytes)
                fixed (byte* pathPtr = pathBytes)
                {
                    IntPtr resultHandle;
                    IntPtr errHandle = AbystClient_Get(_handle, peerIdPtr, peerIdBytes.Length, pathPtr, pathBytes.Length, &resultHandle, EventWaiter.Callback, waiterHandle);
                    if (errHandle != IntPtr.Zero)
                        return (null, new Error(errHandle));
                    return (new HttpIOResult(resultHandle), null);
                }
            }
        }

        public void Dispose()
        {
            if (_handle == IntPtr.Zero) return;
            CloseAbyssClient(_handle);
            _handle = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        ~AbystClient() => Dispose();
    }

    #endregion

    #region Http3Client

    public class Http3Client : IDisposable
    {
        private IntPtr _handle;

        internal Http3Client(IntPtr handle) => _handle = handle;

        public bool IsValid => _handle != IntPtr.Zero;

        public async Task<(HttpResponse?, Error?)> Get(string url)
        {
            var waiter = new EventWaiter();

            var (result, primary_error) = Get_nowait(url, waiter.HandlePtr);
            await waiter.Wait();
            if (result == null)
                return (null, primary_error);

            var (response, error) = result.Unpack();
            result.Dispose(); // destroy temporary HttpIOResult

            return (response, error);
        }
        private (HttpIOResult?, Error?) Get_nowait(string url, IntPtr waiterHandle)
        {
            byte[] urlBytes = Encoding.UTF8.GetBytes(url);
            unsafe
            {
                fixed (byte* urlPtr = urlBytes)
                {
                    IntPtr resultHandle;
                    IntPtr errHandle = Http3Client_Get(_handle, urlPtr, urlBytes.Length, &resultHandle, EventWaiter.Callback, waiterHandle);
                    if (errHandle != IntPtr.Zero)
                        return (null, new Error(errHandle));
                    return (new HttpIOResult(resultHandle), null);
                }
            }
        }

        public (HttpIOResult?, Error?) Post(IntPtr hEvent, string url, string contentType, byte[] body)
        {
            byte[] urlBytes = Encoding.UTF8.GetBytes(url);
            byte[] contentTypeBytes = Encoding.UTF8.GetBytes(contentType);
            unsafe
            {
                fixed (byte* urlPtr = urlBytes)
                fixed (byte* ctPtr = contentTypeBytes)
                fixed (byte* bodyPtr = body)
                {
                    IntPtr resultHandle;
                    IntPtr errHandle = Http3Client_Post(_handle, hEvent, urlPtr, urlBytes.Length, ctPtr, contentTypeBytes.Length, bodyPtr, body.Length, &resultHandle);
                    if (errHandle != IntPtr.Zero)
                        return (null, new Error(errHandle));
                    return (new HttpIOResult(resultHandle), null);
                }
            }
        }

        public (HttpIOResult?, Error?) Head(IntPtr hEvent, string url)
        {
            byte[] urlBytes = Encoding.UTF8.GetBytes(url);
            unsafe
            {
                fixed (byte* urlPtr = urlBytes)
                {
                    IntPtr resultHandle;
                    IntPtr errHandle = Http3Client_Head(_handle, hEvent, urlPtr, urlBytes.Length, &resultHandle);
                    if (errHandle != IntPtr.Zero)
                        return (null, new Error(errHandle));
                    return (new HttpIOResult(resultHandle), null);
                }
            }
        }

        public void Dispose()
        {
            if (_handle == IntPtr.Zero) return;
            CloseAbyssClientCollocatedHttp3Client(_handle);
            _handle = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        ~Http3Client() => Dispose();
    }

    #endregion

    #region HttpIOResult

    public class HttpIOResult : IDisposable
    {
        private IntPtr _handle;

        internal HttpIOResult(IntPtr handle) => _handle = handle;

        public bool IsValid => _handle != IntPtr.Zero;

        public (HttpResponse?, Error?) Unpack()
        {
            unsafe
            {
                IntPtr responseHandle;
                IntPtr errHandle = HttpIOResult_Unpack(_handle, &responseHandle);
                if (errHandle != IntPtr.Zero)
                    return (null, new Error(errHandle));
                return (new HttpResponse(responseHandle), null);
            }
        }

        public void Dispose()
        {
            if (_handle == IntPtr.Zero) return;
            CloseHttpIOResult(_handle);
            _handle = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        ~HttpIOResult() => Dispose();
    }

    public class HttpResponse : IDisposable
    {
        private IntPtr _handle;

        internal HttpResponse(IntPtr handle) => _handle = handle;

        public bool IsValid => _handle != IntPtr.Zero;

        public int StatusCode => HttpResponse_StatusCode(_handle);

        public string? GetHeader(string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] valueBuf = new byte[1024];
            unsafe
            {
                fixed (byte* keyPtr = keyBytes)
                fixed (byte* valuePtr = valueBuf)
                {
                    int len = HttpResponse_GetHeader(_handle, keyPtr, keyBytes.Length, valuePtr, valueBuf.Length);
                    if (len < 0) return null;
                    return Encoding.UTF8.GetString(valueBuf, 0, len);
                }
            }
        }

        public string GetAllHeaders()
        {
            byte[] buf = new byte[8192];
            unsafe
            {
                fixed (byte* bufPtr = buf)
                {
                    int len = HttpResponse_GetAllHeaders(_handle, bufPtr, buf.Length);
                    if (len < 0) return string.Empty;
                    return Encoding.UTF8.GetString(buf, 0, len);
                }
            }
        }

        public int ReadBody(byte[] buffer)
        {
            unsafe
            {
                fixed (byte* bufPtr = buffer)
                {
                    return HttpResponse_ReadBody(_handle, bufPtr, buffer.Length);
                }
            }
        }

        public byte[] ReadAllBody()
        {
            List<byte> allBytes = [];
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = ReadBody(buffer)) > 0)
            {
                for (int i = 0; i < bytesRead; i++)
                    allBytes.Add(buffer[i]);
            }
            return [.. allBytes];
        }

        public void Dispose()
        {
            if (_handle == IntPtr.Zero) return;
            CloseHttpResponse(_handle);
            _handle = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        ~HttpResponse() => Dispose();
    }

    #endregion
}
