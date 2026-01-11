using AbyssCLI.Tool;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

#nullable enable
namespace AbyssCLI;

public class AbystResponseHeaderJson
{
    public int Code
    {
        get; set;
    }
    public string Status { get; set; } = "";
    public Dictionary<string, string[]> Header { get; set; } = [];
}

[Obsolete("AbyssLib is deprecated, please use AbyssLibB instead.")]
public static class AbyssLib
{
    public enum ErrorCode : int
    {
        SUCCESS = 0,
        ERROR = -1, //also EOF
        INVALID_ARGUMENTS = -2,
        BUFFER_OVERFLOW = -3,
        REMOTE_ERROR = -4,
        INVALID_HANDLE = -99,
    }
    public static string GetVersion()
    {
        unsafe
        {
            [DllImport("abyssnet.dll")]
            static extern int GetVersion(byte* buf, int buflen);

            fixed (byte* pBytes = new byte[16])
            {
                int len = GetVersion(pBytes, 16);
                if (len < 0)
                {
                    return "error";
                }
                return System.Text.Encoding.UTF8.GetString(pBytes, len);
            }
        }
    }
    public static int Init()
    {
        [DllImport("abyssnet.dll")]
        static extern int Init();
        return Init();
    }
    private static void CloseAbyssHandle(IntPtr handle)
    {
        if (handle == IntPtr.Zero)
            return;

        [DllImport("abyssnet.dll")]
        static extern void CloseAbyssHandle(IntPtr handle);
        CloseAbyssHandle(handle);
    }
    public class DLLError
    {
        public DLLError(IntPtr error_handle,
            [CallerFilePath] string file = "",
            [CallerLineNumber] int line = 0,
            [CallerMemberName] string member = "")
        {
            _error_handle = error_handle;
            if (error_handle == IntPtr.Zero)
            {
                Empty = true;
                Message = string.Empty;
                return;
            }

            Empty = false;
            string caller_info = $" (at {System.IO.Path.GetFileName(file)}:{line} in {member}())";
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int GetErrorBodyLength(IntPtr err_handle);

                [DllImport("abyssnet.dll")]
                static extern int GetErrorBody(IntPtr err_handle, byte* buf, int buflen);

                int msg_len = GetErrorBodyLength(error_handle);
                byte[] buf = new byte[msg_len];
                fixed (byte* dBytes = buf)
                {
                    int len = GetErrorBody(error_handle, dBytes, buf.Length);
                    if (len != buf.Length)
                    {
                        Message = "DLLError: fatal DLL corruption: failed to get error body" + caller_info;
                        return;
                    }

                    try
                    {
                        Message = "DLLError: " + Encoding.UTF8.GetString(buf) + caller_info;
                    }
                    catch (Exception ex)
                    {
                        Message = "DLLError: fatal DLL corruption: failed to parse error body: " + ex.Message + caller_info;
                    }
                }
            }
            ;
        }
        public DLLError(string message,
            [CallerFilePath] string file = "",
            [CallerLineNumber] int line = 0,
            [CallerMemberName] string member = "")
        {
            Empty = false;
            Message = message + $" (at {System.IO.Path.GetFileName(file)}:{line} in {member}())";
            return;
        }
        private readonly IntPtr _error_handle;
        public bool Empty;
        public readonly string Message;
        ~DLLError() => CloseAbyssHandle(_error_handle);
    }
    public static DLLError GetError()
    {
        [DllImport("abyssnet.dll")]
        static extern IntPtr PopErrorQueue();
        return new DLLError(PopErrorQueue());
    }
    public class SimplePathResolver(IntPtr _handle)
    {
        public readonly IntPtr handle = _handle;
        public DLLError TrySetMapping(string path, byte[] world_id)
        {
            byte[] path_bytes;
            try
            {
                path_bytes = Encoding.ASCII.GetBytes(path);
            }
            catch (Exception ex)
            {
                return new DLLError(ex.Message);
            }
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern void SimplePathResolver_SetMapping(IntPtr h, byte* path_ptr, int path_len, byte* world_ID, IntPtr* err_out);
                fixed (byte* path_ptr = path_bytes)
                {
                    fixed (byte* world_id_ptr = world_id)
                    {
                        IntPtr err_out = IntPtr.Zero;
                        SimplePathResolver_SetMapping(handle, path_ptr, path_bytes.Length, world_id_ptr, &err_out);
                        return new DLLError(err_out);
                    }
                }
            }
        }
        public ErrorCode DeleteMapping(string path)
        {
            byte[] path_bytes;
            try
            {
                path_bytes = Encoding.ASCII.GetBytes(path);
            }
            catch
            {
                return ErrorCode.INVALID_ARGUMENTS;
            }
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int SimplePathResolver_DeleteMapping(IntPtr h, byte* path_ptr, int path_len);
                fixed (byte* path_ptr = path_bytes)
                {
                    return (ErrorCode)SimplePathResolver_DeleteMapping(handle, path_ptr, path_bytes.Length);
                }
            }
        }
        ~SimplePathResolver() => CloseAbyssHandle(handle);
    }
    public static SimplePathResolver NewSimplePathResolver()
    {
        [DllImport("abyssnet.dll")]
        static extern IntPtr NewSimplePathResolver();
        return new SimplePathResolver(NewSimplePathResolver());
    }
    public static IntPtr NewSimpleAbystServer(string absolute_path)
    {
        byte[] path_bytes;
        try
        {
            path_bytes = Encoding.UTF8.GetBytes(absolute_path);
        }
        catch
        {
            return IntPtr.Zero;
        }

        unsafe
        {
            [DllImport("abyssnet.dll")]
            static extern IntPtr NewSimpleAbystServer(byte* path_ptr, int path_len);

            fixed (byte* path_ptr = path_bytes)
            {
                return NewSimpleAbystServer(path_ptr, path_bytes.Length);
            }
        }
    }
    public class Host
    {
        public Host(IntPtr _handle)
        {
            handle = _handle;
            if (_handle == IntPtr.Zero)
            {
                local_aurl = new AbyssURL();
                root_certificate = [];
                handshake_key_certificate = [];
                return;
            }

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int Host_GetLocalAbyssURL(IntPtr h, byte* buf, int buflen);

                [DllImport("abyssnet.dll")]
                static extern int Host_GetCertificates(IntPtr h, byte* root_cert_buf, int* root_cert_len, byte* hs_key_cert_buf, int* hs_key_cert_len);

                fixed (byte* pBytes = new byte[256])
                {
                    int len = Host_GetLocalAbyssURL(handle, pBytes, 256);
                    if (!AbyssURLParser.TryParse(len <= 0 ? "" : System.Text.Encoding.ASCII.GetString(pBytes, len), out local_aurl))
                    {
                        throw new Exception("failed to parse local host AURL");
                    }
                }

                int root_cert_len;
                int hs_key_cert_len;
                _ = Host_GetCertificates(handle, (byte*)0, &root_cert_len, (byte*)0, &hs_key_cert_len);

                root_certificate = new byte[root_cert_len];
                handshake_key_certificate = new byte[hs_key_cert_len];

                fixed (byte* rbuf = root_certificate)
                {
                    fixed (byte* kbuf = handshake_key_certificate)
                    {
                        if (Host_GetCertificates(handle, rbuf, &root_cert_len, kbuf, &hs_key_cert_len) != 0)
                        {
                            throw new Exception("failed to receive local host certificates");
                        }
                    }
                }
            }
        }
        private readonly IntPtr handle;
        public readonly AbyssURL local_aurl;
        public readonly byte[] root_certificate;
        public readonly byte[] handshake_key_certificate;
        public bool IsValid() => handle != IntPtr.Zero;
        public DLLError AppendKnownPeer(byte[] root_cert, byte[] hs_key_cert)
        {
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern void Host_AppendKnownPeer(IntPtr h, byte* root_cert_buf, int root_cert_len, byte* hs_key_cert_buf, int hs_key_cert_len, IntPtr* err_out);

                fixed (byte* rbuf = root_cert)
                {
                    fixed (byte* kbuf = hs_key_cert)
                    {
                        IntPtr err_out = IntPtr.Zero;
                        Host_AppendKnownPeer(handle, rbuf, root_cert.Length, kbuf, hs_key_cert.Length, &err_out);
                        return new DLLError(err_out);
                    }
                }
            }
        }
        public ErrorCode OpenOutboundConnection(string aurl)
        {
            byte[] aurl_bytes;
            try
            {
                aurl_bytes = Encoding.ASCII.GetBytes(aurl);
            }
            catch
            {
                return ErrorCode.INVALID_ARGUMENTS;
            }
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int Host_OpenOutboundConnection(IntPtr h, byte* aurl_ptr, int aurl_len);

                fixed (byte* aurl_ptr = aurl_bytes)
                {
                    return (ErrorCode)Host_OpenOutboundConnection(handle, aurl_ptr, aurl_bytes.Length);
                }
            }
        }
        public World OpenWorld(string url)
        {
            byte[] url_bytes;
            try
            {
                url_bytes = Encoding.ASCII.GetBytes(url);
            }
            catch
            {
                return new World(IntPtr.Zero);
            }
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern IntPtr Host_OpenWorld(IntPtr h, byte* url_ptr, int url_len);

                fixed (byte* url_ptr = url_bytes)
                {
                    nint world_handle = Host_OpenWorld(handle, url_ptr, url_bytes.Length);
                    return new World(world_handle);
                }
            }
        }
        public World JoinWorld(string aurl)
        {
            byte[] aurl_bytes;
            try
            {
                aurl_bytes = Encoding.ASCII.GetBytes(aurl);
            }
            catch
            {
                return new World(IntPtr.Zero);
            }
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern IntPtr Host_JoinWorld(IntPtr h, byte* url_ptr, int url_len, int timeout_ms);

                fixed (byte* aurl_ptr = aurl_bytes)
                {
                    nint world_handle = Host_JoinWorld(handle, aurl_ptr, aurl_bytes.Length, 1000);
                    return new World(world_handle);
                }
            }
        }
        public Tuple<AbystClient, DLLError> GetAbystClient(string peer_hash)
        {
            byte[] peer_hash_bytes;
            try
            {
                peer_hash_bytes = Encoding.ASCII.GetBytes(peer_hash);
            }
            catch (Exception ex)
            {
                return Tuple.Create(new AbystClient(IntPtr.Zero), new DLLError(ex.Message));
            }

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern IntPtr Host_GetAbystClientConnection(IntPtr h, byte* peer_hash_ptr, int peer_hash_len, int timeout_ms, IntPtr* err_out);

                fixed (byte* peer_hash_ptr = peer_hash_bytes)
                {
                    IntPtr err_out = IntPtr.Zero;
                    nint abyst_client = Host_GetAbystClientConnection(handle, peer_hash_ptr, peer_hash_bytes.Length, 10000, &err_out);
                    return Tuple.Create(new AbystClient(abyst_client), new DLLError(err_out));
                }
            }
        }
        public void WriteAndStatisticsLogFile()
        {
            [DllImport("abyssnet.dll")]
            static extern int Host_WriteANDStatisticsLogFile(IntPtr h);

            if (Host_WriteANDStatisticsLogFile(handle) != 0)
            {
                throw new Exception("Host_WriteANDStatisticsLogFile returned non-zero");
            }
        }
        ~Host() => CloseAbyssHandle(handle);
    }
    public static Host OpenAbyssHost(byte[] root_priv_key_pem, SimplePathResolver path_resolver, IntPtr abyst_server)
    {
        unsafe
        {
            [DllImport("abyssnet.dll")]
            static extern IntPtr NewHost(byte* root_priv_key_pem_ptr, int root_priv_key_pem_len, IntPtr h_path_resolver, IntPtr h_abyst_server);

            fixed (byte* key_ptr = root_priv_key_pem)
            {
                return new Host(NewHost(key_ptr, root_priv_key_pem.Length, path_resolver.handle, abyst_server));
            }
        }
    }
    public class World
    {
        public World(IntPtr _handle)
        {
            handle = _handle;

            if (handle == IntPtr.Zero)
            {
                world_id = [];
                return;
            }

            world_id = new byte[16];
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int World_GetSessionID(IntPtr h, byte* world_ID_out);

                fixed (byte* buf_ptr = world_id)
                {
                    _ = World_GetSessionID(handle, buf_ptr);
                }

                [DllImport("abyssnet.dll")]
                static extern int World_GetURL(IntPtr h, byte* buf, int buflen);
                fixed (byte* buf_ptr = new byte[2048])
                {
                    int url_len = World_GetURL(handle, buf_ptr, 2048);
                    url = url_len > 0 ? Encoding.ASCII.GetString(buf_ptr, url_len) : "";
                }
            }
        }
        private readonly IntPtr handle;
        public readonly byte[] world_id;
        public readonly string url = "";
        public bool IsValid() => handle != IntPtr.Zero;
        public dynamic WaitForEvent()
        {
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern IntPtr World_WaitEvent(IntPtr h, int* event_type_out);

                int t;
                IntPtr ret_handle = World_WaitEvent(handle, &t);

                return t switch
                {
                    1 => new WorldMemberRequest(ret_handle),
                    2 => new WorldMember(ret_handle),
                    3 => new MemberObjectAppend(ret_handle),
                    4 => new MemberObjectDelete(ret_handle),
                    5 => new WorldMemberLeave(ret_handle),
                    _ => 0,
                };
            }
        }
        public int Leave()
        {
            [DllImport("abyssnet.dll")]
            static extern int WorldLeave(IntPtr h);

            return WorldLeave(handle);
        }
        ~World() => CloseAbyssHandle(handle);
    }
    public class WorldMemberRequest
    {
        public WorldMemberRequest(IntPtr _handle)
        {
            handle = _handle;

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int WorldPeerRequest_GetHash(IntPtr h, byte* buf, int buflen);

                fixed (byte* buf = new byte[128])
                {
                    int res_len = WorldPeerRequest_GetHash(handle, buf, 128);
                    peer_hash = res_len <= 0 ? "" : Encoding.ASCII.GetString(buf, res_len);
                }
            }
        }
        private readonly IntPtr handle;
        public readonly string peer_hash;
        public ErrorCode Accept()
        {
            [DllImport("abyssnet.dll")]
            static extern int WorldPeerRequest_Accept(IntPtr h);

            return (ErrorCode)WorldPeerRequest_Accept(handle);
        }
        public ErrorCode Decline(int code, string msg)
        {
            byte[] msg_bytes;
            try
            {
                msg_bytes = Encoding.ASCII.GetBytes(msg);
            }
            catch
            {
                return ErrorCode.INVALID_ARGUMENTS;
            }

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int WorldPeerRequest_Decline(IntPtr h, int code, byte* msg, int msglen);

                fixed (byte* msg_ptr = msg_bytes)
                {
                    return (ErrorCode)WorldPeerRequest_Decline(handle, code, msg_ptr, msg_bytes.Length);
                }
            }
        }
        ~WorldMemberRequest() => CloseAbyssHandle(handle);
    }
    public class ObjectInfoFormat
    {
        public required string ID
        {
            get; set;
        }
        public required string Addr
        {
            get; set;
        }

        public required float[] Transform
        {
            get; set;
        }
    }
    private static string BytesToHex(byte[] input)
    {
        char[] result = new char[input.Length * 2];
        for (int i = 0; i < input.Length; i++)
        {
            byte b = input[i];
            result[i * 2] = (char)(b >> 4 <= 9 ? '0' + (b >> 4) : 'A' + (b >> 4) - 10);
            result[i * 2 + 1] = (char)((b & 0x0F) <= 9 ? '0' + (b & 0x0F) : 'A' + (b & 0x0F) - 10);
        }
        return new string(result);
    }
    private static int HexCharToNibble(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        else if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        else
            throw new ArgumentException($"Invalid hex character: {c}");
    }
    private static byte[] HexToBytes(string hex)
    {
        byte[] result = new byte[hex.Length / 2];

        for (int i = 0; i < result.Length; i++)
        {
            int high = HexCharToNibble(hex[i * 2]);
            int low = HexCharToNibble(hex[i * 2 + 1]);

            result[i] = (byte)((high << 4) | low);
        }

        return result;
    }
    public class WorldMember
    {
        public WorldMember(IntPtr _handle)
        {
            handle = _handle;

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int WorldPeer_GetHash(IntPtr h, byte* buf, int buflen);

                fixed (byte* buf = new byte[128])
                {
                    int len = WorldPeer_GetHash(handle, buf, 128);
                    hash = len < 0 ? "" : System.Text.Encoding.ASCII.GetString(buf, len);
                }
            }
        }
        public ErrorCode AppendObjects(Tuple<Guid, string, float[]>[] objects_info)
        {
            ObjectInfoFormat[] objinfo_marshalled = [.. objects_info.Select(x => new ObjectInfoFormat { ID = BytesToHex(x.Item1.ToByteArray()), Addr = x.Item2, Transform = x.Item3 })];
            string data = System.Text.Json.JsonSerializer.Serialize(objinfo_marshalled);
            byte[] data_bytes;
            try
            {
                data_bytes = Encoding.ASCII.GetBytes(data);
            }
            catch
            {
                return ErrorCode.INVALID_ARGUMENTS;
            }
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int WorldPeer_AppendObjects(IntPtr h, byte* json_ptr, int json_len);

                fixed (byte* data_ptr = data_bytes)
                {
                    return (ErrorCode)WorldPeer_AppendObjects(handle, data_ptr, data_bytes.Length);
                }
            }
        }
        public ErrorCode DeleteObjects(Guid[] object_ids)
        {
            IEnumerable<string> objid_marshalled = object_ids.Select(x => BytesToHex(x.ToByteArray()));
            string data = System.Text.Json.JsonSerializer.Serialize(objid_marshalled);
            byte[] data_bytes;
            try
            {
                data_bytes = Encoding.ASCII.GetBytes(data);
            }
            catch
            {
                return ErrorCode.INVALID_ARGUMENTS;
            }
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int WorldPeer_DeleteObjects(IntPtr h, byte* json_ptr, int json_len);

                fixed (byte* data_ptr = data_bytes)
                {
                    return (ErrorCode)WorldPeer_DeleteObjects(handle, data_ptr, data_bytes.Length);
                }
            }
        }
        private readonly IntPtr handle;
        public readonly string hash;
        ~WorldMember() => CloseAbyssHandle(handle);
    }
    public class MemberObjectAppend
    {
        public MemberObjectAppend(IntPtr _handle)
        {
            handle = _handle;

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int WorldPeerObjectAppend_GetHead(IntPtr h, byte* peer_hash_out, int* body_len);

                [DllImport("abyssnet.dll")]
                static extern int WorldPeerObjectAppend_GetBody(IntPtr h, byte* buf, int buflen);

                int body_len = 0;
                fixed (byte* buf = new byte[128])
                {
                    int hash_len = WorldPeerObjectAppend_GetHead(handle, buf, &body_len);
                    peer_hash = hash_len < 0 ? "" : System.Text.Encoding.ASCII.GetString(buf, hash_len);
                }
                if (body_len <= 0)
                {
                    objects = [];
                    return;
                }

                ObjectInfoFormat[]? infos;
                fixed (byte* buf = new byte[body_len])
                {
                    int res_len = WorldPeerObjectAppend_GetBody(handle, buf, body_len);
                    if (res_len != body_len)
                    {
                        objects = [];
                        return;
                    }
                    infos = System.Text.Json.JsonSerializer.Deserialize<ObjectInfoFormat[]>(System.Text.Encoding.ASCII.GetString(buf, res_len));
                }

                objects = infos == null ? [] : [.. infos.Select(x => Tuple.Create(new Guid(HexToBytes(x.ID)), x.Addr, x.Transform))];
            }
        }
        private readonly IntPtr handle;
        public readonly string peer_hash;
        public readonly Tuple<Guid, string, float[]>[] objects;
        ~MemberObjectAppend() => CloseAbyssHandle(handle);
    }
    public class MemberObjectDelete
    {
        public MemberObjectDelete(IntPtr _handle)
        {
            handle = _handle;

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int WorldPeerObjectDelete_GetHead(IntPtr h, byte* peer_hash_out, int* body_len);

                [DllImport("abyssnet.dll")]
                static extern int WorldPeerObjectDelete_GetBody(IntPtr h, byte* buf, int buflen);

                int body_len = 0;
                fixed (byte* buf = new byte[128])
                {
                    int hash_len = WorldPeerObjectDelete_GetHead(handle, buf, &body_len);
                    peer_hash = hash_len < 0 ? "" : System.Text.Encoding.ASCII.GetString(buf, hash_len);
                }
                if (body_len <= 0)
                {
                    object_ids = [];
                    return;
                }

                string[]? infos;
                fixed (byte* buf = new byte[body_len])
                {
                    int res_len = WorldPeerObjectDelete_GetBody(handle, buf, body_len);
                    if (res_len != body_len)
                    {
                        object_ids = [];
                        return;
                    }
                    infos = System.Text.Json.JsonSerializer.Deserialize<string[]>(System.Text.Encoding.ASCII.GetString(buf, res_len));
                }

                object_ids = infos == null ? [] : [.. infos.Select(x => new Guid(HexToBytes(x)))];
            }
        }
        private readonly IntPtr handle;
        public readonly string peer_hash;
        public readonly Guid[] object_ids;
        ~MemberObjectDelete() => CloseAbyssHandle(handle);
    }
    public class WorldMemberLeave
    {
        public WorldMemberLeave(IntPtr _handle)
        {
            handle = _handle;

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int WorldPeerLeave_GetHash(IntPtr h, byte* buf, int buflen);

                fixed (byte* buf = new byte[128])
                {
                    int len = WorldPeerLeave_GetHash(handle, buf, 128);
                    peer_hash = len < 0 ? "" : System.Text.Encoding.ASCII.GetString(buf, len);
                }
            }
        }
        private readonly IntPtr handle;
        public readonly string peer_hash;
        ~WorldMemberLeave() => CloseAbyssHandle(handle);
    }
    public enum AbystRequestMethod : int
    {
        GET = 0,
    }
    public class AbystClient(IntPtr _handle)
    {
        private readonly IntPtr handle = _handle;
        public bool IsValid() => handle != IntPtr.Zero;
        public AbystResponse Request(AbystRequestMethod method, string path)
        {
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern IntPtr AbystClient_Request(IntPtr h, int method, byte* path_ptr, int path_len, IntPtr* err_out);

                IntPtr err = 0;
                if (path == string.Empty)
                {
                    var result = new AbystResponse(AbystClient_Request(handle, (int)method, (byte*)0, 0, &err));
                    if (err != IntPtr.Zero)
                    {
                        throw new Exception(new DLLError(err).ToString());
                    }
                    return result;
                }

                byte[] path_bytes;
                try
                {
                    path_bytes = Encoding.ASCII.GetBytes(path);
                }
                catch
                {
                    return new AbystResponse(IntPtr.Zero);
                }

                fixed (byte* path_ptr = path_bytes)
                {
                    var result = new AbystResponse(AbystClient_Request(handle, (int)method, path_ptr, path_bytes.Length, &err));
                    if (err != IntPtr.Zero)
                    {
                        throw new Exception(new DLLError(err).ToString());
                    }
                    return result;
                }
            }
        }
        ~AbystClient() => CloseAbyssHandle(handle);
    }
    public class AbystResponse
    {
        private static readonly JsonSerializerOptions header_serialize_opt = new()
        {
            PropertyNameCaseInsensitive = true
        };
        public AbystResponse(IntPtr _handle)
        {
            handle = _handle;
            if (handle == IntPtr.Zero)
            {
                Code = 400;
                Status = "Bad Request";
                return;
            }

            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int AbyssResponse_GetHeaders(IntPtr h, byte* buf, int buflen);

                [DllImport("abyssnet.dll")]
                static extern int AbyssResponse_GetContentLength(IntPtr h);

                fixed (byte* buf = new byte[4096])
                {
                    int header_len = AbyssResponse_GetHeaders(handle, buf, 4096);
                    if (header_len < 0)
                    {
                        Code = 422;
                        Status = "Unprocessable Entity - " + header_len.ToString();
                        return;
                    }

                    try
                    {
                        string header = Encoding.ASCII.GetString(buf, header_len);

                        AbystResponseHeaderJson dynJson = JsonSerializer.Deserialize<AbystResponseHeaderJson>(header, header_serialize_opt) ?? throw new Exception();
                        Code = dynJson.Code;
                        Status = dynJson.Status;
                        Header = dynJson.Header;
                        ContentLength = AbyssResponse_GetContentLength(handle);
                        return;
                    }
                    catch
                    {
                        Code = 422;
                        Status = "my json format does not parse";
                        return;
                    }
                }
            }
        }
        private readonly IntPtr handle;
        public readonly int Code;
        public readonly string Status;
        public readonly int ContentLength;
        public readonly Dictionary<string, string[]> Header = [];
        public byte[] Body = [];
        public bool TryLoadBodyAll()
        {
            if (ContentLength == 0)
            {
                return true;
            }
            Body = new byte[ContentLength];
            unsafe
            {
                [DllImport("abyssnet.dll")]
                static extern int AbystResponse_ReadBodyAll(IntPtr h, byte* buf_ptr, int buflen);

                fixed (byte* buf = Body)
                {
                    if (AbystResponse_ReadBodyAll(handle, buf, ContentLength) != ContentLength)
                    {
                        return false;
                    }
                }
            }
            return true;
        }
        ~AbystResponse() => CloseAbyssHandle(handle);
    }
}
