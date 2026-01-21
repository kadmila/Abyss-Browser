using System.Buffers;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;

namespace AbyssCLI.Cache;

/// <summary>
/// StaticResource in a IPC memory-mapped file with dynamically updating StaticResourceHeader prefix.
/// </summary>
public class StaticResource : CachedResource
{
    private const int BufferSize = 12 * 1024; //12kB
    private readonly CancellationTokenSource _cts = new();
    private readonly MemoryMappedFile _mmf;
    private readonly string _name = GetRandomName();
    private readonly MemoryMappedViewAccessor _accessor;
    private readonly Task _loading_task;
    public StaticResource(HttpResponseMessage http_response) : base(http_response)
    {
        string mime_type = http_response.Content.Headers.ContentType?.MediaType ?? string.Empty;
        int content_length = (int)(_http_response.Content.Headers.ContentLength ?? 0);
        _mmf = MemoryMappedFile.CreateNew(
            _name,
            Marshal.SizeOf<StaticResourceHeader>() + content_length
        );
        _accessor = _mmf.CreateViewAccessor();
        var header = new StaticResourceHeader
        {
            TotalSize = content_length,
            CurrentSize = 0,
            IsLoading = true
        };
        _accessor.Write(0, ref header);
        //this has to be synchronous; as following actions may refer to this resource.
        Client.Client.RenderWriter.OpenStaticResource(ResourceID, GetMimeType(mime_type), _name);
        _loading_task = LoadLoop();
    }
    private async Task LoadLoop()
    {
        CancellationToken token = _cts.Token;
        using Stream reader = await _http_response.Content.ReadAsStreamAsync(token);
        int content_length = (int)(_http_response.Content.Headers.ContentLength ?? 0);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Min(BufferSize, content_length));
        var header = new StaticResourceHeader
        {
            TotalSize = content_length,
            CurrentSize = 0,
            IsLoading = true
        };
        try
        {
            while (!token.IsCancellationRequested)
            {
                int read = await reader.ReadAsync(buffer, token);
                int next_CurrentSize = header.CurrentSize + read;
                if (next_CurrentSize > header.TotalSize)
                {
                    Client.Client.Cerr.WriteLine("Received over Content-Length. faulty server");
                    break;
                }

                _accessor.WriteArray(
                    Marshal.SizeOf<StaticResourceHeader>() + header.CurrentSize,
                    buffer,
                    0,
                    read
                );
                header.CurrentSize = next_CurrentSize;

                if (header.CurrentSize == header.TotalSize)
                    break;

                _accessor.Write(0, ref header);
            }
        }
        catch (TaskCanceledException)
        {
            //canceled.
        }
        catch (Exception ex)
        {
            Client.Client.Cerr.WriteLine("fatal:::StaticResource.LoadLoop throwed an unexpected exception: " + ex.ToString());
        }
        header.IsLoading = false;
        _accessor.Write(0, ref header);
        _accessor.Dispose();
    }
    private static readonly Random random = new();
    public static string GetRandomName()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var stringBuilder = new StringBuilder();

        for (int i = 0; i < 20; i++)
        {
            _ = stringBuilder.Append(chars[random.Next(chars.Length)]);
        }
        return stringBuilder.ToString();
    }
    private bool _disposed = false;
    public override void Dispose()
    {
        if (_disposed)
            return;

        _cts.Cancel();
        _loading_task.Wait();

        Client.Client.RenderWriter.CloseResource(ResourceID);

        _cts.Dispose();
        _accessor.Dispose();
        _mmf.Dispose();
        base.Dispose();

        _disposed = true;
        GC.SuppressFinalize(this);
    }
    public static MIME GetMimeType(string mime_type)
    {
        var marsh = string.Join("", mime_type.Split(['/','-']).Select(s => char.ToUpper(s[0]) + s[1..]));
        _ = Enum.TryParse(typeof(MIME), marsh, out var mime);
        return (mime as MIME?) ?? MIME.Invalid;
    }
    ~StaticResource() => Dispose();
}
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal struct StaticResourceHeader
{
    public int TotalSize; // 4 byte header for total size
    public int CurrentSize; // 4 byte header for current size
    public bool IsLoading;
}
