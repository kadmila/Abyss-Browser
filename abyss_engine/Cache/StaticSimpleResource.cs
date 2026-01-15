using System.Buffers;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace AbyssCLI.Cache;

public class StaticSimpleResource : CachedResource
{
    private readonly string _mime_type;
    private readonly int _content_length;
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _accessor;
    private StaticResourceHeader _header;
    private readonly CancellationTokenSource _cts = new();
    private readonly string _name = StaticResource.GetRandomName();
    private readonly Task _loading_task;
    public StaticSimpleResource(HttpResponseMessage http_response) : base(http_response)
    {
        //content initialization
        _mime_type = _http_response.Content.Headers.ContentType?.MediaType ?? string.Empty;
        _content_length = (int)(_http_response.Content.Headers.ContentLength ?? 0);
        _mmf = MemoryMappedFile.CreateNew(
            _name,
            Marshal.SizeOf<StaticResourceHeader>() + _content_length
        );
        _accessor = _mmf.CreateViewAccessor();
        _header = new StaticResourceHeader
        {
            TotalSize = _content_length,
            CurrentSize = 0,
            IsLoading = true
        };
        _accessor.Write(0, ref _header);
        Client.Client.RenderWriter.OpenStaticResource(ResourceID, StaticResource.GetMimeType(_mime_type), _name);
        _loading_task = LoadLoop();
    }
    private async Task LoadLoop()
    {
        CancellationToken token = _cts.Token;

        using Stream reader = await _http_response.Content.ReadAsStreamAsync(token);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(_content_length);
        try
        {
            while (_header.CurrentSize < _header.TotalSize)
            {
                _header.CurrentSize += await reader.ReadAsync(buffer.AsMemory(_header.CurrentSize), token);
            }
            _accessor.WriteArray(
                Marshal.SizeOf<StaticResourceHeader>(),
                buffer,
                0,
                _header.CurrentSize
            );
            _header.IsLoading = false;
            _accessor.Write(0, ref _header);
        }
        catch (TaskCanceledException)
        {
            //canceled.
        }
        catch (Exception ex)
        {
            Client.Client.CerrWriteLine("fatal:::StaticResource.LoadLoop throwed an unexpected exception: " + ex.ToString());
        }
    }
    private bool _disposed = false;
    public override void Dispose()
    {
        if (_disposed)
            return;

        _cts.Cancel();
        _loading_task.Wait();

        Client.Client.RenderWriter.CloseResource(ResourceID);
        _accessor.Dispose();
        _mmf.Dispose();

        _cts.Dispose();
        base.Dispose();

        _disposed = true;
        GC.SuppressFinalize(this);
    }
    ~StaticSimpleResource() => Dispose();
}
