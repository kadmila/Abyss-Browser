using AbyssCLI.AML;

namespace AbyssCLI.Cache;

/// <summary>
/// ***caution*** do not Dispose() CachedResource outside Cache.
/// </summary>
/// <param name="http_response"></param>
public class CachedResource(HttpResponseMessage http_response) : IDisposable
{
    public readonly int ResourceID = RenderID.ResourceId;
    public string MIMEType => _http_response.Content.Headers.ContentType?.MediaType ?? "";

    protected HttpResponseMessage _http_response = http_response;

    private bool _disposed = false;
    public virtual void Dispose() //this is called by Cache, in RcTaskCompletionSource.
    {
        if (_disposed)
            return;

        _http_response.Dispose();

        GC.SuppressFinalize(this);
        _disposed = true;
    }
    public static CachedResource DefaultFailedResource => default;
}
