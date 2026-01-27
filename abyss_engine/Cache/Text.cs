namespace AbyssCLI.Cache;

internal class Text(HttpResponseMessage http_response) : CachedResource(http_response)
{
    public Task<string> ReadAsync(CancellationToken token) =>
        _http_response.Content.ReadAsStringAsync(token);
}
