using AbyssCLI.Tool;

namespace AbyssCLI.Cache;

/// <summary>
/// Cache operates per content, suppressing redundant network fetch.
/// Regardless of HTTP Cache-Control, this content-wide cache is absolute.
/// </summary>
public class Cache
{
    private readonly Dictionary<string, RcTaskCompletionSource<CachedResource>> _inner = []; //lock this.
    private readonly LinkedList<RcTaskCompletionSource<CachedResource>> _outdated_inner = [];
    public void Patch(string key, CachedResource value)
    {
        lock (_inner)
        {
            Client.Client.Cerr.WriteLine("Patch:" + key + "|");
            if (_inner.TryGetValue(key, out RcTaskCompletionSource<CachedResource>? entry))
            {
                if (entry.TrySetResult(value))
                {
                    return;
                }

                // we are updating.
                _ = _inner.Remove(key);
                _ = _outdated_inner.AddLast(entry);

                RcTaskCompletionSource<CachedResource> new_entry = new();
                _ = new_entry.TrySetResult(value);
                _inner.Add(key, new_entry);
            }
        }
    }
    public TaskCompletionReference<CachedResource> GetReference(string url)
    {
        lock (_inner)
        {
            Client.Client.Cerr.WriteLine($"GetReference:{url}|");
            if (_inner.TryGetValue(url, out RcTaskCompletionSource<CachedResource>? entry))
            {
                _ = entry.TryGetReference(out TaskCompletionReference<CachedResource> reference);
                return reference;
            }

            RcTaskCompletionSource<CachedResource> new_entry = new();
            _ = new_entry.TryGetReference(out TaskCompletionReference<CachedResource> new_reference);
            _inner.Add(url, new_entry);

            _= Task.Run(() => Fetch(url));
            return new_reference;
        }
    }
    private async Task Fetch(string url)
    {
        HttpResponseMessage response = url.StartsWith("abyst:") ?
            await Client.Client.AbystClient.GetAsync(url) :
            await Client.Client.HttpClient.GetAsync(url);

        string mime = response.Content.Headers.ContentType?.MediaType ?? "application/octet-stream";
        Patch(url, mime switch
        {
            "model/obj" or "image/png" => new StaticSimpleResource(response),
            "image/jpeg" => new StaticResource(response),
            _ when mime != null && mime.StartsWith("text/") => new Text(response),
            _ => new StaticSimpleResource(response),
        });
    }
    public void Remove(string key)
    {
        lock (_inner)
        {
            if (_inner.TryGetValue(key, out RcTaskCompletionSource<CachedResource>? old))
            {
                _ = _inner.Remove(key);
                _ = old.TrySetResult(CachedResource.DefaultFailedResource);
                _ = _outdated_inner.AddLast(old);
            }
        }
    }
    private static readonly TimeSpan CacheTimeout = TimeSpan.FromMinutes(3);
    public void Cleanup()
    {
        lock (_inner)
        {
            DateTime now = DateTime.Now;
            List<string> olds = [];
            foreach (KeyValuePair<string, RcTaskCompletionSource<CachedResource>> entry in _inner)
            {
                if (entry.Value.TryGetLastAccess(out DateTime last_access)
                    && now - last_access > CacheTimeout
                    && entry.Value.TryClose())
                {
                    _ = entry.Value.TrySetResult(CachedResource.DefaultFailedResource);
                    olds.Add(entry.Key);
                }
            }
            foreach (string old in olds)
            {
                _ = _inner.Remove(old, out RcTaskCompletionSource<CachedResource>? value);
                value!.Dispose();
            }

            for (LinkedListNode<RcTaskCompletionSource<CachedResource>>? node = _outdated_inner.First; node != null;)
            {
                LinkedListNode<RcTaskCompletionSource<CachedResource>>? next = node.Next;
                if (node.Value.TryClose())
                {
                    node.Value.Dispose();
                    _outdated_inner.Remove(node);
                }
                node = next;
            }
        }
    }
}
