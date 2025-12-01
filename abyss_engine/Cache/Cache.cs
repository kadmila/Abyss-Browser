using AbyssCLI.Abyst;
using AbyssCLI.Tool;
using System;

namespace AbyssCLI.Cache;

/// <summary>
/// In abyss browser, we cache abyst resources according to the Cache-Control header.
/// We have monolithic cache, which entry contains 1) resource 2) origin 3) response headers. (and more)
/// However, non-semantic response header fields are excluded.
/// </summary>
public class Cache(Action<HttpRequestMessage> http_requester, Action<AbystRequestMessage> abyst_requester)
{
    public static (object, string) InterpreURIText(string uri)
    {
        object requestMessage = uri switch
        {
            string s when s.StartsWith("http") => new HttpRequestMessage(HttpMethod.Get, uri),
            string s when s.StartsWith("abyst") => new AbystRequestMessage(HttpMethod.Get, uri),
            _ => throw new Exception("invalid address: " + uri),
        };
        string normalized_key = requestMessage switch
        {
            HttpRequestMessage hrm => hrm.RequestUri.ToString(),
            AbystRequestMessage arm => arm.AbyssURL.Raw,
            _ => throw new Exception("invalid address: " + uri),
        };
        return (requestMessage, normalized_key);
    }

    private readonly Action<HttpRequestMessage> _http_requester = http_requester;
    private readonly Action<AbystRequestMessage> _abyst_requester = abyst_requester;
    private readonly Dictionary<string, RcTaskCompletionSource<CachedResource>> _inner = []; //lock this.
    private readonly LinkedList<RcTaskCompletionSource<CachedResource>> _outdated_inner = [];
    public void Patch(string key, CachedResource value)
    {
        lock (_inner)
        {
            Client.Client.CerrWriteLine("Patch:" + key + "|");
            if (_inner.TryGetValue(key, out RcTaskCompletionSource<CachedResource> entry))
            {
                Client.Client.RenderWriter.DebugEnter("patch A");
                if (entry.TrySetResult(value))
                {
                    Client.Client.RenderWriter.DebugLeave("patch A");
                    return;
                }
                Client.Client.RenderWriter.DebugLeave("patch A");

                // we are updating.
                _ = _inner.Remove(key);
                _ = _outdated_inner.AddLast(entry);

                RcTaskCompletionSource<CachedResource> new_entry = new();
                _ = new_entry.TrySetResult(value);
                _inner.Add(key, new_entry);
            }
        }
    }
    public TaskCompletionReference<CachedResource> GetReference(string uri)
    {
        (object requestMessage, string normalized_key) = InterpreURIText(uri);

        lock (_inner) //not releasing
        {
            Client.Client.CerrWriteLine("GetReference: " + normalized_key + "|");
            if (_inner.TryGetValue(normalized_key, out RcTaskCompletionSource<CachedResource> entry))
            {
                _ = entry.TryGetReference(out TaskCompletionReference<CachedResource> reference);
                return reference;
            }

            RcTaskCompletionSource<CachedResource> new_entry = new();
            _ = new_entry.TryGetReference(out TaskCompletionReference<CachedResource> new_reference);
            _inner.Add(normalized_key, new_entry);
            ThreadUnsafeRequestAny(requestMessage);
            return new_reference;
        }
    }
    private void ThreadUnsafeRequestAny(object requestMessage)
    {
        switch (requestMessage)
        {
        case HttpRequestMessage hrm:
            _http_requester.Invoke(hrm);
            break;
        case AbystRequestMessage arm:
            _abyst_requester.Invoke(arm);
            break;
        default:
            throw new Exception("invalid request message type");
        }
    }
    public void Remove(string key)
    {
        lock (_inner)
        {
            if (_inner.TryGetValue(key, out RcTaskCompletionSource<CachedResource> old))
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
                _ = _inner.Remove(old, out RcTaskCompletionSource<CachedResource> value);
                value.Dispose();
            }

            for (LinkedListNode<RcTaskCompletionSource<CachedResource>> node = _outdated_inner.First; node != null;)
            {
                LinkedListNode<RcTaskCompletionSource<CachedResource>> next = node.Next;
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
