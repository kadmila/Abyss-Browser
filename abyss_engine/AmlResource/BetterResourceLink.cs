using AbyssCLI.Tool;

namespace AbyssCLI.AmlResource;

public abstract class BetterResourceLink : IDisposable
{
    public readonly string Src;
    public bool IsRemovalRequired = true;
    private readonly TaskCompletionSource<byte> _tcs = new();
    private readonly Task _inner_task;
    protected Cache.CachedResource? Resource;
    public BetterResourceLink(Cache.Cache shared_cache, string src)
    {
        Src = src;
        _inner_task = Task.Run(async () =>
        {
            using TaskCompletionReference<Cache.CachedResource> cache_rsc_ref = shared_cache.GetReference(src);

            if (await Task.WhenAny(cache_rsc_ref.Task, _tcs.Task)
            is not Task<Cache.CachedResource> resource_task) //cancelled
            {
                return;
            }

            Cache.CachedResource resource = resource_task.Result;
            Resource = resource;
            Deploy();
        });
    }

    public abstract void Deploy();
    public abstract void Remove();

    private bool _disposed = false;
    public void Dispose()
    {
        if (_disposed)
            return;

        _tcs.SetResult(0);
        _inner_task.Wait(); //This is kinda unavoidable; JS main is expected to call Dispose().
        if (IsRemovalRequired && Resource != null)
            Remove();

        GC.SuppressFinalize(this);
        _disposed = true;
    }
}
