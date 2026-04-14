namespace AbyssCLI.Tool;

public class RcTaskCompletionSource<TResult>() : IDisposable where TResult : IDisposable
{
    /// <summary>
    /// TryGetReference to get reference.
    /// While References are not disposed, you will not be able to close resource.
    /// After TryClose succeedes, this may be disposed.
    /// Before disposing, result must be setted. Call TrySetResult().
    /// </summary>
    private readonly TaskCompletionSource<TResult> _inner = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _count = 0; //if this is -1, it is closed.
    private DateTime _last_access = DateTime.Now;
    public bool TryGetLastAccess(out DateTime last_access) //returns false if occupied
    {
        if (_count > 0)
        {
            last_access = default;
            return false;
        }
        last_access = _last_access;
        return true;
    }
    public bool TryGetReference(out TaskCompletionReference<TResult>? result)
    {
        while (true)
        {
            int prev = _count;
            if (_count == -1)
            {
                result = null;
                return false;
            }
            if (Interlocked.CompareExchange(ref _count, prev + 1, prev) == prev)
            {
                result = new(_inner.Task, () =>
                {
                    while (true)
                    {
                        int dec_prev = _count;
                        if (dec_prev == 1)
                        {
                            _last_access = DateTime.Now;
                            Thread.MemoryBarrier();
                        }
                        if (Interlocked.CompareExchange(ref _count, dec_prev - 1, dec_prev) == dec_prev)
                        {
                            return;
                        }
                    }
                });
                return true;
            }
        }
    }
    public bool TrySetResult(TResult result) => _inner.TrySetResult(result);
    //no exception or cancellation. Every failed request must set well-formed fallback
    public bool TryClose()
    {
        if (Interlocked.CompareExchange(ref _count, -1, 0) != 0)
        {
            return false;
        }
        return true;
    }
    private bool _disposed = false;
    public void Dispose() //not thread safe
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
    protected virtual async void Dispose(bool disposing) //this will hang until resource is provided (or canceled/throwed)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                if (_count > -1)
                {
                    throw new InvalidOperationException(); // not closed.
                }
                TResult result;
                try
                {
                    result = await _inner.Task;
                    result.Dispose();
                }
                catch { }
            }
            _disposed = true;
        }
    }
    ~RcTaskCompletionSource() //if dispose not called, we cause resource leak.
    {
        Dispose(disposing: false);
    }
}

public class TaskCompletionReference<TResult>(Task<TResult> inner, Action free) : IDisposable where TResult : IDisposable
{
    public Task<TResult> Task { get; private set; } = inner;
    private readonly Action _free = free; // origin reference clearer.
    private bool _disposed = false;
    public void Dispose() //not thread safe
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                _free.Invoke();
            }
            _disposed = true;
        }
    }
    ~TaskCompletionReference() //if dispose not called, we cause resource leak.
    {
        Dispose(disposing: false);
    }
}
