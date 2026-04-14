using Microsoft.ClearScript;
using System.Collections.Concurrent;

namespace AbyssCLI.AML2.JavaScriptAPI;
public class Timer
{
    private readonly ConcurrentDictionary<int, System.Timers.Timer> _timers = new();
    private int _nextId = 1;
    private bool _isRunning = true;
    private readonly object _lock = new();
    public void SetTimeout(ScriptObject callback, int delayMs)
    {
        ArgumentNullException.ThrowIfNull(callback);

        int id = Interlocked.Increment(ref _nextId);

        var timer = new System.Timers.Timer(delayMs);
        timer.AutoReset = false;

        _timers[id] = timer;
        timer.Elapsed += (_, _) =>
        {
            lock (_lock)
            {
                if (!_isRunning)
                    return;
                try
                {
                    _ = callback.Invoke(false);
                }
                finally
                {
                    _ = _timers.Remove(id, out _);
                    if (_timers.TryRemove(id, out var timer))
                    {
                        timer.Dispose();
                    }
                }
            }
        };
        timer.Start();
    }
    /// <summary>
    /// This must be called before interrupting the JS engine.
    /// </summary>
    public void Interrupt()
    {
        lock (_lock)
        {
            _isRunning = false;
        }
    }

    public void Join()
    {
        foreach (var kv in _timers)
        {
            kv.Value.Dispose();
        }
        _timers.Clear();
    }
}
