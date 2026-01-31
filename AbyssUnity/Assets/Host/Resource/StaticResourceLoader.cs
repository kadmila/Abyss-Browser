using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;

namespace Host
{
    public class StaticResourceLoader : IDisposable
    {
        private readonly ConcurrentDictionary<int, StaticResource> _resources = new();
        private readonly CancellationTokenSource _cts = new();
        public Task _main_loop;
        public Action<Action> SynchronizedActionEnqueueCallback;
        //public Action<StaticResource> OnResourceFinialize;
        private bool _started = false;
        public void Start() { _main_loop = Task.Run(MainLoop); }
        private async Task MainLoop()
        {
            if (_started) throw new InvalidOperationException("Start() called multiple times");
            _started = true;

            var token = _cts.Token;
            while (!token.IsCancellationRequested)
            {
                var entries = _resources.ToArray();
                foreach (var entry in entries)
                {
                    if (entry.Value.IsMarkedDispose)
                    {
                        if (entry.Value.IsCheckedOut)
                            continue;

                        _ = _resources.Remove(entry.Key, out var resource);
                        SynchronizedActionEnqueueCallback(resource.Dispose);
                        entry.Value.IsCheckedOut = true;
                        continue;
                    }

                    var current_size = entry.Value.CurrentSize;
                    if (entry.Value.PrevSize != current_size)
                    {
                        entry.Value.PrevSize = current_size;
                        SynchronizedActionEnqueueCallback(entry.Value.UpdateMMFRead);
                    }
                }
                await Task.Delay(50, token); //TODO: adaptive
            }
        }

        public void Add(int resource_id, StaticResource resource)
        {
            if (!_resources.TryAdd(resource_id, resource))
                throw new InvalidOperationException("duplicate resource id");
        }
        public bool TryGetValue(int resource_id, out StaticResource resource) =>
            _resources.TryGetValue(resource_id, out resource);
        public void RequestRemove(int resource_id)
        {
            if (!_resources.TryGetValue(resource_id, out var resource))
                return;
            resource.IsMarkedDispose = true;
        }

        private bool _disposed = false;
        /// <summary>
        /// It must be guaranteed that after Dispose() is called,
        /// no thread references any instance of StaticResource. (from req A)
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;

            _cts.Cancel();
            if (_started)
            {
                try
                {
                    _main_loop.Wait();
                }
                catch (Exception ex)
                {
                    Debug.LogError("StaticResourceLoader Disposed: " + ex.ToString());
                }
            }

            _cts.Dispose();
            SynchronizedActionEnqueueCallback = null;

            foreach (var resource in _resources.Values)
                resource.Dispose();

            _disposed = true;
        }
    }
    /// <summary>
    /// Static Resource Entry.
    /// This frees mmap file after completion. TODO: Tell engine to close file.
    /// ConsumedSize and PrevSize must only be used in corresponding purposes.
    /// While Update() is queued to be executed on unity main thread, 
    /// Dispose() must be carefully scheduled.
    /// </summary>
    public abstract class StaticResource : IDisposable
    {
        protected readonly MemoryMappedFile _mmf;
        protected readonly MemoryMappedViewAccessor _accessor;
        public readonly int Size;
        public StaticResource(string file_name)
        {
            _mmf = MemoryMappedFile.OpenExisting(file_name);
            _accessor = _mmf.CreateViewAccessor();

            _accessor.Read(0, out Size);
        }
        protected int ConsumedSize = 0; // used by derived class.
        public int PrevSize = 0; // used by ResourceLoader
        public int CurrentSize
        {
            get
            {
                _accessor.Read(4, out int result);
                return result;
            }
        }
        protected bool IsLoading
        {
            get
            {
                _accessor.Read(8, out bool result);
                return result;
            }
        }

        //only used by StaticResourceLoader
        public bool IsMarkedDispose = false;
        public bool IsCheckedOut = false;

        /// <summary>
        /// Init() and Update() are executed on unity main thread.
        /// This is only called from the RenderingActionQueue consumer.
        /// Init() should be guaranteed to be executed before any calls
        /// that references the resources are executed.
        /// </summary>
        public abstract void Init();
        public abstract void UpdateMMFRead();

        private bool _disposed = false;
        /// <summary>
        /// It must be guaranteed that after Dispose() is called,
        /// no thread accesses this object. (req A)
        /// </summary>
        public virtual void Dispose()
        {
            if (_disposed) return;

            _mmf.Dispose();
            _accessor.Dispose();

            _disposed = true;
        }
    }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct StaticResourceHeader
    {
        public int TotalSize; // 4 byte header for total size
        public int CurrentSize; // 4 byte header for current size
        public bool IsLoading;
    }
}
