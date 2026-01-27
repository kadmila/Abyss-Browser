using AbyssCLI.ABI;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Threading;

#nullable enable
namespace Host
{
    /// <summary>
    /// This host handles engine IO and action interpreting.
    /// Construction and Dispose() must be called from Unity main thread.
    /// It MUST be disposed.
    /// </summary>
    public partial class Host : IDisposable
    {
        private readonly GlobalDependency.RendererBase _renderer_base;
        private readonly GlobalDependency.UIBase _ui_base;
        private readonly GlobalDependency.InteractionBase _interaction_base;

        private readonly EngineCom.EngineCom _engine_com;
        private readonly Thread _rx_thread;
        private readonly Thread _rx_stderr_thread;

        public readonly ConcurrentQueue<Action> RenderingActionQueue = new();
        public readonly ConcurrentQueue<string> StderrQueue = new();

        private readonly StaticResourceLoader _static_resource_loader = new();

        public UIActionWriter Tx => _engine_com.Tx;

        public Host(
            GlobalDependency.RendererBase renderer_base,
            GlobalDependency.UIBase ui_base,
            GlobalDependency.InteractionBase interaction_base)
        {
            //prepare dependencies
            _renderer_base = renderer_base;
            _ui_base = ui_base;
            _interaction_base = interaction_base;

            //find root key from current directory
            string[] pemFiles = Directory.GetFiles(".", "*.pem", SearchOption.TopDirectoryOnly);
            if (pemFiles.Length == 0)
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "keygen.exe",
                        Arguments = "User-" + Guid.NewGuid().ToString().Substring(0, 6) + ".pem",
                        UseShellExecute = false
                    }
                };

                if (!process.Start())
                    throw new Exception("fatal:::failed to run keygen.exe");

                process.WaitForExit();

                pemFiles = Directory.GetFiles(".", "*.pem", SearchOption.TopDirectoryOnly);
                if (pemFiles.Length == 0)
                    throw new Exception("fatal:::failed to create key");
            }

            //main setup
            _engine_com = new(pemFiles[0]);
            _rx_thread = new(RxLoop);
            _rx_stderr_thread = new(RxStdErrLoop);
        }
        public void Start()
        {
            _rx_thread.Start();
            _rx_stderr_thread.Start();
            _static_resource_loader.Start();
        }

        private void RxLoop()
        {
            while(true)
            {
                try
                {
                    var render_action = _engine_com.Rx.Read();
                    LogRequest(render_action);
                    InterpretRequest(render_action);
                }
                catch (Exception ex)
                {
                    StderrQueue.Enqueue("fatal:::RxLoop throwed an error: " + ex.ToString());
                    return;
                }
            }
        }
        private void RxStdErrLoop()
        {
            while (true)
            {
                try
                {
                    var err_msg = _engine_com.StdErr.ReadLine() ?? throw new Exception("StdErr.ReadLine() returned null");
                    StderrQueue.Enqueue(err_msg);
                }
                catch
                {
                    StderrQueue.Enqueue("===== stderr closed =====");
                    return;
                }
            }
        }

        private bool _disposed;
        public void Dispose()
        {
            GlobalDependency.UnityThreadChecker.Check();

            if (_disposed) return;
            _disposed = true;

            _engine_com.Stop();

            _rx_thread.Join();
            _rx_stderr_thread.Join();
            _engine_com.Dispose();

            RenderingActionQueue.Clear();
            _static_resource_loader.Dispose();
        }
    }
}