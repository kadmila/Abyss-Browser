using AbyssCLI.ABI;
using ClientUtils;
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
        private readonly ClientUtils.ClientUtils clientUtils = ClientUtils.ClientUtils.GetInstance();
        private readonly SceneManager sceneManager = new();

        private readonly EngineCom.EngineCom _engine_com;
        private readonly Thread _rx_thread;
        private readonly Thread _rx_stderr_thread;

        public readonly ConcurrentQueue<Action> RenderingActionQueue = new();

        private readonly StaticResourceLoader _static_resource_loader = new();

        public UIActionWriter Tx => _engine_com.Tx;

        public Host()
        {
            clientUtils.AssertIsUnityThread();

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

            Init();
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
#if UNITY_EDITOR
                    LogRequest(render_action);
#endif
                    InterpretRequest(render_action);
                }
                catch (Exception ex)
                {
                    clientUtils.UIManager.AppendConsole("fatal:::RxLoop throwed an error: " + ex.ToString());
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
                    clientUtils.UIManager.AppendConsole(err_msg);
                }
                catch
                {
                    clientUtils.UIManager.AppendConsole("===== stderr closed =====");
                    return;
                }
            }
        }
        public void Dispose()
        {
            _engine_com.Stop();

            _rx_thread.Join();
            _rx_stderr_thread.Join();
            _engine_com.Dispose();

            RenderingActionQueue.Clear();
            _static_resource_loader.Dispose();
        }
    }
}