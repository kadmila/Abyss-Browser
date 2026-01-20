using AbyssCLI.ABI;
using System;
using System.IO;
using UnityEngine;

namespace EngineCom
{
    public class EngineCom : IDisposable
    {
        
        private readonly System.Diagnostics.Process _host_proc;
        public UIActionWriter Tx { get; private set; }
        public RenderActionReader Rx { get; private set; }
        public StreamReader StdErr { get; private set; }

        const string EngineBinaryPath = ".\\AbyssCLI\\AbyssCLI.exe";

        public EngineCom(string root_key_path) //may throw exception.
        {
            byte[] root_key = System.IO.File.ReadAllBytes(root_key_path);
            _host_proc = new System.Diagnostics.Process();
            _host_proc.StartInfo.FileName = EngineBinaryPath;
            _host_proc.StartInfo.UseShellExecute = false;
            _host_proc.StartInfo.CreateNoWindow = true;
            _host_proc.StartInfo.RedirectStandardInput = true;
            _host_proc.StartInfo.RedirectStandardOutput = true;
            _host_proc.StartInfo.RedirectStandardError = true;
            _ = _host_proc.Start();

            Tx = new(_host_proc.StandardInput.BaseStream)
            {
                AutoFlush = true
            };
            Rx = new(_host_proc.StandardOutput.BaseStream);
            StdErr = _host_proc.StandardError;

            Tx.Init(
                Google.Protobuf.ByteString.CopyFrom(root_key), 
                Path.GetFileNameWithoutExtension(root_key_path)
            );
        }
        public void Stop()
        {
            if (!_host_proc.HasExited)
            {
                _host_proc.Kill();
                _host_proc.WaitForExit();
            }
        }

        private bool _disposed;
        public void Dispose()
        {
            if (_disposed) return;

            _host_proc.Dispose();
            Tx = null;
            Rx = null;
            StdErr.Dispose();
            StdErr = null;

            _disposed = true;
        }
    }
}