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

        public EngineCom(string root_key_path) //may throw exception.
        {
            byte[] root_key = System.IO.File.ReadAllBytes(root_key_path);

            var startinfo = new System.Diagnostics.ProcessStartInfo()
            {
                FileName = @".\AbyssCLI\AbyssCLI.exe",
                WorkingDirectory = @".\AbyssCLI",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            _host_proc = System.Diagnostics.Process.Start(startinfo);

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

            //setup abyst gateway
            //find abyst gateway config file from current directory
            var abyst_config_file_path = root_key_path[..^4] + "-abyst-gateway.config";
            string content;
            if (File.Exists(abyst_config_file_path))
            {
                content = File.ReadAllText(abyst_config_file_path);
            }
            else
            {
                File.WriteAllText(abyst_config_file_path, "{}");
                content = "{}";
            }
            Tx.ConfigAbystGateway(content);
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