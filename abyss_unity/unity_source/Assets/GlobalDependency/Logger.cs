using System;
using System.IO;
using System.Runtime.CompilerServices;

#nullable enable
namespace GlobalDependency
{
    public static class Logger
    {
        public static StreamWriter? Writer;
        public static void Init()
        {
            Writer = new StreamWriter($"log_{DateTime.Now:yyyyMMdd_HHmmss}.txt", append: true)
            {
                AutoFlush = true
            };
        }
        public static void Log(
            string message = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0,
            [CallerMemberName] string memberName = "")
        {
            string fileName = Path.GetFileName(filePath);
            Writer?.WriteLine(
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.ffffff}] {fileName}:{lineNumber} ({memberName}) {message}"
            );
        }
        public static void Clear()
        {
            Writer?.Close();
            Writer?.Dispose();
            Writer = null;
        }
    }
}