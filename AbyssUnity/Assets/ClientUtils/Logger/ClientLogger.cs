using System;
using System.IO;
using UnityEngine;

namespace ClientUtils
{
    public static class ClientLogger
    {
        private static StreamWriter streamWriter = new StreamWriter($"log_{DateTime.Now:yyyyMMdd_HHmmss}.txt", append: true)
        {
            AutoFlush = true
        };

        public static void WriteLine(object msg)
        {
            lock (streamWriter)
            {
                streamWriter.WriteLine(msg);
            }
        }
    }
}