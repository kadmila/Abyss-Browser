using System;

#nullable enable
namespace GlobalDependency
{
    public static class RuntimeCout
    {
        private static Action<string>? PrintCallback;
        public static void Set(Action<string> print_callback)
        {
            PrintCallback = print_callback;
        }
        public static void Clear()
        {
            PrintCallback = null;
        }
        public static void Print(string msg)
        {
            PrintCallback?.Invoke(msg);
        }
    }
}