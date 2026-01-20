using System.Runtime.CompilerServices;
using System.Threading;

namespace GlobalDependency
{
    public static class UnityThreadChecker
    {
        private static int _main_thread_id = -1;
        public static void Init()
        {
            _main_thread_id = Thread.CurrentThread.ManagedThreadId;
        }
        public static void Clear()
        {
            _main_thread_id = -1;
        }
        public static void Check(
            [CallerMemberName] string memberName = "",
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0)
        {
            if (Thread.CurrentThread.ManagedThreadId != _main_thread_id)
                RuntimeCout.Print($"This must be in unity main thread, but it isn't: {memberName} in {filePath}:{lineNumber}");
        }
    }
}