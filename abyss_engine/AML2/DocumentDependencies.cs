using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AbyssCLI.AML2;
/// <summary>
/// Dependency injection container for AML Elemenets.
/// Document-scoped dependencies (resource cache, event callback) are included here.
/// All Element constructors should receive this as an argument, and store it as a field.
/// </summary>
internal class DocumentDependencies
{
    public readonly Cache.Cache Cache;
    public readonly System.Collections.Concurrent.ConcurrentQueue<string> JavaScriptQueue;

    public DocumentDependencies(Cache.Cache cache, System.Collections.Concurrent.ConcurrentQueue<string> script_queue)
    {
        Cache = cache;
        JavaScriptQueue = script_queue;
    }
}
