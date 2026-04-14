using System.Collections.Concurrent;

namespace AbyssCLI.AML2;
/// <summary>
/// Dependency injection container for AML Elemenets.
/// Document-scoped dependencies (resource cache, event callback) are included here.
/// All Element constructors should receive this as an argument, and store it as a field.
/// </summary>
internal class DocumentDependencies
{
    public readonly Cache.Cache Cache;
    public readonly Action<(string, string)> JavaScriptAppendCallback;
    public DocumentDependencies(Cache.Cache cache, Action<(string, string)> jsAppendCallback)
    {
        Cache = cache;
        JavaScriptAppendCallback = jsAppendCallback;
    }
}
