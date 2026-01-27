namespace AbyssCLI.AML;

internal static class RenderID
{
    public static int ElementId => Interlocked.Increment(ref _element_id);
    private static int _element_id = 1;

    public static int ResourceId => Interlocked.Increment(ref _resource_id);
    private static int _resource_id = 1;
}
