namespace AbyssCLI.AML;
/// <summary>
/// Manual resource deallocation stack. This is not thread safe.
/// </summary>
public class Deallocator
{
    public LinkedList<DeallocEntry> stack = new();
    public void Add(DeallocEntry entry)
    {
        entry.stack_node = stack.AddLast(entry);
        entry.stack = stack;
    }
    public void FreeAll()
    {
        LinkedListNode<DeallocEntry>? entry = stack.First;
        while (entry != null)
        {
            LinkedListNode<DeallocEntry>? next = entry.Next; // Store the next node BEFORE potential removal
            entry.Value.Free();
            entry = next; // Move to the next node
        }
    }
    ~Deallocator()
    {
        if (stack.Count != 0)
        {
            Client.Client.Cerr.WriteLine("DeallocStack was not empty on finalization. This is a bug");
        }
    }
}
public class DeallocEntry
{
    public enum EDeallocType
    {
        IDisposable,
        RendererElement,
        RendererUiItem,
    }
    private readonly IDisposable element;
    public DeallocEntry(IDisposable disposable)
    {
        element = disposable;
    }
    //** this is set by DeallocStack.Add() **
    public LinkedList<DeallocEntry>? stack;
    public LinkedListNode<DeallocEntry>? stack_node;
    //////////////////////////////////////////
    public void Free() //this removes self from the dealloc stack
    {
        element.Dispose();
        stack?.Remove(stack_node!);
    }
}