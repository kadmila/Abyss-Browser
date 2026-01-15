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
        LinkedListNode<DeallocEntry> entry = stack.First;
        while (entry != null)
        {
            LinkedListNode<DeallocEntry> next = entry.Next; // Store the next node BEFORE potential removal
            entry.Value.Free();
            entry = next; // Move to the next node
        }
    }
    ~Deallocator()
    {
        if (stack.Count != 0)
        {
            Client.Client.CerrWriteLine("DeallocStack was not empty on finalization. This is a bug");
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
    private readonly EDeallocType type;
    private readonly object element;
    public DeallocEntry(IDisposable disposable)
    {
        type = EDeallocType.IDisposable;
        element = disposable;
    }
    public DeallocEntry(int element_id, EDeallocType type)
    {
        this.type = type;
        element = element_id;
    }
    //** this is set by DeallocStack.Add() **
    public LinkedList<DeallocEntry> stack;
    public LinkedListNode<DeallocEntry> stack_node;
    //////////////////////////////////////////
    public void Free() //this removes self from the dealloc stack
    {
        switch (type)
        {
        case EDeallocType.IDisposable:
            (element as IDisposable).Dispose();
            break;
        case EDeallocType.RendererElement:
            Client.Client.RenderWriter.DeleteElement((int)element);
            break;
        case EDeallocType.RendererUiItem:
            Client.Client.RenderWriter.DeleteItem((int)element);
            break;
        }
        stack?.Remove(stack_node);
    }
}