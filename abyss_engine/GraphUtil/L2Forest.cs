using AbyssCLI.GraphUtil;
using System.ComponentModel;
using System.Text;

namespace AbyssCLI.GraphUtil;
public class L2TreeNode: IDisposable
{
    public L2TreeNode? L1Parent
    {
        get; private set;
    }
    public readonly List<L2TreeNode> L1Children;

    public L2TreeNode? L2Parent;
    public readonly List<L2TreeNode> L2Children;
    public int L2RefCount;
    private bool disposed;

    public L2TreeNode()
    {
        L1Children = [];
        L2Children = [];
    }
    // Find returns target node, whether found, and the nearest ancestor that is lifted. It may return self.
    public (L2TreeNode?, bool, L2TreeNode?) Find(Predicate<L2TreeNode> cond)
    {
        return Find(cond, this);
    }
    private (L2TreeNode?, bool, L2TreeNode?) Find(Predicate<L2TreeNode> cond, L2TreeNode l2_ancestor)
    {
        if (L2RefCount > 0)
            l2_ancestor = this;

        if (cond(this))
            return (this, true, l2_ancestor);

        foreach (var child in L1Children)
        {
            var found = child.Find(cond, l2_ancestor);
            if (found.Item2)
                return found;
        }
        return (null, false, null);
    }
    public (L2TreeNode?, bool) FindChild(Predicate<L2TreeNode> cond)
    {
        foreach (var child in L1Children)
        {
            if (cond(child))
                return (child, true);
        }
        return (null, false);
    }
    public bool IsL1AncestorOf(L2TreeNode node, L2TreeNode limit)
    {
        var current = node;
        while (current != null && current != limit)
        {
            if (current == this)
                return true;
            current = current.L1Parent;
        }
        return false;
    }

    protected virtual void OnAddChild(L2TreeNode child) {}
    protected virtual void OnInsertChild(L2TreeNode child, int index) {}
    protected virtual void OnIsolate() {}

    // Direct L1 Tree access is only allowed before initializing the Forest.
    // This does not provide cycle detection. The caller must ensure the tree structure is valid.
    public void L1AddChild(L2TreeNode child)
    {
        if (child.L1Parent != null)
            throw new InvalidOperationException("Child already has a parent");

        child.L1Parent = this;
        L1Children.Add(child);
        OnAddChild(child);
    }
    public void L1InsertChild(L2TreeNode child, int index)
    {
        if (child.L1Parent != null)
            throw new InvalidOperationException("Child already has a parent");

        child.L1Parent = this;
        L1Children.Insert(index, child);
        OnInsertChild(child, index);
    }
    public void L1Isolate()
    {
        if (L1Parent == null)
            return;

        _ = L1Parent.L1Children.Remove(this);
        L1Parent = null;
        OnIsolate();
    }

#pragma warning disable CA1816 // Dispose 메서드는 SuppressFinalize를 호출해야 합니다.
    protected virtual void Dispose(bool is_root)
    {
        if (disposed)
        {
            Client.Client.Cerr.WriteLine("L2TreeNode disposed multiple times. This may indicate AmlElement lifecycle management failure.");
            return;
        }
        disposed = true;

        if (L2RefCount > 0)
        {
            Client.Client.Cerr.WriteLine("L2TreeNode disposed while still being referenced. This may indicate AmlElement lifecycle management failure.");
            return;
        }

        foreach (var child in L1Children)
        {
            child.Dispose(is_root: false);
        }
        GC.SuppressFinalize(this);
    }
    // **Important** an L2TreeNode must be isolated before being disposed.
    public void Dispose()
    {
        Dispose(is_root: true);
    }
#pragma warning restore CA1816 // Dispose 메서드는 SuppressFinalize를 호출해야 합니다.

    ~L2TreeNode()
    {
        Client.Client.Cerr.WriteLine("L2TreeNode finalized without being disposed. This is a fatal bug.");
    }
}

public class L2TreeNodeRef: IDisposable
{
    private readonly L2Forest forest;
    public readonly L2TreeNode Origin;
    private bool disposed;

    // L2TreeNodeRef should not be manually constructed.
    public L2TreeNodeRef(L2Forest forest, L2TreeNode origin)
    {
        this.forest = forest;
        Origin = origin;
        origin.L2RefCount++;
    }
    public L2TreeNodeRef? Find(Predicate<L2TreeNode> cond)
    {
        var (result, ok, l2Ancestor) = Origin.Find(cond);
        if (!ok)
            return null;

        if (result!.L2RefCount == 0) // Lift node if there were no previous reference.
            Lift(l2Ancestor!, result!);

        return new L2TreeNodeRef(forest, result!);
    }
    public L2TreeNodeRef? FindChild(Predicate<L2TreeNode> cond)
    {
        var (result, ok) = Origin.FindChild(cond);
        if (!ok)
            return null;

        if (result!.L2RefCount == 0)
            Lift(result!, Origin);

        return new L2TreeNodeRef(forest, result!);
    }
    public void AddChild(L2TreeNodeRef nodeRef)
    {
        if (nodeRef.Origin.L1Parent != null)
            nodeRef.Isolate();

        _ = forest.Roots.Remove(nodeRef.Origin);

        Origin.L1AddChild(nodeRef.Origin);
        
        Origin.L2Children.Add(nodeRef.Origin);
        nodeRef.Origin.L2Parent = Origin;
    }
    public void InsertChild(L2TreeNodeRef nodeRef, int index)
    {
        if (nodeRef.Origin.L1Parent != null)
            nodeRef.Isolate();

        _ = forest.Roots.Remove(nodeRef.Origin);

        Origin.L1InsertChild(nodeRef.Origin, index);
        
        Origin.L2Children.Add(nodeRef.Origin);
        nodeRef.Origin.L2Parent = Origin;
    }
    public void Isolate()
    {
        Origin.L1Isolate();
        
        _ = Origin.L2Parent?.L2Children.Remove(Origin);
        Origin.L2Parent = null;

        forest.Roots.Add(Origin);
    }

    // L2 Tree Mutation Implementation
    public static void Lift(L2TreeNode l2Parent, L2TreeNode l2Child)
    {
        _=l2Parent.L2Children.RemoveAll(l2c =>
        {
            if (l2Child.IsL1AncestorOf(l2c, l2Parent))
            {
                //in-path old children. They will be reparented to the lifted node.
                l2c.L2Parent = l2Child;
                l2Child.L2Children.Add(l2c);
                return true;
            }
            return false;
        });

        l2Parent.L2Children.Add(l2Child);
        l2Child.L2Parent = l2Parent;
    }
    public void Drop()
    {
        if (Origin.L2Parent == null)
        {
            // root. Dispose corresponding nodes.
            foreach (var l2c in Origin.L2Children)
            {
                l2c.L1Isolate();
                forest.Roots.Add(l2c);
                l2c.L2Parent = null;
            }
            _=forest.Roots.Remove(Origin);
            Origin.Dispose();
        }
        else
        {
            foreach (var l2c in Origin.L2Children)
            {
                l2c.L2Parent = Origin.L2Parent;
                Origin.L2Parent.L2Children.Add(l2c);
            }
            _ = Origin.L2Parent.L2Children.Remove(Origin);
            Origin.L2Parent = null;
            Origin.L2Children.Clear();
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            Client.Client.Cerr.WriteLine("L2TreeNodeRef disposed multiple times. This may indicate AmlElement lifecycle management failure.");
            return;
        }
        disposed = true;

        Origin.L2RefCount--;
        if (Origin.L2RefCount == 0)
        {
            // L2 Tree Mutation
            Drop();
        }

        GC.SuppressFinalize(this);
    }
    ~L2TreeNodeRef()
    {
        Client.Client.Cerr.WriteLine("L2TreeNodeRef finalized without being disposed. This is a fatal bug.");
    }
}

public class L2Forest
{
    public readonly List<L2TreeNode> Roots = []; // L2 roots
    public L2TreeNodeRef Insert(L2TreeNode node)
    {
        Roots.Add(node);
        return new L2TreeNodeRef(this, node);
    }

    /// debug dump
    public string DumpL1WithL2(Func<L2TreeNode, string>? label = null)
    {
        var sb = new StringBuilder();
        label ??= n => n.GetHashCode().ToString();

        _ = sb.AppendLine("=== L1 DFS (with L2 info) ===");

        foreach (var root in Roots)
        {
            DumpL1Node(root, sb, label, indent: 0);
        }

        return sb.ToString();
    }
    private static void DumpL1Node(
        L2TreeNode node,
        StringBuilder sb,
        Func<L2TreeNode, string> label,
        int indent)
    {
        _ = sb.Append(' ', indent * 2);

        // Node label
        _ = sb.Append(label(node));

        // Inline L2 info
        if (node.L2RefCount > 0 || node.L2Parent != null || node.L2Children.Count > 0)
        {
            _ = sb.Append(" {");

            _ = sb.Append($"ref={node.L2RefCount}");

            if (node.L2Parent != null)
            {
                _ = sb.Append(", p=");
                _ = sb.Append(label(node.L2Parent));
            }

            if (node.L2Children.Count > 0)
            {
                _ = sb.Append(", c=[");
                for (int i = 0; i < node.L2Children.Count; i++)
                {
                    if (i > 0)
                        _ = sb.Append(", ");
                    _ = sb.Append(label(node.L2Children[i]));
                }
                _ = sb.Append(']');
            }

            _ = sb.Append('}');
        }

        _ = sb.AppendLine();

        // L1 DFS
        foreach (var child in node.L1Children)
        {
            DumpL1Node(child, sb, label, indent + 1);
        }
    }
    public static void TestDrive()
    {
        L2Forest forest = new();
        var refA = forest.Insert(new L2TreeNode());
        var refB = forest.Insert(new L2TreeNode());
        var refC = forest.Insert(new L2TreeNode());
        var refD = forest.Insert(new L2TreeNode());
        var refE = forest.Insert(new L2TreeNode());
        Console.WriteLine(forest.DumpL1WithL2());

        refA.AddChild(refB);
        refB.AddChild(refC);
        refB.AddChild(refD);
        Console.WriteLine(forest.DumpL1WithL2());

        refB.Dispose();
        Console.WriteLine(forest.DumpL1WithL2());

        refA.AddChild(refE);
        Console.WriteLine(forest.DumpL1WithL2());

        refA.Dispose();
        Console.WriteLine(forest.DumpL1WithL2());
    }
}
