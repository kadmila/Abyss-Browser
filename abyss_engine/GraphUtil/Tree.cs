namespace AbyssCLI.GraphUtil;
internal class TreeNode
{
    public TreeNode? Parent { get; private set; }
    public List<TreeNode> Children { get; private set; } = [];
    public void AddChild(TreeNode child)
    {
        if (child.Parent != null)
            throw new InvalidOperationException("Child already has a parent");
        
        child.Parent = this;
        Children.Add(child);
    }
    public void InsertChild(TreeNode child, int index)
    {
        if (child.Parent != null)
            throw new InvalidOperationException("Child already has a parent");
        
        child.Parent = this;
        Children.Insert(index, child);
    }
    public void Isolate()
    {
        if (Parent == null)
            return;

        _ = Parent.Children.Remove(this);
        Parent = null;
    }
}
