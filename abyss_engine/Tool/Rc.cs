namespace AbyssCLI.Tool;

public class Rc<T>(T value) where T : class
{
    private readonly T _value = value;
    private int _count = 0;
    /// <summary>
    /// DoRefExist is only meaningful when called after GetRef is guaranteed to be not called.
    /// </summary>
    public bool DoRefExist => _count != 0;

    public Ref GetRef() => new(this);
    public class Ref
    {
        private readonly Rc<T> _origin;
        public Ref(Rc<T> origin)
        {
            _origin = origin;
            _ = Interlocked.Increment(ref _origin._count);
        }
        public T Value => _origin._value;
        ~Ref()
        {
            _ = Interlocked.Decrement(ref _origin._count);
        }
    }
}
