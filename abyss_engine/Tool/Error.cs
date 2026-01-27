namespace AbyssCLI.Tool;

public interface IError
{
    string Message
    {
        get;
    }
}

public class StringError(string message) : IError
{
    public string Message { get; private set; } = message;
}
