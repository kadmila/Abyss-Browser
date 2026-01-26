# Abyss Browser Engine - Development Guidelines

## Project Overview

This is a .NET 8.0 C# project that implements a specialize next generation web browser engine. The project includes:
- Core browser engine (AML - Abyss Markup Language)
- Reference to external network communication library (./AbyssLibB.cs)
- JavaScript integration with ClearScript/V8
- Protocol Buffer definitions for communicating with an external rendering engine (occupies STDIN/STDOUT)

From standard I/O, the Abyss browser provides service to an external rendering engine. The expected external system is outside the coverage of this project, and we assume its existance.

## Build Command

### Full build (includes protobuf generation and external data)
```shell
powershell.exe -Command ".\build_debug.ps1"
```

### C# Build (when writing C# code only)
```shell
powershell.exe -Command "dotnet build AbyssCLI.csproj --configuration Debug"
```

## Execution

```shell
./bin/Debug/net8.0/AbyssCLI.exe
```

## Testing

There is no testing framework or automated script.
Tests must be written as a C# method in `./Test/`, with explicit `Console.WriteLine`.
```csharp
namespace AbyssCLI.Test
{
    public class Basics
    {
        public static async Task Test()
        {
            ...
        }
    }
}
```

The tests can be run by inserting the testing method call in the `Main()` function.
You can only check test progress with the console outputs, by running the executable after build.
```csharp
internal class Program
{
    public static async Task Main()
    {
        await Basics.Test();
        Environment.Exit(0);
    }
}
```

## Important Notes

### AbyssLib Migration

- We are migrating from `./AbyssLib.cs` to `./AbyssLibB.cs` for the networking library (DLL) reference.
- Nullables are enabled by default. Write modern C# codes.