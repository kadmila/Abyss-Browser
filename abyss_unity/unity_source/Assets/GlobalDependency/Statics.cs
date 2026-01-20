#nullable enable
namespace GlobalDependency
{
    public static class Statics
    {
        public static string LocalHash = string.Empty;
        public static string LocalHostAurl = string.Empty;
        public static CommonShaderLoader ShaderLoader = null!;

        public static void Clear()
        {
            LocalHash = string.Empty;
            LocalHostAurl = string.Empty;
            ShaderLoader = null!;
        }
    }
}