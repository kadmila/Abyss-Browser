using AbyssCLI.Tool;

namespace AbyssCLI.Abyst;

public class AbystRequestMessage
{
    public AbystRequestMessage(HttpMethod method, string path)
    {
        _ = AbyssURLParser.TryParse(path, out AbyssURL abyss_url);
        AbyssURL = abyss_url;
    }

    public readonly AbyssURL AbyssURL;
}
