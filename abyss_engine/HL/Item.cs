using AbyssCLI.Tool;
using System.Numerics;

namespace AbyssCLI.HL;

internal class Item : IDisposable
{
    public readonly string _sharer_hash;
    public readonly Guid _uuid;
    public readonly string _url;
    public readonly HL.ContentB _content;

    public Item(string sharer_hash, Guid uuid, string url, Vector3 spawn_pos, Quaternion spawn_rot)
    {
        _sharer_hash = sharer_hash;
        _uuid = uuid;
        _url = url;
        _content = new(url, new()
        {
            title = sharer_hash + ":" + uuid.ToString(),
            pos = new(spawn_pos),
            rot = new(spawn_rot),
            is_item = true,
            sharer_hash = sharer_hash,
            uuid = uuid
        });
    }
    public void Dispose()
    {
        _content.Dispose();
        GC.SuppressFinalize(this);
    }
    ~Item()
    {
        Client.Client.Cerr.WriteLine("Warning:::Item must be manually disposed. This is a bug");
        Dispose();
    }
}
