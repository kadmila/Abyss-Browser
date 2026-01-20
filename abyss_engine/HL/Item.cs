using AbyssCLI.Tool;
using System.Numerics;

namespace AbyssCLI.HL;

public class Item : IDisposable
{
    public readonly string SharerHash;
    public readonly Guid UUID;
    public readonly string URL;
    public readonly HL.ContentB Content;
    public AbyssLibB.ObjectInfo SerializedObjectInfo { get; private set; }

    public Item(string sharer_hash, Guid uuid, string url, float[] transform) 
        : this( sharer_hash, uuid, url, 
                new(transform[0], transform[1], transform[2]), 
                new(transform[3], transform[4], transform[5], transform[6])) { }
    public Item(string sharer_hash, Guid uuid, string url, Vector3 spawn_pos, Quaternion spawn_rot)
    {
        SharerHash = sharer_hash;
        UUID = uuid;
        URL = url;
        Content = new(url, new()
        {
            title = sharer_hash + ":" + uuid.ToString(),
            pos = new(spawn_pos),
            rot = new(spawn_rot),
            is_item = true,
            sharer_hash = sharer_hash,
            uuid = uuid
        });
        SerializedObjectInfo = new AbyssLibB.ObjectInfo()
        {
            Address = url,
            Id = uuid,
            Transform = [spawn_pos.X, spawn_pos.Y, spawn_pos.Z, spawn_rot.X, spawn_rot.Y, spawn_rot.Z, spawn_rot.W]
        };
    }
    public void Dispose()
    {
        Content.Dispose();
        GC.SuppressFinalize(this);
    }
    ~Item()
    {
        Client.Client.Cerr.WriteLine("Warning:::Item must be manually disposed. This is a bug");
        Dispose();
    }
}
