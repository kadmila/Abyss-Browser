using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AbyssCLI.Client;
public class Member : IDisposable
{
    public string PeerId;
    public Guid WSID;
    public readonly Dictionary<Guid, HL.Item> RemoteItems = []; //UUID - item

    public Member(string peerId, Guid wsid)
    {
        PeerId = peerId;
        WSID = wsid;
    }

    public void Dispose()
    {
        foreach (var item in RemoteItems.Values)
            item.Dispose();

        GC.SuppressFinalize(this);
    }
    ~Member() => Dispose();
}