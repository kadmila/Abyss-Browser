using AbyssCLI.ABI;
using System.Net;
using static AbyssCLI.ABI.UIAction.Types;

namespace AbyssCLI.Client;

public static partial class Client
{
    // MoveWorld may return false (no-op) if the client is overloaded.
    public static bool MoveWorld(string world_url)
    {
        var message = new UIAction()
        {
            MoveWorld = new()
            {
                WorldUrl = world_url
            }
        };
        return _client_operations.Writer.TryWrite(message);
    }

    private class PublicAddressCandidate
    {
        public readonly string address;
        public DateTime last_update;
        private PublicAddressCandidate(string address)
        {
            this.address = address;
            last_update = DateTime.UtcNow;
        }
        static public bool TryNew(string address, out PublicAddressCandidate retval)
        {
            retval = new PublicAddressCandidate(address);
            if (string.IsNullOrWhiteSpace(address) || !IPEndPoint.TryParse(address, out _))
                return false;
            
            return true;
        }
    }
    static private List<PublicAddressCandidate> _public_address_candidates = [];
    static public void AddAddressCandidate(string address)
    {
        if (!PublicAddressCandidate.TryNew(address, out var entry))
        {
            Cerr.WriteLine("invalid address: " + address);
            return;
        }

        lock (_public_address_candidates)
        {
            var old_entry = _public_address_candidates.Find(x => x.address == address);
            if (old_entry != null)
            {
                old_entry.last_update = entry.last_update;
                return;
            }

            _public_address_candidates.Add(entry);
        }
    }
    static public string GetHandshakeKeyCertificate()
    {
        var local_addr_candidates = Host.GetLocalAddrCandidates(); // This goes over dll boundary, calls windows API, do dirty works.

        lock (_public_address_candidates)
        {
            var time_criteria = DateTime.UtcNow.AddMinutes(-10);
            _=_public_address_candidates.RemoveAll(x => x.last_update < time_criteria);

            var all_address_candidates = _public_address_candidates.Select(x => x.address).Concat(local_addr_candidates).ToArray();

            var update_err = Host.UpdateHandshakeInfo(all_address_candidates);
            if (update_err != null)
            {
                Cerr.WriteLine("fatal: failed to update address candidate list: " + update_err.Message);
            }
        }

        return Host.GetHandshakeKeyCertificate();
    }
}
