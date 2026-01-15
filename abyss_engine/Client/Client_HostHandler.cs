using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AbyssCLI.Client;

public static partial class Client
{
    private static void HostEventLoop()
    {
        while (true)
        {
            var (evnt, error) = Host.WaitForEvent();
            if (error != null)
            {
                CerrWriteLine("Host event error: " + error.Message);
                return;
            }

            switch (evnt)
            {
                case AbyssLibB.EPeerConnected e:
                    CerrWriteLine($"Peer connected: {e.Peer.ID}");
                    break;
                case AbyssLibB.EPeerDisconnected e:
                    CerrWriteLine($"Peer disconnected: {e.PeerID}");
                    break;
            }

            lock (_worldMoveLock)
            {
                if (_currentWorld == null)
                    continue;

                switch (evnt)
                {
                    case AbyssLibB.EWorldEnter e when _currentWorld.WSID == e.WSID:
                        _currentWorld.OnWorldEnter(e);
                        break;
                    case AbyssLibB.ESessionRequest e when _currentWorld.WSID == e.WSID:
                        _currentWorld.OnMemberRequest(e);
                        break;
                    case AbyssLibB.ESessionReady e when _currentWorld.WSID == e.WSID:
                        _currentWorld.OnMemberReady(e);
                        break;
                    case AbyssLibB.EObjectAppend e when _currentWorld.WSID == e.WSID:
                        _currentWorld.OnMemberObjectAppend(e);
                        break;
                    case AbyssLibB.EObjectDelete e when _currentWorld.WSID == e.WSID:
                        _currentWorld.OnMemberObjectDelete(e);
                        break;
                    case AbyssLibB.ESessionClose e when _currentWorld.WSID == e.WSID:
                        _currentWorld.OnMemberLeave(e.PeerID);
                        break;
                    default:
                        break;
                }
            }

        }
    }

}
