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
                Cerr.WriteLine("Host event error: " + error.Message);
                return;
            }

            switch (evnt)
            {
                case AbyssLibB.EPeerConnected e:
                    Cerr.WriteLine($"Peer connected: {e.PeerID}");
                    continue;
                case AbyssLibB.EPeerDisconnected e:
                    Cerr.WriteLine($"Peer disconnected: {e.PeerID}");
                    continue;
                default:
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
