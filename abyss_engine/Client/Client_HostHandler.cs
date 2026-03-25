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
            case AbyssLibB.EPeerFound e:
                Cerr.WriteLine($"Peer found: {e.PeerID}");
                continue;
            case AbyssLibB.EPeerForgot e:
                Cerr.WriteLine($"Peer forgot: {e.PeerID}");
                continue;
            default:
                break;
            }

            lock (_worldLock)
            {
                if (_mainWorld == null)
                    continue;

                switch (evnt)
                {
                case AbyssLibB.EWorldEnter e when _mainWorld.WSID == e.WSID:
                    _mainWorld.OnWorldEnter(e);
                    break;
                case AbyssLibB.ESessionReady e when _mainWorld.WSID == e.WSID:
                    _mainWorld.OnMemberReady(e);
                    break;
                case AbyssLibB.EObjectAppend e when _mainWorld.WSID == e.WSID:
                    _mainWorld.OnMemberObjectAppend(e);
                    break;
                case AbyssLibB.EObjectDelete e when _mainWorld.WSID == e.WSID:
                    _mainWorld.OnMemberObjectDelete(e);
                    break;
                case AbyssLibB.ESessionClose e when _mainWorld.WSID == e.WSID:
                    _mainWorld.OnMemberLeave(e.PeerID);
                    break;
                case AbyssLibB.EWorldLeave e when _mainWorld.WSID == e.WSID:
                    _mainWorld.Dispose();
                    _mainWorld = null;
                    break;
                default:
                    break;
                }
            }

        }
    }

}
