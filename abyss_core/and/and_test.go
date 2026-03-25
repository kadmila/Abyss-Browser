package and_test

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/infchan"
)

type DummyFetcher struct{}

func (f *DummyFetcher) Fetch(
	world *and.World,
	target and.ANDFullPeerSessionInfo,
	fwd bool,
) {
	fmt.Println(time.Now().Format("15:04:05.00000") + "| Fetch " + target.PeerID)
}

type DummyPeer struct {
	peerID string
}

func (p *DummyPeer) ID() string                          { return p.peerID }
func (p *DummyPeer) RootCertificate() string             { return "" }
func (p *DummyPeer) RootCertificateDer() []byte          { return make([]byte, 0) }
func (p *DummyPeer) HandshakeKeyCertificate() string     { return "" }
func (p *DummyPeer) HandshakeKeyCertificateDer() []byte  { return make([]byte, 0) }
func (p *DummyPeer) AddressCandidates() []netip.AddrPort { return make([]netip.AddrPort, 0) }
func (p *DummyPeer) RemoteAddr() netip.AddrPort          { return netip.AddrPort{} }
func (p *DummyPeer) Send(_ ahmp.AHMPMsgType, v any) error {
	fmt.Println(time.Now().Format("15:04:05.00000") + "| Send > " + p.peerID[:8] + " | " + v.(fmt.Stringer).String())
	return nil
}
func (p *DummyPeer) Recv() (*ahmp.AHMPMessage, error) { return nil, nil }
func (p *DummyPeer) Close() error                     { return nil }
func (p *DummyPeer) IssueTime() time.Time             { return time.Time{} }

func MakeDummyPeerSession(peerID string) and.ANDPeerSession {
	return and.ANDPeerSession{
		Peer:      &DummyPeer{peerID},
		SessionID: uuid.New(),
	}
}

func expectEvent[T any](t *testing.T, event_ch *infchan.InfiniteChan[any]) T {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	var zero T
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timeout waiting for event %T", zero)
			return zero
		case event := <-event_ch.Out:
			if typed_event, ok := event.(T); ok {
				return typed_event
			}
			t.Fatalf("unexpected event %T", event)
			return zero
		}
	}
}

func TestSJN(t *testing.T) {
	event_ch := infchan.NewInfiniteChan[any](32)
	world, err := and.NewWorld_Open(context.Background(), &DummyFetcher{}, event_ch, "local", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	expectEvent[*and.EANDWorldEnter](t, event_ch)

	A_session := MakeDummyPeerSession("H-PeerAx")
	world.JN(A_session)
	expectEvent[*and.EANDSessionReady](t, event_ch)

	B_session := MakeDummyPeerSession("H-PeerBx")
	world.JNI(A_session, and.MakeANDFullPeerSessionInfo(B_session), true)
	world.FetchReturn(B_session, true)
	world.MEM(B_session)
	expectEvent[*and.EANDSessionReady](t, event_ch)

	<-time.After(time.Second)
}

func TestCramChurn(t *testing.T) {
	event_ch := infchan.NewInfiniteChan[any](32)
	world, err := and.NewWorld_Open(context.Background(), &DummyFetcher{}, event_ch, "local", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	expectEvent[*and.EANDWorldEnter](t, event_ch)

	N := 10
	sessions := make([]and.ANDPeerSession, 0, N)
	for i := range N {
		sessions = append(sessions, MakeDummyPeerSession("H-"+strconv.Itoa(i)+"xxxxxx"))
	}
	for _, session := range sessions {
		world.JN(session)
	}
	for range N {
		expectEvent[*and.EANDSessionReady](t, event_ch)
	}

	<-time.After(time.Second)
}

func TestCramChurnJoin(t *testing.T) {
	target_session := MakeDummyPeerSession("H-target")

	event_ch := infchan.NewInfiniteChan[any](32)
	world, err := and.NewWorld_Join(context.Background(), &DummyFetcher{}, event_ch, "local", target_session.Peer, "/")
	if err != nil {
		t.Fatal(err)
	}
	world.JOK(target_session, "example.com", make([]and.ANDFullPeerSessionInfo, 0))
	expectEvent[*and.EANDWorldEnter](t, event_ch)

	N := 10
	sessions := make([]and.ANDPeerSession, 0, N)
	for i := range N {
		sessions = append(sessions, MakeDummyPeerSession("H-"+strconv.Itoa(i)+"xxxxxx"))
	}
	for _, session := range sessions {
		world.JNI(target_session, and.MakeANDFullPeerSessionInfo(session), true)
	}
	for _, session := range sessions {
		world.FetchReturn(session, true)
	}
	for _, session := range sessions {
		world.MEM(session)
	}
	world.SJN(sessions[0], functional.Filter(sessions[:5], func(s and.ANDPeerSession) and.ANDIdentity { return s.ANDIdentity() }))
	world.SJN(sessions[1], functional.Filter(sessions, func(s and.ANDPeerSession) and.ANDIdentity { return s.ANDIdentity() }))
	world.SJN(sessions[2], functional.Filter(sessions, func(s and.ANDPeerSession) and.ANDIdentity { return s.ANDIdentity() }))
	for range N {
		expectEvent[*and.EANDSessionReady](t, event_ch)
	}

	<-time.After(time.Second * 5)
}

func TestCRR(t *testing.T) {
	event_ch := infchan.NewInfiniteChan[any](32)
	world, err := and.NewWorld_Open(context.Background(), &DummyFetcher{}, event_ch, "local", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	expectEvent[*and.EANDWorldEnter](t, event_ch)

	A_session := MakeDummyPeerSession("H-PeerAx")
	world.JN(A_session)
	expectEvent[*and.EANDSessionReady](t, event_ch)

	B_session := MakeDummyPeerSession("H-PeerBx")
	world.SJN(A_session, []and.ANDIdentity{B_session.ANDIdentity()})

	<-time.After(time.Second)
}
