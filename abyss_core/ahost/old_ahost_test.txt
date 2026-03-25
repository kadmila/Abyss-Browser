package ahost_test

import (
	"context"
	"testing"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/ahost"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

// expectEvent waits for an event of type T.
// Returns the event on success or fails the test on timeout.
// Skips events that don't match the expected type.
func expectEvent[T any](t *testing.T, event_ch <-chan any) T {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	var zero T
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("timeout waiting for event %T", zero)
			return zero
		case event := <-event_ch:
			if typed_event, ok := event.(T); ok {
				return typed_event
			}
			// Skip events that don't match - they might be for other purposes
		}
	}
}

func TestPeerConnectedEvent(t *testing.T) {
	// Construct two hosts
	root_key_A, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	host_A, err := ahost.NewAbyssHost(root_key_A)
	if err != nil {
		t.Fatal(err)
	}

	root_key_B, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	host_B, err := ahost.NewAbyssHost(root_key_B)
	if err != nil {
		t.Fatal(err)
	}

	// Bind both hosts
	err = host_A.Bind()
	if err != nil {
		t.Fatal(err)
	}
	err = host_B.Bind()
	if err != nil {
		t.Fatal(err)
	}

	// Start serving (Serve() blocks, so run in goroutines)
	go host_A.Serve()
	go host_B.Serve()
	defer host_A.Close()
	defer host_B.Close()

	// Exchange peer information
	err = host_A.AppendKnownPeer(host_B.RootCertificate(), host_B.HandshakeKeyCertificate())
	if err != nil {
		t.Fatal(err)
	}
	err = host_B.AppendKnownPeer(host_A.RootCertificate(), host_A.HandshakeKeyCertificate())
	if err != nil {
		t.Fatal(err)
	}

	// One host dials another
	err = host_A.Dial(host_B.ID())
	if err != nil {
		t.Fatal(err)
	}

	// This should raise EPeerConnected event
	expectEvent[*ahost.EPeerConnected](t, host_A.GetEventCh())
	expectEvent[*ahost.EPeerConnected](t, host_B.GetEventCh())
}

func TestJoinWorld(t *testing.T) {
	// Construct two hosts
	root_key_A, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	host_A, err := ahost.NewAbyssHost(root_key_A)
	if err != nil {
		t.Fatal(err)
	}

	root_key_B, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	host_B, err := ahost.NewAbyssHost(root_key_B)
	if err != nil {
		t.Fatal(err)
	}

	// Bind both hosts
	err = host_A.Bind()
	if err != nil {
		t.Fatal(err)
	}
	err = host_B.Bind()
	if err != nil {
		t.Fatal(err)
	}

	// Start serving
	go host_A.Serve()
	go host_B.Serve()
	defer host_A.Close()
	defer host_B.Close()

	// Exchange peer information
	err = host_A.AppendKnownPeer(host_B.RootCertificate(), host_B.HandshakeKeyCertificate())
	if err != nil {
		t.Fatal(err)
	}
	err = host_B.AppendKnownPeer(host_A.RootCertificate(), host_A.HandshakeKeyCertificate())
	if err != nil {
		t.Fatal(err)
	}

	// Host A opens a world
	world_A := host_A.OpenWorld("abyss://example.com/test")
	if world_A == nil {
		t.Fatal("world should not be nil")
	}

	// Expose world to default path "/"
	host_A.ExposeWorldForJoin(world_A, "/")

	// Wait for world enter event on host A
	expectEvent[*and.EANDWorldEnter](t, host_A.GetEventCh())

	// Host B dials host A
	err = host_B.Dial(host_A.ID())
	if err != nil {
		t.Fatal(err)
	}

	// Wait for peer connection on host B
	peer_B_to_A := expectEvent[*ahost.EPeerConnected](t, host_B.GetEventCh())
	expectEvent[*ahost.EPeerConnected](t, host_A.GetEventCh())

	// Host B joins the world at path "/"
	world, err := host_B.JoinWorld(peer_B_to_A.PeerID, "/")
	if err != nil {
		t.Fatal(err)
	}

	// Wait for session request event on host A (host A should receive join request)
	session_request := expectEvent[*and.EANDSessionRequest](t, host_A.GetEventCh())

	// Host A accepts the session request
	host_A.AcceptWorldSession(world_A, session_request.Peer.ID(), session_request.SessionID)

	// Host B should receive EANDWorldEnter event
	expectEvent[*and.EANDWorldEnter](t, host_B.GetEventCh())

	// Both hosts should receive EANDSessionReady event
	expectEvent[*and.EANDSessionReady](t, host_A.GetEventCh())
	expectEvent[*and.EANDSessionReady](t, host_B.GetEventCh())

	world.CheckSanity()
}

func TestJoinWorldTransitive(t *testing.T) {
	// Construct three hosts
	root_key_A, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	host_A, err := ahost.NewAbyssHost(root_key_A)
	if err != nil {
		t.Fatal(err)
	}

	root_key_B, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	host_B, err := ahost.NewAbyssHost(root_key_B)
	if err != nil {
		t.Fatal(err)
	}

	root_key_C, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	host_C, err := ahost.NewAbyssHost(root_key_C)
	if err != nil {
		t.Fatal(err)
	}

	// Bind all hosts
	if err = host_A.Bind(); err != nil {
		t.Fatal(err)
	}
	if err = host_B.Bind(); err != nil {
		t.Fatal(err)
	}
	if err = host_C.Bind(); err != nil {
		t.Fatal(err)
	}

	// Start serving
	go host_A.Serve()
	go host_B.Serve()
	go host_C.Serve()
	defer host_A.Close()
	defer host_B.Close()
	defer host_C.Close()

	// Exchange peer information (A-B and B-C, but not A-C initially)
	if err = host_A.AppendKnownPeer(host_B.RootCertificate(), host_B.HandshakeKeyCertificate()); err != nil {
		t.Fatal(err)
	}
	if err = host_B.AppendKnownPeer(host_A.RootCertificate(), host_A.HandshakeKeyCertificate()); err != nil {
		t.Fatal(err)
	}
	if err = host_B.AppendKnownPeer(host_C.RootCertificate(), host_C.HandshakeKeyCertificate()); err != nil {
		t.Fatal(err)
	}
	if err = host_C.AppendKnownPeer(host_B.RootCertificate(), host_B.HandshakeKeyCertificate()); err != nil {
		t.Fatal(err)
	}

	// Synchronization channels
	world_exposed_A := make(chan struct{})
	world_exposed_B := make(chan struct{})
	B_joined := make(chan struct{})

	// Run each host's event handling in separate goroutines
	done_A := make(chan error, 1)
	done_B := make(chan error, 1)
	done_C := make(chan error, 1)

	// Host A goroutine
	go func() {
		defer func() { done_A <- nil }()

		// 1. Opens world, exposes at "/" -> EANDWorldEnter
		world_A := host_A.OpenWorld("abyss://example.com/transitive")
		host_A.ExposeWorldForJoin(world_A, "/")
		expectEvent[*and.EANDWorldEnter](t, host_A.GetEventCh())
		close(world_exposed_A)

		// 2. EPeerConnected (B)
		expectEvent[*ahost.EPeerConnected](t, host_A.GetEventCh())

		// 3. receives EANDSessionRequest (from B), accepts it
		session_req_B := expectEvent[*and.EANDSessionRequest](t, host_A.GetEventCh())
		host_A.AcceptWorldSession(world_A, session_req_B.Peer.ID(), session_req_B.SessionID)

		// 4. receives EANDSessionReady (from B)
		expectEvent[*and.EANDSessionReady](t, host_A.GetEventCh())

		// 5. EPeerConnected (C)
		expectEvent[*ahost.EPeerConnected](t, host_A.GetEventCh())

		// 6. receives EANDSessionRequest (from C), accepts it
		session_req_C := expectEvent[*and.EANDSessionRequest](t, host_A.GetEventCh())
		host_A.AcceptWorldSession(world_A, session_req_C.Peer.ID(), session_req_C.SessionID)

		// 7. receives EANDSessionReady (from C)
		expectEvent[*and.EANDSessionReady](t, host_A.GetEventCh())
	}()

	// Host B goroutine
	go func() {
		defer func() { done_B <- nil }()

		// Wait for A to expose the world
		<-world_exposed_A

		// 1. dials A -> EPeerConnected (A)
		if err := host_B.Dial(host_A.ID()); err != nil {
			t.Error(err)
			return
		}
		peer_B_to_A := expectEvent[*ahost.EPeerConnected](t, host_B.GetEventCh())

		// 2. joins "/" to A -> EANDWorldEnter -> exposes at "/shared"
		host_B.JoinWorld(peer_B_to_A.PeerID, "/")
		world_enter_B := expectEvent[*and.EANDWorldEnter](t, host_B.GetEventCh())
		host_B.ExposeWorldForJoin(world_enter_B.World, "/shared")
		close(world_exposed_B)

		// 3. EANDSessionReady (from A)
		expectEvent[*and.EANDSessionReady](t, host_B.GetEventCh())
		close(B_joined)

		// 4. EPeerConnected (C)
		expectEvent[*ahost.EPeerConnected](t, host_B.GetEventCh())

		// 5. receives EANDSessionRequest (from C), accepts it
		session_req_C := expectEvent[*and.EANDSessionRequest](t, host_B.GetEventCh())
		host_B.AcceptWorldSession(world_enter_B.World, session_req_C.Peer.ID(), session_req_C.SessionID)

		// 6. receives EANDSessionReady (from C)
		expectEvent[*and.EANDSessionReady](t, host_B.GetEventCh())
	}()

	// Host C goroutine
	go func() {
		defer func() { done_C <- nil }()

		// Wait for B to join and expose the world
		<-world_exposed_B
		<-B_joined

		// 1. dials B -> EPeerConnected (B)
		if err := host_C.Dial(host_B.ID()); err != nil {
			t.Error(err)
			return
		}
		peer_C_to_B := expectEvent[*ahost.EPeerConnected](t, host_C.GetEventCh())

		// 2. joins "/shared" to B -> EANDWorldEnter
		host_C.JoinWorld(peer_C_to_B.PeerID, "/shared")
		world_enter_C := expectEvent[*and.EANDWorldEnter](t, host_C.GetEventCh())

		// 3. EANDSessionReady (from B)
		expectEvent[*and.EANDSessionReady](t, host_C.GetEventCh())

		// 4. EPeerConnected (A)
		expectEvent[*ahost.EPeerConnected](t, host_C.GetEventCh())

		// 5. receives EANDSessionRequest (from A), accepts it
		session_req_A := expectEvent[*and.EANDSessionRequest](t, host_C.GetEventCh())
		host_C.AcceptWorldSession(world_enter_C.World, session_req_A.Peer.ID(), session_req_A.SessionID)

		// 6. receives EANDSessionReady (from A)
		expectEvent[*and.EANDSessionReady](t, host_C.GetEventCh())
	}()

	// Wait for all goroutines to complete
	timeout := time.After(time.Second * 10)
	for range 3 {
		select {
		case err := <-done_A:
			if err != nil {
				t.Fatalf("Host A failed: %v", err)
			}
		case err := <-done_B:
			if err != nil {
				t.Fatalf("Host B failed: %v", err)
			}
		case err := <-done_C:
			if err != nil {
				t.Fatalf("Host C failed: %v", err)
			}
		case <-timeout:
			t.Fatal("Test timed out")
		}
	}

	<-time.After(3 * time.Second)
}

func TestJoinWorldTransitiveNPeers(t *testing.T) {
	N := 30

	// Construct five hosts
	hosts := make([]*ahost.AbyssHost, N)
	for i := 0; i < N; i++ {
		root_key, err := sec.NewRootPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		host, err := ahost.NewAbyssHost(root_key)
		if err != nil {
			t.Fatal(err)
		}
		hosts[i] = host
	}

	// Bind all hosts
	for i := 0; i < N; i++ {
		if err := hosts[i].Bind(); err != nil {
			t.Fatal(err)
		}
	}

	// Start serving
	for i := 0; i < N; i++ {
		go hosts[i].Serve()
		defer hosts[i].Close()
	}

	// Exchange peer information: each host knows the next one
	for i := 0; i < (N - 1); i++ {
		if err := hosts[i].AppendKnownPeer(hosts[i+1].RootCertificate(), hosts[i+1].HandshakeKeyCertificate()); err != nil {
			t.Fatal(err)
		}
		if err := hosts[i+1].AppendKnownPeer(hosts[i].RootCertificate(), hosts[i].HandshakeKeyCertificate()); err != nil {
			t.Fatal(err)
		}
	}

	// Synchronization channels for each host exposing the world
	world_exposed := make([]chan struct{}, N)
	for i := 0; i < N; i++ {
		world_exposed[i] = make(chan struct{})
	}

	// Done channels for each host
	done := make([]chan error, N)
	for i := 0; i < N; i++ {
		done[i] = make(chan error, 1)
	}

	// Host 0: Opens world and waits for all others to join
	go func() {
		defer func() { done[0] <- nil }()

		world_0 := hosts[0].OpenWorld("abyss://example.com/chainN")
		hosts[0].ExposeWorldForJoin(world_0, "/")
		expectEvent[*and.EANDWorldEnter](t, hosts[0].GetEventCh())
		close(world_exposed[0])

		// Accept (N-1) peers (hosts 1, 2, 3, (N-1))
		for i := 1; i <= (N - 1); i++ {
			expectEvent[*ahost.EPeerConnected](t, hosts[0].GetEventCh())
			session_req := expectEvent[*and.EANDSessionRequest](t, hosts[0].GetEventCh())
			hosts[0].AcceptWorldSession(world_0, session_req.Peer.ID(), session_req.SessionID)
			expectEvent[*and.EANDSessionReady](t, hosts[0].GetEventCh())
		}
	}()

	// Hosts 1-(N-1): All follow the same pattern
	for host_idx := 1; host_idx <= (N - 1); host_idx++ {
		idx := host_idx // Capture for closure
		go func() {
			defer func() { done[idx] <- nil }()

			// Wait for previous host to expose world
			<-world_exposed[idx-1]

			// Wait 100ms before joining
			time.Sleep(time.Millisecond * 100)

			// Dial previous host (join target)
			if err := hosts[idx].Dial(hosts[idx-1].ID()); err != nil {
				t.Error(err)
				return
			}
			peer := expectEvent[*ahost.EPeerConnected](t, hosts[idx].GetEventCh())

			// Join world
			hosts[idx].JoinWorld(peer.PeerID, "/")
			world_enter := expectEvent[*and.EANDWorldEnter](t, hosts[idx].GetEventCh())

			// Expose world for next host to join (except host (N-1))
			if idx < (N - 1) {
				hosts[idx].ExposeWorldForJoin(world_enter.World, "/")
				close(world_exposed[idx])
			}

			// Now process events from existing members in any order
			// We expect:
			// - (idx-1) EANDSessionReady events (from all existing members 0 to idx-1)
			// - (idx-2) EPeerConnected events (from non-join-target members 0 to idx-2)
			// - (idx-2) EANDSessionRequest events (from non-join-target members)

			session_ready_count := 0
			peer_connected_count := 0
			session_requests := make([]*and.EANDSessionRequest, 0)

			// Loop until we have all expected events from existing members
			for session_ready_count < idx {
				select {
				case event := <-hosts[idx].GetEventCh():
					switch e := event.(type) {
					case *and.EANDSessionReady:
						session_ready_count++
					case *ahost.EPeerConnected:
						peer_connected_count++
					case *and.EANDSessionRequest:
						// Accept immediately
						hosts[idx].AcceptWorldSession(world_enter.World, e.Peer.ID(), e.SessionID)
						session_requests = append(session_requests, e)
					}
				case <-time.After(time.Second * 5):
					t.Errorf("Host %d timeout: got %d/%d SessionReady, %d PeerConnected, %d SessionRequest",
						idx, session_ready_count, idx, peer_connected_count, len(session_requests))
					return
				}
			}

			// Verify we got the right number of each event type
			if peer_connected_count != idx-1 {
				t.Errorf("Host %d: expected %d EPeerConnected, got %d", idx, idx-1, peer_connected_count)
			}
			if len(session_requests) != idx-1 {
				t.Errorf("Host %d: expected %d EANDSessionRequest, got %d", idx, idx-1, len(session_requests))
			}

			// Now accept session requests from subsequent joiners (idx+1 to (N-1))
			for i := idx + 1; i <= (N - 1); i++ {
				expectEvent[*ahost.EPeerConnected](t, hosts[idx].GetEventCh())
				session_req := expectEvent[*and.EANDSessionRequest](t, hosts[idx].GetEventCh())
				hosts[idx].AcceptWorldSession(world_enter.World, session_req.Peer.ID(), session_req.SessionID)
				expectEvent[*and.EANDSessionReady](t, hosts[idx].GetEventCh())
			}
		}()
	}

	// Wait for all goroutines to complete
	timeout := time.After(time.Second * 30)
	for i := 0; i < N; i++ {
		select {
		case err := <-done[i]:
			if err != nil {
				t.Fatalf("Host %d failed: %v", i, err)
			}
		case <-timeout:
			t.Fatalf("Test timed out waiting for host %d", i)
		}
	}

	<-time.After(10 * time.Second)
}

func TestDisconnect(t *testing.T) {
	// Construct two hosts
	root_key_A, _ := sec.NewRootPrivateKey()
	host_A, _ := ahost.NewAbyssHost(root_key_A)

	root_key_B, _ := sec.NewRootPrivateKey()
	host_B, _ := ahost.NewAbyssHost(root_key_B)

	// Bind both hosts
	host_A.Bind()
	host_B.Bind()

	// Start serving
	go host_A.Serve()
	go host_B.Serve()
	defer host_A.Close()
	defer host_B.Close()

	// Exchange peer information
	host_A.AppendKnownPeer(host_B.RootCertificate(), host_B.HandshakeKeyCertificate())
	host_B.AppendKnownPeer(host_A.RootCertificate(), host_A.HandshakeKeyCertificate())

	// Wait for peer found events
	expectEvent[*ahost.EPeerFound](t, host_A.GetEventCh())
	expectEvent[*ahost.EPeerFound](t, host_B.GetEventCh())

	// Host A dials host B
	host_A.Dial(host_B.ID())

	// Wait for peer connection events
	e_a_conn := expectEvent[*ahost.EPeerConnected](t, host_A.GetEventCh())
	e_b_conn := expectEvent[*ahost.EPeerConnected](t, host_B.GetEventCh())

	if e_a_conn.PeerID != host_B.ID() || e_b_conn.PeerID != host_A.ID() {
		t.Fatal("Peer IDs do not match")
	}

	// Host A closes
	host_A.EraseKnownPeer(e_a_conn.PeerID)

	// Wait for peer forget event
	expectEvent[*ahost.EPeerForgot](t, host_A.GetEventCh())

	// Both hosts should receive EPeerDisconnected event
	expectEvent[*ahost.EPeerDisconnected](t, host_A.GetEventCh())
	expectEvent[*ahost.EPeerDisconnected](t, host_B.GetEventCh())
}

func TestDisconnect2(t *testing.T) {
	// Construct two hosts
	root_key_A, _ := sec.NewRootPrivateKey()
	host_A, _ := ahost.NewAbyssHost(root_key_A)

	root_key_B, _ := sec.NewRootPrivateKey()
	host_B, _ := ahost.NewAbyssHost(root_key_B)

	// Bind both hosts
	host_A.Bind()
	host_B.Bind()

	// Start serving
	go host_A.Serve()
	go host_B.Serve()
	defer host_A.Close()
	defer host_B.Close()

	// Exchange peer information
	host_A.AppendKnownPeer(host_B.RootCertificate(), host_B.HandshakeKeyCertificate())
	host_B.AppendKnownPeer(host_A.RootCertificate(), host_A.HandshakeKeyCertificate())

	// Wait for peer found events
	expectEvent[*ahost.EPeerFound](t, host_A.GetEventCh())
	expectEvent[*ahost.EPeerFound](t, host_B.GetEventCh())

	// Host A dials host B
	host_A.Dial(host_B.ID())

	// Wait for peer connection events
	e_a_conn := expectEvent[*ahost.EPeerConnected](t, host_A.GetEventCh())
	e_b_conn := expectEvent[*ahost.EPeerConnected](t, host_B.GetEventCh())

	if e_a_conn.PeerID != host_B.ID() || e_b_conn.PeerID != host_A.ID() {
		t.Fatal("Peer IDs do not match")
	}

	// Host A closes
	host_A.Close()

	<-time.After(20 * time.Second) // wait for timeout.

	expectEvent[*ahost.EPeerDisconnected](t, host_B.GetEventCh())
}
