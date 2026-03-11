package ahost_test

import (
	"context"
	"testing"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/ahost"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

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
	world_A, err := host_A.OpenWorld("abyss://example.com/test")
	if err != nil {
		t.Fatal(err)
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
	_, err = host_B.JoinWorld(peer_B_to_A.PeerID, "/")
	if err != nil {
		t.Fatal(err)
	}

	// Host B should receive EANDWorldEnter event
	expectEvent[*and.EANDWorldEnter](t, host_B.GetEventCh())

	// Both hosts should receive EANDSessionReady event
	expectEvent[*and.EANDSessionReady](t, host_A.GetEventCh())
	expectEvent[*and.EANDSessionReady](t, host_B.GetEventCh())
}
