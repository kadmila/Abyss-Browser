package ann_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

func TestNewAbyssNode(t *testing.T) {
	// Node construction
	root_key_A, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	var node_A ani.IAbyssNode
	node_A, err = ann.NewAbyssNode(root_key_A)
	if err != nil {
		t.Fatal(err)
	}

	root_key_B, err := sec.NewRootPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	var node_B ani.IAbyssNode
	node_B, err = ann.NewAbyssNode(root_key_B)
	if err != nil {
		t.Fatal(err)
	}

	// Listening
	err = node_A.Listen()
	if err != nil {
		t.Fatal(err)
	}
	err = node_B.Listen()
	if err != nil {
		t.Fatal(err)
	}

	// Start service loop
	node_A_done := make(chan error)
	node_B_done := make(chan error)
	go func() {
		node_A_done <- node_A.Serve()
	}()
	go func() {
		node_B_done <- node_B.Serve()
	}()

	// Appending peer information
	err = node_A.AppendKnownPeer(node_B.RootCertificate(), node_B.HandshakeKeyCertificate())
	if err != nil {
		t.Fatal(err)
	}
	err = node_B.AppendKnownPeer(node_A.RootCertificate(), node_A.HandshakeKeyCertificate())
	if err != nil {
		t.Fatal(err)
	}

	// Mutual dialing (all address candidates)
	for _, v := range node_A.LocalAddrCandidates() {
		err = node_B.Dial(node_A.ID(), v)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range node_B.LocalAddrCandidates() {
		err = node_A.Dial(node_B.ID(), v)
		if err != nil {
			t.Fatal(err)
		}
	}

	ctx, ctxcancel := context.WithTimeout(context.Background(), time.Second)
	defer ctxcancel()

	// Accept for 3 seconds.
	dial_count := len(node_A.LocalAddrCandidates()) + len(node_B.LocalAddrCandidates())
	// fmt.Println("total dials: ", dial_count)
	node_A_err_ch := make(chan error, dial_count-1)
	peer_A_B_ch := make(chan ani.IAbyssPeer, 1)
	node_B_err_ch := make(chan error, dial_count-1)
	peer_B_A_ch := make(chan ani.IAbyssPeer, 1)
	go func() {
		for {
			peer_A_B, err := node_A.Accept(ctx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return
				}
				// fmt.Println("A: declined>> ", err)
				node_A_err_ch <- err
			} else {
				// fmt.Println("A: connected>> " + peer_A_B.RemoteAddr().String() + peer_A_B.ID())
				peer_A_B_ch <- peer_A_B
			}
		}
	}()
	go func() {
		for {
			peer_B_A, err := node_B.Accept(ctx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return
				}
				// fmt.Println("B: declined>> ", err)
				node_B_err_ch <- err
			} else {
				// fmt.Println("B: connected>> " + peer_B_A.RemoteAddr().String() + peer_B_A.ID())
				peer_B_A_ch <- peer_B_A
			}
		}
	}()

	// While accepting, check the accept results.
	select {
	case <-ctx.Done():
		t.Fatal("accept timeout")
	case peer_A_B := <-peer_A_B_ch:
		if peer_A_B.ID() != node_B.ID() {
			t.Fatal("peer id mismatch")
		}
	}
	for range dial_count - 1 {
		select {
		case <-ctx.Done():
			t.Fatal("accept timeout")
		case <-node_A_err_ch:
		}
	}
	select {
	case <-ctx.Done():
		t.Fatal("accept timeout")
	case peer_B_A := <-peer_B_A_ch:
		if peer_B_A.ID() != node_A.ID() {
			t.Fatal("peer id mismatch")
		}
	}
	for range dial_count - 1 {
		select {
		case <-ctx.Done():
			t.Fatal("accept timeout")
		case <-node_B_err_ch:
		}
	}

	<-ctx.Done()

	// If more entries remain in channels, it is a bug.
	too_many_accept := true
	select {
	case <-node_A_err_ch:
	case <-peer_A_B_ch:
	case <-node_B_err_ch:
	case <-peer_B_A_ch:
	default:
		too_many_accept = false
	}
	if too_many_accept {
		t.Fatal("too many accept")
	}

	node_A.Close()
	node_B.Close()

	err = <-node_A_done
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	err = <-node_B_done
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReconnect(t *testing.T) {
	root_key_A, _ := sec.NewRootPrivateKey()
	node_A, _ := ann.NewAbyssNode(root_key_A)
	node_A.Listen()
	go node_A.Serve()

	root_key_B, _ := sec.NewRootPrivateKey()
	node_B, _ := ann.NewAbyssNode(root_key_B)
	node_B.Listen()
	go node_B.Serve()

	node_A.AppendKnownPeer(node_B.RootCertificate(), node_B.HandshakeKeyCertificate())
	node_B.AppendKnownPeer(node_A.RootCertificate(), node_A.HandshakeKeyCertificate())

	one_cycle := func() {
		ctx, ctxcancel := context.WithTimeout(context.Background(), time.Second)
		defer ctxcancel()

		for _, v := range node_B.LocalAddrCandidates() {
			node_A.Dial(node_B.ID(), v)
		}
		for _, v := range node_A.LocalAddrCandidates() {
			node_B.Dial(node_A.ID(), v)
		}

		var peer_A_B ani.IAbyssPeer
		for {
			peer, err := node_A.Accept(ctx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("accept timeout")
				}
				continue
			}
			peer_A_B = peer
			break
		}
		var peer_B_A ani.IAbyssPeer
		for {
			peer, err := node_B.Accept(ctx)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("accept timeout")
				}
				continue
			}
			peer_B_A = peer
			break
		}

		v_sent := rand.Int()
		peer_A_B.Send(0, v_sent)

		var msg_rcvd ahmp.AHMPMesage
		peer_B_A.Recv(&msg_rcvd)

		var v_rcvd int
		cbor.Unmarshal(msg_rcvd.Payload, &v_rcvd)

		if v_rcvd != v_sent {
			t.Fatal("communication fail")
		}

		// drain accept queue
		done_ch := make(chan bool, 2)
		go func() {
			for {
				_, err := node_A.Accept(ctx)
				if err != nil && errors.Is(err, context.DeadlineExceeded) {
					break
				}
			}
			done_ch <- true
		}()
		go func() {
			for {
				_, err := node_B.Accept(ctx)
				if err != nil && errors.Is(err, context.DeadlineExceeded) {
					break
				}
			}
			done_ch <- true
		}()
		<-done_ch
		<-done_ch

		peer_A_B.Close()
		peer_B_A.Close()
	}

	for range 5 {
		one_cycle()
	}
}

func TestDialTimeout(t *testing.T) {
	root_key_A, _ := sec.NewRootPrivateKey()
	node_A, _ := ann.NewAbyssNode(root_key_A)
	node_A.Listen()
	go node_A.Serve()

	root_key_B, _ := sec.NewRootPrivateKey()
	node_B, _ := ann.NewAbyssNode(root_key_B)

	node_A.AppendKnownPeer(node_B.RootCertificate(), node_B.HandshakeKeyCertificate())

	err := node_A.Dial(node_B.ID(), netip.MustParseAddrPort("127.0.0.1:10000"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, ctxcancel := context.WithTimeout(context.Background(), time.Second*10)
	defer ctxcancel()
	_, err = node_A.Accept(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("should throw error other than Accept context timeout")
	}
}

func TestDialTimeout2(t *testing.T) {
	root_key_A, _ := sec.NewRootPrivateKey()
	node_A, _ := ann.NewAbyssNode(root_key_A)
	node_A.Listen()
	go node_A.Serve()

	root_key_B, _ := sec.NewRootPrivateKey()
	node_B, _ := ann.NewAbyssNode(root_key_B)
	node_B.Listen()

	node_A.AppendKnownPeer(node_B.RootCertificate(), node_B.HandshakeKeyCertificate())

	err := node_A.Dial(node_B.ID(), node_B.LocalAddrCandidates()[1])
	if err != nil {
		t.Fatal(err)
	}
	ctx, ctxcancel := context.WithTimeout(context.Background(), time.Second*10)
	defer ctxcancel()
	_, err = node_A.Accept(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("should throw error other than Accept context timeout")
	}
}
