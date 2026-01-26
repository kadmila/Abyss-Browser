package ann_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

func TestAbystSimpleHttpRequest(t *testing.T) {
	// Create two AbyssNodes
	root_key_A, _ := sec.NewRootPrivateKey()
	node_A, _ := ann.NewAbyssNode(root_key_A)

	root_key_B, _ := sec.NewRootPrivateKey()
	node_B, _ := ann.NewAbyssNode(root_key_B)

	// Start listening
	node_A.Listen()
	node_B.Listen()

	// Start service loops
	go node_A.Serve()
	go node_B.Serve()

	err := node_B.ConfigAbystGateway(`{"testpath":"dir:///./"}`)
	if err != nil {
		t.Errorf("Failed to configure abyst gateway: %v", err)
		return
	}

	// Exchange peer information
	node_A.AppendKnownPeer(node_B.RootCertificate(), node_B.HandshakeKeyCertificate())
	node_B.AppendKnownPeer(node_A.RootCertificate(), node_A.HandshakeKeyCertificate())

	// Establish connection from A to B
	node_A.Dial(node_B.ID())

	ctx, ctxcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer ctxcancel()
	go func() {
		for ctx.Err() == nil {
			node_B.Accept(ctx)
		}
	}()

	// Wait a bit for connection to establish
	<-time.After(500 * time.Millisecond)

	// Create AbystClient using node_A
	client := node_A.NewAbystClient()

	// Try to make a simple GET request to node_B
	resp, err := client.Get(node_B.ID(), "testpath/abyst_test_file.txt")
	if err != nil {
		t.Errorf("HTTP GET request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("Failed to read response body: %v", err)
		return
	}

	t.Logf("Response status: %s", resp.Status)
	t.Logf("Response body: %s", string(body))

	if string(body) != "Hello, Abyst!" {
		t.Fatal("abyst payload mismatch")
	}

	// Cleanup
	node_A.Close()
	node_B.Close()
}

func TestCollocatedHttp3Client(t *testing.T) {
	// Create an AbyssNode
	root_key, _ := sec.NewRootPrivateKey()
	node, _ := ann.NewAbyssNode(root_key)

	// Start listening
	node.Listen()

	// Start service loop
	go node.Serve()

	// Create collocated HTTP/3 client
	// This reuses the same quic.Transport (same IP:port) as the AbyssNode
	client := node.NewCollocatedHttp3Client()

	// Try to make a GET request to localhost:4433
	// Note: This requires an external HTTP/3 server to be running on port 4433
	// You can use the test server in testutil/http3server (change port to 4433)
	resp, err := client.Get("https://localhost:4433/")
	if err != nil {
		t.Fatal(err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("Failed to read response body: %v", err)
		return
	}

	t.Logf("Response status: %s", resp.Status)
	t.Logf("Response body: %s", string(body))

	// Cleanup
	node.Close()
}
