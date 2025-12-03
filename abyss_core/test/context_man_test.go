package test

import (
	"context"
	"testing"
	"time"

	abyss_net "github.com/kadmila/Abyss-Browser/abyss_core/net_service"
)

func TestContextMan(t *testing.T) {
	pcm := abyss_net.NewContextedPeerMap()

	pci, ok := pcm.Append(context.Background(), "mallang", nil)
	if !ok {
		t.Fatal("failed to create context")
	}

	go pcm.Cleaner(context.Background())

	time.Sleep(time.Second)
	pci.Renew()

	<-pci.Context().Done()
}
