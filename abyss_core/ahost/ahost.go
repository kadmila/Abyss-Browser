// ahost (alpha/abyss host) is a revised abyss host implementation of previous host package.
// ahost features better straightforward API interfaces, with significantly enhanced code maintainability.
package ahost

import (
	"context"
	"errors"

	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/ann"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
)

type AbyssHost struct {
	net ani.IAbyssNode
	and *and.AND
}

func NewAbyssHost(root_key sec.PrivateKey) (*AbyssHost, error) {
	node, err := ann.NewAbyssNode(root_key)
	if err != nil {
		return nil, err
	}
	return &AbyssHost{
		net: node,
		and: and.NewAND(node.ID()),
	}, nil
}

func (h *AbyssHost) Main() error {
	err := h.net.Listen()
	if err != nil {
		return err
	}
	node_done := make(chan error)
	go func() {
		node_done <- h.net.Serve()
	}()
	return nil
}

func (h *AbyssHost) servePeer() error {
	var peer ani.IAbyssPeer
	for {
		var err error
		peer, err = h.net.Accept(context.Background())
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return err
			}
			// dial/accept normal errors: not properly implemented yet.
			continue
		}
	}

	var msg ahmp.AHMPMesage
	for {
		err := peer.Recv(&msg)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetEvent blocks until an event is raised.
// Possible event types are below:
/*
and.EANDWorldEnter
and.EANDSessionRequest
and.EANDSessionReady
and.EANDSessionClose
and.EANDObjectAppend
and.EANDObjectDelete
and.EANDWorldLeave
EPeerConnected
EPeerDisconnected
*/
func (h *AbyssHost) GetEvent() (any, error) {
	return nil, nil
}
