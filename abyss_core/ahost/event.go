package ahost

import "github.com/kadmila/Abyss-Browser/abyss_core/ani"

type EPeerConnected struct {
	Peer ani.IAbyssPeer
}

type EPeerDisconnected struct {
	PeerID string
}
