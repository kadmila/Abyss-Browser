package ahost

type EPeerConnected struct {
	PeerID string
}

type EPeerDisconnected struct {
	PeerID string
}

type EPeerFound struct {
	PeerID string
}

type EPeerForgot struct {
	PeerID string
}
