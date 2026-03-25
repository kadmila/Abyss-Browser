package ahost

import (
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
)

func (h *AbyssHost) onAUPingTX(
	peer ani.IAbyssPeer,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// TODO: Implement AU_PING_TX handler
	return nil
}

func (h *AbyssHost) onAUPingRX(
	peer ani.IAbyssPeer,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// TODO: Implement AU_PING_RX handler
	return nil
}
