package ahost

import (
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
)

func (h *AbyssHost) onAUPingTX(
	events ds.Queue,
	peer ani.IAbyssPeer,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// TODO: Implement AU_PING_TX handler
	h.handleANDEvent(events)
	return nil
}

func (h *AbyssHost) onAUPingRX(
	events ds.Queue,
	peer ani.IAbyssPeer,
) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	// TODO: Implement AU_PING_RX handler
	h.handleANDEvent(events)
	return nil
}
