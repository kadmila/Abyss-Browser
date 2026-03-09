package ahost

import (
	"context"

	"github.com/google/uuid"
	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
)

type fetchEntry struct {
	wsid uuid.UUID
	and.ANDIdentity
	fwd bool
}

type PeerFetcher struct {
	ctx               context.Context
	ctx_cancel        context.CancelFunc
	dial_func         func(and.ANDFullPeerSessionInfo)
	peer_ch           chan ani.IAbyssPeer
	fetch_ch          chan fetchEntry
	peers             map[string]ani.IAbyssPeer
	and_fetch_pending map[string][]fetchEntry // PeerID -> entries

	done chan bool
}

func NewPeerFetcher(
	ctx context.Context,
	dial_func func(and.ANDFullPeerSessionInfo),
	world_get_func func(uuid.UUID) (*and.World, bool),
) *PeerFetcher {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &PeerFetcher{
		ctx:               inner_ctx,
		ctx_cancel:        cancel,
		dial_func:         dial_func,
		peer_ch:           make(chan ani.IAbyssPeer, 32),
		fetch_ch:          make(chan fetchEntry, 32),
		peers:             make(map[string]ani.IAbyssPeer),
		and_fetch_pending: make(map[string][]fetchEntry),
		done:              make(chan bool, 1),
	}
	go result.work(world_get_func)
	return result
}

func (f *PeerFetcher) work(
	world_get_func func(uuid.UUID) (*and.World, bool),
) {
	for {
		select {
		case <-f.ctx.Done():
			f.done <- true
			return
		case fetch := <-f.fetch_ch:
			if peer, ok := f.peers[fetch.PeerID]; ok {
				world, ok := world_get_func(fetch.wsid)
				if ok {
					world.FetchReturn(
						ds.MakeQueue(),
						and.ANDPeerSession{
							Peer:      peer,
							SessionID: fetch.SessionID,
						},
						fetch.fwd,
					)
				}
				// or, ignore
				continue
			}

			rem, ok := f.and_fetch_pending[fetch.PeerID]
			if ok {
				f.and_fetch_pending[fetch.PeerID] = append(rem, fetch)
			} else {
				new_entry := make([]fetchEntry, 0, 1)
				new_entry = append(new_entry, fetch)
				f.and_fetch_pending[fetch.PeerID] = new_entry
			}
		case peer := <-f.peer_ch:
			if pending_fetches, ok := f.and_fetch_pending[peer.ID()]; ok {
				for _, pending_fetch := range pending_fetches {
					world, ok := world_get_func(pending_fetch.wsid)
					if ok {

					}
				}
			}
		}
	}
}

func (f *PeerFetcher) Fetch(
	wsid uuid.UUID,
	target and.ANDFullPeerSessionInfo,
	fwd bool,
) {
	f.dial_func(target)
	f.fetch_ch <- fetchEntry{
		wsid:        wsid,
		ANDIdentity: target.ANDIdentity,
		fwd:         fwd,
	}
}

func (f *PeerFetcher) GiveupFetch()

func (f *PeerFetcher) AddPeer(peer ani.IAbyssPeer) {

}

// RemovePeer is synchronous.
func (f *PeerFetcher) RemovePeer(peerID string) {

}
