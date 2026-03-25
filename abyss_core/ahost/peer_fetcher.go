package ahost

import (
	"context"
	"sync"

	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/infchan"
)

type fetchEntry struct {
	world *and.World
	and.ANDIdentity
	fwd bool
}

type fetchReadyEntry struct {
	world *and.World
	and.ANDPeerSession
	fwd bool
}

type PeerFetcher struct {
	ctx        context.Context
	ctx_cancel context.CancelFunc

	dial_func func(and.ANDFullPeerSessionInfo)

	mtx               sync.Mutex
	peers             map[string]ani.IAbyssPeer
	and_fetch_pending map[string][]fetchEntry // PeerID -> entries

	fetch_ready_ch *infchan.InfiniteChan[fetchReadyEntry]
	done           chan bool
}

func NewPeerFetcher(
	ctx context.Context,
	dial_func func(and.ANDFullPeerSessionInfo),
) *PeerFetcher {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &PeerFetcher{
		ctx:        inner_ctx,
		ctx_cancel: cancel,

		dial_func: dial_func,

		peers:             make(map[string]ani.IAbyssPeer),
		and_fetch_pending: make(map[string][]fetchEntry),

		fetch_ready_ch: infchan.NewInfiniteChan[fetchReadyEntry](32),
		done:           make(chan bool, 1),
	}
	go func() {
		for {
			select {
			case <-result.ctx.Done():
				result.done <- true
				return
			case pending_fetch := <-result.fetch_ready_ch.Out:
				pending_fetch.world.FetchReturn(pending_fetch.ANDPeerSession, pending_fetch.fwd)
			}
		}
	}()
	return result
}

func (f *PeerFetcher) Fetch(
	world *and.World,
	target and.ANDFullPeerSessionInfo,
	fwd bool,
) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	if peer, ok := f.peers[target.PeerID]; ok {
		f.fetch_ready_ch.In <- fetchReadyEntry{
			world: world,
			ANDPeerSession: and.ANDPeerSession{
				Peer:      peer,
				SessionID: target.SessionID,
			},
			fwd: fwd,
		}
		return
	}

	f.dial_func(target)
	rem, ok := f.and_fetch_pending[target.PeerID]
	if ok {
		f.and_fetch_pending[target.PeerID] = append(
			rem,
			fetchEntry{
				world:       world,
				ANDIdentity: target.ANDIdentity,
				fwd:         fwd,
			},
		)
	} else {
		f.and_fetch_pending[target.PeerID] = []fetchEntry{
			{
				world:       world,
				ANDIdentity: target.ANDIdentity,
				fwd:         fwd,
			},
		}
	}
}

func (f *PeerFetcher) AddPeer(peer ani.IAbyssPeer) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	pending_fetches, ok := f.and_fetch_pending[peer.ID()]
	if ok {
		for _, fetch := range pending_fetches {
			f.fetch_ready_ch.In <- fetchReadyEntry{
				world: fetch.world,
				ANDPeerSession: and.ANDPeerSession{
					Peer:      peer,
					SessionID: fetch.SessionID,
				},
				fwd: fetch.fwd,
			}
		}
		delete(f.and_fetch_pending, peer.ID())
	}

	f.peers[peer.ID()] = peer
}

// RemovePeer deletes peer. TODO: let PeerFetcher call and.World.Disconnect().
func (f *PeerFetcher) RemovePeer(peerID string) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	delete(f.peers, peerID)
}

func (f *PeerFetcher) GetPeer(peerID string) (ani.IAbyssPeer, bool) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	peer, ok := f.peers[peerID]
	return peer, ok
}

func (f *PeerFetcher) WorldClose(world *and.World) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	f.and_fetch_pending = functional.Filter_M_ok(
		f.and_fetch_pending,
		func(pendings []fetchEntry) ([]fetchEntry, bool) {
			remainder := functional.Filter_ok(
				pendings,
				func(e fetchEntry) (fetchEntry, bool) {
					if e.world != world {
						return e, true
					}
					return e, false
				},
			)
			if len(remainder) > 0 {
				return remainder, true
			}
			return remainder, false
		},
	)
}

// Close() can only be called once.
func (f *PeerFetcher) Close() {
	f.ctx_cancel()
	<-f.done
}
