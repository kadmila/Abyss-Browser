package ahost

import (
	"context"
	"fmt"
	"time"

	"github.com/kadmila/Abyss-Browser/abyss_core/and"
	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

//// Deadlock risk
// and.World calls FetchQueue.Add(), which may block when f.fetch_ch is full.
// The f.fetch_ch is consumed by the PeerFetcher.work() goroutine,
// which calls and.World.FetchReturn().
// If and.World.FetchReturn() blocks, fetch routine deadlocks.
//
// The problem is, and.World.FetchReturn() requires locking the world.
// If and.World is blocked calling FetchQueue.Add(), the world lock never releases.
//
// Mitigation:
// Scale fetch queue.
//
// Solution:
// Let FetchQueue.Add() fail if the channel is full.
// and.World internal paths must not include a blocking call.
// Be conservative; don't push in traffic and computation load to max up resource.
// abyss_core should not be the main resource hungry path in any project.
////

type fetchEntry struct {
	world *and.World
	and.ANDIdentity
	fwd bool
}

// FetchQueue is referenced from and.World
type FetchQueue struct {
	fetch_ch  chan fetchEntry
	dial_func func(and.ANDFullPeerSessionInfo)
}

func (f *FetchQueue) Fetch(
	world *and.World,
	target and.ANDFullPeerSessionInfo,
	fwd bool,
) {
	fmt.Println(time.Now().Format("15:04:05.00000") + "| Fetch " + target.PeerID[:8])
	f.dial_func(target)
	f.fetch_ch <- fetchEntry{
		world:       world,
		ANDIdentity: target.ANDIdentity,
		fwd:         fwd,
	}
}

type peerCloseEntry struct {
	peerID string
	done   chan bool
}
type peerQueryEntry struct {
	peerID string
	result chan ani.IAbyssPeer
}

// PeerFetcher calles and.World.FetchReturn
type PeerFetcher struct {
	ctx        context.Context
	ctx_cancel context.CancelFunc

	FetchQueue *FetchQueue

	peer_ch           chan ani.IAbyssPeer
	peer_close_ch     chan *peerCloseEntry
	peer_query_ch     chan *peerQueryEntry
	closing_world_ch  chan *and.World
	peers             map[string]ani.IAbyssPeer
	and_fetch_pending map[string][]fetchEntry // PeerID -> entries

	done chan bool
}

func NewPeerFetcher(
	ctx context.Context,
	dial_func func(and.ANDFullPeerSessionInfo),
) *PeerFetcher {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &PeerFetcher{
		ctx:        inner_ctx,
		ctx_cancel: cancel,

		FetchQueue: &FetchQueue{
			fetch_ch:  make(chan fetchEntry, 32),
			dial_func: dial_func,
		},

		peer_ch:           make(chan ani.IAbyssPeer, 32),
		peer_close_ch:     make(chan *peerCloseEntry, 32),
		peer_query_ch:     make(chan *peerQueryEntry, 32),
		closing_world_ch:  make(chan *and.World, 32),
		peers:             make(map[string]ani.IAbyssPeer),
		and_fetch_pending: make(map[string][]fetchEntry),

		done: make(chan bool, 1),
	}
	go result.work()
	return result
}

func (f *PeerFetcher) work() {
	for {
		select {
		case <-f.ctx.Done():
			f.done <- true
			return
		case fetch := <-f.FetchQueue.fetch_ch:
			f.onFetch(fetch)
		case peer := <-f.peer_ch:
			f.onPeer(peer)
		case peer_close := <-f.peer_close_ch:
			delete(f.peers, peer_close.peerID)
			peer_close.done <- true
		case peer_query := <-f.peer_query_ch:
			peer, ok := f.peers[peer_query.peerID]
			if ok {
				peer_query.result <- peer
			} else {
				close(peer_query.result)
			}
		case world := <-f.closing_world_ch:
			f.onWorldClose(world)
		}
	}
}

func (f *PeerFetcher) onFetch(fetch fetchEntry) {
	if peer, ok := f.peers[fetch.PeerID]; ok {
		fetch.world.FetchReturn(
			and.ANDPeerSession{
				Peer:      peer,
				SessionID: fetch.SessionID,
			},
			fetch.fwd,
		)
		return
	}

	rem, ok := f.and_fetch_pending[fetch.PeerID]
	if ok {
		f.and_fetch_pending[fetch.PeerID] = append(rem, fetch)
	} else {
		f.and_fetch_pending[fetch.PeerID] = []fetchEntry{fetch}
	}
}
func (f *PeerFetcher) onPeer(peer ani.IAbyssPeer) {
	fmt.Println(time.Now().Format("15:04:05.00000") + "| Fetcher: Peer added: " + peer.ID()[:8])
	pending_fetches, ok := f.and_fetch_pending[peer.ID()]
	if ok {
		for _, fetch := range pending_fetches {
			fetch.world.FetchReturn(
				and.ANDPeerSession{
					Peer:      peer,
					SessionID: fetch.SessionID,
				},
				fetch.fwd,
			)
		}
		delete(f.and_fetch_pending, peer.ID())
	}

	f.peers[peer.ID()] = peer
}
func (f *PeerFetcher) onWorldClose(world *and.World) {
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

func (f *PeerFetcher) AddPeer(peer ani.IAbyssPeer) {
	f.peer_ch <- peer
}

// RemovePeer is synchronous.
// TODO: let PeerFetcher call and.World.Disconnect().
func (f *PeerFetcher) RemovePeer(peerID string) {
	done := make(chan bool)
	f.peer_close_ch <- &peerCloseEntry{
		peerID: peerID,
		done:   done,
	}
	<-done
}

func (f *PeerFetcher) QueryPeer(peerID string) (ani.IAbyssPeer, bool) {
	result := make(chan ani.IAbyssPeer)
	f.peer_query_ch <- &peerQueryEntry{
		peerID: peerID,
		result: result,
	}
	retval, ok := <-result
	return retval, ok
}

func (f *PeerFetcher) RemoveWorld(world *and.World) {
	f.closing_world_ch <- world
}

func (f *PeerFetcher) Close() {
	f.ctx_cancel()
	<-f.done
}
