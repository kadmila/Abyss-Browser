package and

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

// TODO: reporter (side effect logger for malicious peer behavior)

// World is a state machine for a world and its member/related peers.
// Removing join target from a world breakes it, so be careful.
// A world must be externally locked, using the embedded sync.Mutex.
// This gives better control over call and event synchronization for the host.
type World struct {
	o              *AND                                   //origin
	mtx            sync.Mutex                             // lock for the world state.
	WSID           uuid.UUID                              // local world session id
	timestamp      time.Time                              // local world session creation timestamp
	join_target    string                                 // (when constructed with Join) join target peer ID
	env_url        string                                 // (when constructed with Open, or Join accepted) environmental content URL.
	entries        map[ANDIdentity]*peerWorldSessionState // key: id, value: peer states
	callback_timer *ANDTimer
	ctx            context.Context
	ctx_cancel     context.CancelFunc
	done           chan bool // closed when the world is closed.
}

func (w *World) Members() []*peerWorldSessionState {
	return functional.Filter_MtS_ok(w.entries, func(e *peerWorldSessionState) (*peerWorldSessionState, bool) {
		return e, e.state == WS_MEM
	})
}

func newWorld_Open(ctx context.Context, events ds.Queue, origin *AND, env_url string) *World {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &World{
		o:              origin,
		WSID:           uuid.New(),
		timestamp:      time.Now(),
		join_target:    "",
		env_url:        env_url,
		entries:        make(map[ANDIdentity]*peerWorldSessionState),
		callback_timer: NewANDTimer(),
		ctx:            inner_ctx,
		ctx_cancel:     cancel,
	}
	events.Push(&EANDWorldEnter{
		World: result,
		URL:   env_url,
	})
	go result.worker()
	return result
}

func newWorld_Join(ctx context.Context, origin *AND, target ani.IAbyssPeer, path string) (*World, error) {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &World{
		o:              origin,
		WSID:           uuid.New(),
		timestamp:      time.Now(),
		join_target:    target.ID(),
		env_url:        "",
		entries:        make(map[ANDIdentity]*peerWorldSessionState),
		callback_timer: NewANDTimer(),
		ctx:            inner_ctx,
		ctx_cancel:     cancel,
	}
	err := result.sendJN(target, path)
	if err != nil {
		return nil, err
	}
	go result.worker()
	return result, nil
}

func (w *World) Close() {
	w.broadcastRST(JNC_CLOSED, JNM_CLOSED)

	w.ctx_cancel()
	w.callback_timer.Stop()
	<-w.done
}

// worker handles background works for the world, such as timer events. It must be called in a separate goroutine for each world.
func (w *World) worker() {
	for {
		select {
		case <-w.ctx.Done():
			w.done <- true
			return
		case <-w.callback_timer.C:
			w.TimerExpire()
		}
	}
}

func (w *World) TimerExpire() {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	w.broadcastSJN()
}

// IsExposable checks if the world joining procedure is finished and the world information is set.
func (w *World) IsExposable() bool {
	return w.env_url != ""
}

func (w *World) finalizeMember(events ds.Queue, subject ANDPeerSession, fwd bool) {
	w.entries[subject.ANDIdentity()] = &peerWorldSessionState{
		ANDPeerSession: subject,
		state:          WS_MEM,
		fwd:            fwd,
		cnt:            0,
	}

}

func (w *World) acceptRemoteMember(events ds.Queue, member_info ANDFullPeerSessionInfo, fwd bool) {
	entry, ok := w.entries[member_info.ANDIdentity]
	if !ok {
		events.Push(&EANDPeerRequest{
			World:                      w,
			PeerID:                     member_info.PeerID,
			RootCertificateDer:         member_info.RootCertificateDer,
			HandshakeKeyCertificateDer: member_info.HandshakeKeyCertificateDer,
		})
	} else {
		w.sendMEM(entry.ANDPeerSession)
		w.finalizeMember(events, entry.ANDPeerSession, false)
	}
}

func (w *World) closeEntry(events ds.Queue, entry *peerWorldSessionState) {
	if entry.state == WS_MEM {
		//TODO: reschedule timer
	}
	delete(w.entries, entry.ANDIdentity())
}

// mustBeMemberCheck can only be used as a barrier for handling a message that must be sent from a member.
func (w *World) mustBeMemberCheck(events ds.Queue, peer_session ANDPeerSession) (*peerWorldSessionState, bool) {
	entry, ok := w.entries[peer_session.ANDIdentity()]
	if !ok {
		return nil, false
	}

	if entry.state != WS_MEM {
		// exists, but not a member. This is a sign of peer failure.
		w.sendRST(entry.ANDPeerSession, JNC_INVALID_STATES, JNM_INVALID_STATES)
		w.closeEntry(events, entry)
		return nil, false
	}

	return entry, true
}

func (w *World) JN(events ds.Queue, peer_session ANDPeerSession) {
	entry, ok := w.entries[peer_session.ANDIdentity()]
	if ok {
		w.sendRST(entry.ANDPeerSession, JNC_INVALID_STATES, JNM_INVALID_STATES)
		w.closeEntry(events, entry)
		return
	}
	w.sendJOK_JNI(peer_session)
	w.finalizeMember(events, peer_session, false)
}

func (w *World) JOK(events ds.Queue, peer_session ANDPeerSession, world_url string, member_infos []ANDFullPeerSessionInfo) {
	if w.join_target != peer_session.Peer.ID() {
		if entry, ok := w.entries[peer_session.ANDIdentity()]; ok {
			w.sendRST(entry.ANDPeerSession, JNC_INVALID_STATES, JNM_INVALID_STATES)
			w.closeEntry(events, entry)
			return
		}
	}

	w.finalizeMember(events, peer_session, false)
	for _, member_info := range member_infos {
		w.acceptRemoteMember(events, member_info, false)
	}
	w.join_target = ""
}

func (w *World) JNI(events ds.Queue, peer_session ANDPeerSession, member_info ANDFullPeerSessionInfo) {
	// only the members can send JNI.
	_, ok := w.mustBeMemberCheck(events, peer_session)
	if !ok {
		return
	}

	w.acceptRemoteMember(events, member_info, true)
}

func (w *World) MEM(events ds.Queue, peer_session ANDPeerSession, fwd bool) {
	// only malicious case - join target sending MEM.
	if w.join_target == peer_session.Peer.ID() {
		// join process corrupted
		w.sendRST_Direct(peer_session, JNC_INVALID_STATES, JNM_INVALID_STATES)
		events.Push(&EANDWorldLeave{
			World:   w,
			Code:    JNC_INVALID_STATES,
			Message: JNM_INVALID_STATES,
		})
		w.join_target = ""
		return
	}

	entry, ok := w.entries[peer_session.ANDIdentity()]
	if ok {
		if entry.state == WS_NOTISENT {
			w.finalizeMember(events, peer_session, fwd)
		}
	} else {
		w.entries[peer_session.ANDIdentity()] = &peerWorldSessionState{
			ANDPeerSession: peer_session,
			state:          WS_NOTIRCVD,
			fwd:            fwd,
			cnt:            0,
		}
	}
}

func (w *World) FetchReturn(events ds.Queue, peer_session ANDPeerSession) {
	if _, ok := w.entries[peer_session.ANDIdentity()]; !ok {
		w.sendMEM(peer_session)
	}
}

func (w *World) SJN(events ds.Queue, peer_session ANDPeerSession, member_infos []ANDIdentity) {
	entry, ok := w.mustBeMemberCheck(events, peer_session)
	if !ok {
		return
	}

	missing_members := functional.Filter_ok(member_infos, func(e ANDIdentity) (ANDIdentity, bool) {
		if e.PeerID == w.o.local_id {
			// exclude self
			return e, false
		}
		r_sjd, ok := w.entries[e]
		if !ok {
			// peer not found
			return e, true
		}

		// peer with corresponding session exists.
		if r_sjd.fwd && r_sjd.state == WS_MEM {
			r_sjd.cnt++
			if r_sjd.cnt >= 3 {
				r_sjd.fwd = false
			}
		}
		return e, false
	})

	if len(missing_members) != 0 {
		w.sendCRR(entry.ANDPeerSession, missing_members)
	}
}

func (w *World) CRR(events ds.Queue, peer_session ANDPeerSession, member_infos []ANDIdentity) {
	sender, ok := w.mustBeMemberCheck(events, peer_session)
	if !ok {
		return
	}

	for _, mem_info := range member_infos {
		entry, ok := w.entries[mem_info]
		if !ok || entry.state != WS_MEM {
			continue
		}
		w.sendJNI(sender.ANDPeerSession, entry.ANDPeerSession)
		w.sendJNI(entry.ANDPeerSession, sender.ANDPeerSession)
	}
}

func (w *World) RST(events ds.Queue, peer_session ANDPeerSession) {
	entry, ok := w.entries[peer_session.Peer.ID()]
	if !ok || entry.SessionID != peer_session.SessionID {
		return
	}

	w.removeEntrySilent(events, entry)
}

func (w *World) ObjectAppend(peer_session_identities []ANDIdentity, objects []ObjectInfo) {
	for _, peer_session_identity := range peer_session_identities {
		entry, ok := w.entries[peer_session_identity]
		if !ok {
			// entry deleted
			break
		}
		w.sendSOA(entry, objects)
	}
}

func (w *World) ObjectDelete(peer_session_identities []ANDIdentity, objectIDs []uuid.UUID) {
	for _, peer_session_identity := range peer_session_identities {
		entry, ok := w.entries[peer_session_identity]
		if !ok {
			// entry deleted
			break
		}
		w.sendSOD(entry, objectIDs)
	}
}

func (w *World) SOA(events ds.Queue, peer_session ANDPeerSession, objects []ObjectInfo) {
	_, ok := w.mustBeMemberCheck(events, peer_session)
	if !ok {
		return
	}

	events.Push(&EANDObjectAppend{
		World:          w,
		ANDPeerSession: peer_session,
		Objects:        objects,
	})
}

func (w *World) SOD(events ds.Queue, peer_session ANDPeerSession, objectIDs []uuid.UUID) {
	_, ok := w.mustBeMemberCheck(events, peer_session)
	if !ok {
		return
	}

	events.Push(&EANDObjectDelete{
		World:          w,
		ANDPeerSession: peer_session,
		ObjectIDs:      objectIDs,
	})
}
