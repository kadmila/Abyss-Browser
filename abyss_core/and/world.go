package and

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/config"
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
	join_path      string                                 // (when constructed with Join) world request path
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
		join_path:      "",
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
	return result
}

func newWorld_Join(ctx context.Context, origin *AND, target ani.IAbyssPeer, path string) (*World, error) {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &World{
		o:              origin,
		WSID:           uuid.New(),
		timestamp:      time.Now(),
		join_target:    target.ID(),
		join_path:      path,
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
	return result, nil
}

func (w *World) Close() {
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

	// At this point, the timer is consumed.

	//TODO
}

// IsExposable checks if the world joining procedure is finished and the world information is set.
func (w *World) IsExposable() bool {
	return w.env_url != ""
}

func (w *World) finalizeMember(events ds.Queue, subject ANDPeerSession, fwd bool) {
	w.entries[subject.ANDIdentity()] = &peerWorldSessionState{
		state:     WS_MEM,
		Peer:      subject.Peer,
		SessionID: subject.SessionID,
		fwd:       fwd,
		cnt:       0,
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
		w.sendRST(entry, JNC_INVALID_STATES, JNM_INVALID_STATES)
		w.closeEntry(events, entry)
		return nil, false
	}

	return entry, true
}

func (w *World) JN(events ds.Queue, peer_session ANDPeerSession) {
	entry, ok := w.entries[peer_session.ANDIdentity()]
	if ok {
		w.sendRST(entry, JNC_INVALID_STATES, JNM_INVALID_STATES)
		w.closeEntry(events, entry)
		return
	}

	new_entry := &peerWorldSessionState{
		state: WS_JN,
	}

	entry.state = WS_JN
	events.Push(&EANDSessionRequest{
		World:          w,
		ANDPeerSession: peer_session,
	})
	entry.is_session_requested = true
}

func (w *World) JOK(events ds.Queue, peer_session ANDPeerSession, timestamp time.Time, world_url string, member_infos []ANDFullPeerSessionInfo) {
	if w.is_closed {
		return
	}

	// normal case
	if w.join_target != nil && w.join_target.Peer == peer_session.Peer {
		first_member := w.join_target

		w.join_target = nil
		w.join_path = ""
		w.url = world_url

		first_member.state = WS_MEM
		w.member_count++
		first_member.SessionID = peer_session.SessionID
		first_member.TimeStamp = timestamp
		first_member.is_session_requested = true
		first_member.sjnp = true

		w.entries[first_member.PeerID] = first_member

		events.Push(&EANDWorldEnter{
			World: w,
			URL:   world_url,
		})
		events.Push(&EANDTimerRequest{
			World:    w,
			Duration: time.Millisecond * INITIAL_WORLD_TIMER,
		})
		events.Push(&EANDSessionReady{
			World:          w,
			ANDPeerSession: first_member.ANDPeerSession(),
		})

		for _, mem_info := range member_infos {
			w.jni_mems(events, mem_info, true)
		}
		return
	}

	// faulty cases
	if entry, ok := w.entries[peer_session.Peer.ID()]; ok {
		w.sendRST_Direct(peer_session, JNC_INVALID_STATES, JNM_INVALID_STATES)
		w.removeEntry(events, entry, JNC_INVALID_STATES, JNM_INVALID_STATES)
		return
	}
	panic("JOK: World corrupted")
}

func (w *World) JDN(events ds.Queue, peer ani.IAbyssPeer, code int, message string) {
	if w.is_closed {
		return
	}

	// normal case
	if w.join_target != nil && w.join_target.Peer == peer {
		events.Push(&EANDWorldLeave{
			World:   w,
			Code:    code,
			Message: message,
		})
		w.is_closed = true
		return
	}

	// faulty cases
	if entry, ok := w.entries[peer.ID()]; ok {
		w.removeEntry(events, entry, JNC_INVALID_STATES, JNM_INVALID_STATES)
		return
	}
	panic("JDN: World corrupted")
}

func (w *World) JNI(events ds.Queue, peer_session ANDPeerSession, member_info ANDFullPeerSessionInfo) {
	if w.is_closed {
		return
	}

	// only the members can send JNI.
	_, ok := w.mustBeMemberCheck(events, peer_session)
	if !ok {
		return
	}

	w.jni_mems(events, member_info, false)
}

func (w *World) jni_mems(events ds.Queue, mem_info ANDFullPeerSessionInfo, sjnp bool) {
	config.IF_DEBUG(func() {
		if w.join_target != nil {
			panic("jni_mems: world is joining")
		}
	})

	mem_entry, ok := w.entries[mem_info.PeerID]
	if !ok {
		w.entries[mem_info.PeerID] = &peerWorldSessionState{
			state:     WS_DC_JNI,
			PeerID:    mem_info.PeerID,
			SessionID: mem_info.SessionID,
			TimeStamp: mem_info.TimeStamp,
			sjnp:      sjnp,
		}
		events.Push(&EANDPeerRequest{
			World:                      w,
			PeerID:                     mem_info.PeerID,
			AddressCandidates:          mem_info.AddressCandidates,
			RootCertificateDer:         mem_info.RootCertificateDer,
			HandshakeKeyCertificateDer: mem_info.HandshakeKeyCertificateDer,
		})
		return
	}

	// entry exists.
	if w.tryOverwritePeerSession(events, mem_entry, mem_info.SessionID, mem_info.TimeStamp) {
		if mem_entry.Peer == nil {
			mem_entry.state = WS_DC_JNI
			mem_entry.sjnp = sjnp
			events.Push(&EANDPeerRequest{
				World:                      w,
				PeerID:                     mem_info.PeerID,
				AddressCandidates:          mem_info.AddressCandidates,
				RootCertificateDer:         mem_info.RootCertificateDer,
				HandshakeKeyCertificateDer: mem_info.HandshakeKeyCertificateDer,
			})
		} else {
			mem_entry.state = WS_JNI
			mem_entry.sjnp = sjnp
			events.Push(&EANDSessionRequest{
				World:          w,
				ANDPeerSession: mem_entry.ANDPeerSession(),
			})
			mem_entry.is_session_requested = true
		}
	}
}

func (w *World) MEM(events ds.Queue, peer_session ANDPeerSession, timestamp time.Time) {
	if w.is_closed {
		return
	}

	// MEM is onemost simple but tricky message. Any peer can send MEM, and
	// MEM can overrun old session; and it is forced, as it is from the peer.

	// only malicious case - join target sending MEM.
	if w.join_target != nil && w.join_target.Peer == peer_session.Peer {
		// join process corrupted
		events.Push(&EANDWorldLeave{
			World:   w,
			Code:    JNC_INVALID_STATES,
			Message: JNM_INVALID_STATES,
		})
		w.is_closed = true
		return
	}

	entry := w.entries[peer_session.Peer.ID()]
	if entry.SessionID != peer_session.SessionID {
		// MEM for unexpected session, or
		// no previous session information exists.
		if w.tryOverwritePeerSession(events, entry, peer_session.SessionID, timestamp) {
			// re-configure state, no further action can be taken.
			entry.state = WS_RMEM_NJNI
			return
		} else {
			// reset this MEM.
			w.sendRST_Direct(peer_session, JNC_OVERRUN, JNM_OVERRUN)
			return
		}
	}
	// Confirmed: This MEM is from an expected peer.

	switch entry.state {
	case WS_DC_JNI, WS_CC:
		panic("impossible")
	case WS_JN:
		// Joined and also sent MEM.
		// This is a failure, because
		// 1) joining session does not have a member.
		// 2) MEM can only be fired for JNI.
		// 3) JNI can only be sent from a member.
		// Therefore, a joining peer must not send MEM.
		w.sendRST_Direct(peer_session, JNC_INVALID_STATES, JNM_INVALID_STATES)
		w.removeEntry(events, entry, JNC_INVALID_STATES, JNM_INVALID_STATES)
		return
	case WS_RMEM_NJNI, WS_RMEM, WS_MEM:
		// very weird case - session check passed, duplicate MEM.
		// There is absolutely no need for this.
		w.removeEntry(events, entry, JNC_INVALID_STATES, JNM_INVALID_STATES)
		return
	case WS_JNI:
		entry.state = WS_RMEM
	case WS_TMEM:
		entry.state = WS_MEM
		w.member_count++
		events.Push(&EANDSessionReady{
			World:          w,
			ANDPeerSession: peer_session,
		})
	}
}

func (w *World) AcceptSession(events ds.Queue, peer_session_identity ANDIdentity) {
	if w.is_closed {
		return
	}

	entry, ok := w.entries[peer_session_identity.PeerID]
	if !ok {
		// entry deleted
		return
	}
	peer_session := entry.ANDPeerSession()

	if entry.SessionID != peer_session_identity.SessionID {
		// session expired
		return
	}
	// Confirmed: corresponding peer session exists.

	switch entry.state {
	case WS_JN:
		w.sendJOK_JNI(entry)
		entry.state = WS_MEM
		w.member_count++
		events.Push(&EANDSessionReady{
			World:          w,
			ANDPeerSession: peer_session,
		})
	case WS_JNI:
		w.sendMEM(entry)
		entry.state = WS_TMEM
	case WS_RMEM:
		w.sendMEM(entry)
		entry.state = WS_MEM
		w.member_count++
		events.Push(&EANDSessionReady{
			World:          w,
			ANDPeerSession: peer_session,
		})
	default:
		panic("invalied peer state for AcceptSession")
	}
}

func (w *World) DeclineSession(events ds.Queue, peer_session_identity ANDIdentity, code int, message string) {
	if w.is_closed {
		return
	}

	entry, ok := w.entries[peer_session_identity.PeerID]
	if !ok {
		// entry deleted
		return
	}

	if entry.SessionID != peer_session_identity.SessionID {
		// session expired
		return
	}
	// Confirmed: corresponding peer session exists.

	config.IF_DEBUG(func() {
		if entry.state != WS_JN && entry.state != WS_JNI && entry.state != WS_RMEM {
			panic("invalied peer state for DeclineSession")
		}
	})

	w.removeEntry(events, entry, JNC_REJECTED, JNM_REJECTED)
}

func (w *World) ObjectAppend(peer_session_identities []ANDIdentity, objects []ObjectInfo) {
	if w.is_closed {
		return
	}

	for _, peer_session_identity := range peer_session_identities {
		entry, ok := w.entries[peer_session_identity.PeerID]
		if !ok {
			// entry deleted
			break
		}
		if entry.SessionID != peer_session_identity.SessionID {
			// session expired
			break
		}
		w.sendSOA(entry, objects)
	}
}

func (w *World) ObjectDelete(peer_session_identities []ANDIdentity, objectIDs []uuid.UUID) {
	if w.is_closed {
		return
	}

	for _, peer_session_identity := range peer_session_identities {
		entry, ok := w.entries[peer_session_identity.PeerID]
		if !ok {
			// entry deleted
			break
		}
		if entry.SessionID != peer_session_identity.SessionID {
			// session expired
			break
		}
		w.sendSOD(entry, objectIDs)
	}
}

func (w *World) TimerExpire(events ds.Queue) {
	if w.is_closed {
		return
	}

	w.broadcastSJN()

	duration := 500 + int(w.weibull_dist.Rand()*float64(200*(w.member_count+1)))
	events.Push(&EANDTimerRequest{
		World:    w,
		Duration: time.Millisecond * time.Duration(duration),
	})
}

func (w *World) SJN(events ds.Queue, peer_session ANDPeerSession, member_infos []ANDIdentity) {
	if w.is_closed {
		return
	}

	entry, ok := w.mustBeMemberCheck(events, peer_session)
	if !ok {
		return
	}

	missing_members := functional.Filter_ok(member_infos, func(e ANDIdentity) (ANDIdentity, bool) {
		if e.PeerID == w.o.local_id {
			// exclude self
			return e, false
		}
		entry, ok := w.entries[e.PeerID]
		if !ok {
			// peer not found
			return e, true
		}
		if entry.SessionID != e.SessionID {
			// no information for the current session
			return e, true
		}
		// peer with corresponding session exists.
		switch entry.state {
		case WS_DC_JNI, WS_CC, WS_RMEM_NJNI:
			// requires CRR
			return e, true
		case WS_MEM:
			entry.sjnc++
			config.IF_DEBUG(func() {
				if entry.sjnc > 5 {
					panic("too many SJN")
				}
			})
			return e, false
		default:
			// not a member, but don't bother sending CRR
			return e, false
		}
	})

	if len(missing_members) != 0 {
		w.sendCRR(entry, missing_members)
	}
}

func (w *World) CRR(events ds.Queue, peer_session ANDPeerSession, member_infos []ANDIdentity) {
	if w.is_closed {
		return
	}

	sender, ok := w.mustBeMemberCheck(events, peer_session)
	if !ok {
		return
	}

	for _, mem_info := range member_infos {
		entry, ok := w.entries[mem_info.PeerID]
		if !ok || entry.SessionID != mem_info.SessionID || entry.state != WS_MEM {
			continue
		}
		w.sendJNI(sender, entry)
		w.sendJNI(entry, sender)
	}
}

func (w *World) SOA(events ds.Queue, peer_session ANDPeerSession, objects []ObjectInfo) {
	if w.is_closed {
		return
	}

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
	if w.is_closed {
		return
	}

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

func (w *World) RST(events ds.Queue, peer_session ANDPeerSession) {
	if w.is_closed {
		return
	}

	entry, ok := w.entries[peer_session.Peer.ID()]
	if !ok || entry.SessionID != peer_session.SessionID {
		return
	}

	w.removeEntrySilent(events, entry)
}

// We don't verify everything like we did for the other messages; we trust the caller.
// PeerDisconnected should raise EANDPeerDiscoard event for the peer.
func (w *World) PeerDisconnected(events ds.Queue, peer_id string) {
	if w.is_closed {
		return
	}

	if w.join_target != nil && w.join_target.PeerID == peer_id {
		events.Push(&EANDWorldLeave{
			World:   w,
			Code:    JNC_DISCONNECTED,
			Message: JNM_DISCONNECTED,
		})
		w.is_closed = true
		return
	}

	w.removeEntrySilent(events, w.entries[peer_id])
}

// Close does not take events argument, as the world is closed immediately.
// no events are meaningful afterwards.
func (w *World) Close() {
	if w.is_closed {
		return
	}

	w.broadcastRST(JNC_CLOSED, JNM_CLOSED)
	w.is_closed = true
}
