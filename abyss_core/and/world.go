package and

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/infchan"
)

//// Deadlock risk
// Due to the current design limitation in ahost.peer_fetcher.go,
// All paths in and.World MUST NOT contain any blocking call (including writing to channel)
// A world should FORCEFULLY close if it cannot continue without waiting a blocking call.
// We consider this as a failure due to the limited hardware resource.
//
// This requires non-blocking Write (TODO)
////

// TODO: reporter (side effect logger for malicious peer behavior)

type IFetcher interface {
	Fetch(
		world *World,
		target ANDFullPeerSessionInfo,
	)
}

type World struct {
	mtx sync.Mutex // lock for the world state.

	fetcher  IFetcher
	event_ch *infchan.InfiniteChan[any] // target origin event channel

	localID     string
	WSID        uuid.UUID                              // local world session id
	join_target string                                 // (when constructed with Join) join target peer ID
	env_url     string                                 // (when constructed with Open, or Join accepted) environmental content URL.
	entries     map[ANDIdentity]*peerWorldSessionState // key: id, value: peer states

	trickle *TrickleWorker

	ctx        context.Context
	ctx_cancel context.CancelFunc
}

func NewWorld_Open(ctx context.Context, fetcher IFetcher, event_ch *infchan.InfiniteChan[any], localID string, env_url string) (*World, error) {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &World{
		fetcher:  fetcher,
		event_ch: event_ch,

		localID:     localID,
		WSID:        uuid.New(),
		join_target: "",
		env_url:     env_url,
		entries:     make(map[ANDIdentity]*peerWorldSessionState),

		trickle: NewTrickleWorker(inner_ctx),

		ctx:        inner_ctx,
		ctx_cancel: cancel,
	}
	result.event_ch.In <- &EANDWorldEnter{
		WSID: result.WSID,
		URL:  env_url,
	}
	return result, nil
}

func NewWorld_Join(ctx context.Context, fetcher IFetcher, event_ch *infchan.InfiniteChan[any], localID string, target ani.IAbyssPeer, path string) (*World, error) {
	inner_ctx, cancel := context.WithCancel(ctx)
	result := &World{
		fetcher:  fetcher,
		event_ch: event_ch,

		localID:     localID,
		WSID:        uuid.New(),
		join_target: target.ID(),
		env_url:     "",
		entries:     make(map[ANDIdentity]*peerWorldSessionState),

		trickle: NewTrickleWorker(inner_ctx),

		ctx:        inner_ctx,
		ctx_cancel: cancel,
	}
	err := result.sendJN(target, path)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (w *World) Close() {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	w.broadcastRST(JNC_CLOSED, JNM_CLOSED)
	w.cleanup()
}

// cleanup forcefully clears world, unabling it to produce further events.
func (w *World) cleanup() {
	w.join_target = ""
	w.env_url = ""
	w.entries = make(map[ANDIdentity]*peerWorldSessionState)

	// We don't check error.
	w.event_ch.In <- &EANDWorldLeave{
		WSID:    w.WSID,
		Code:    JNC_CLOSED,
		Message: JNM_CLOSED,
	}

	w.ctx_cancel()
}

// IsActive checks if the world is active and ready for use.
func (w *World) IsActive() bool {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	return w.env_url != ""
}

func (w *World) TrickleTimeout(subject_identity ANDIdentity) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	entry, ok := w.entries[subject_identity]
	if ok && entry.state == WS_MEM && entry.cnt < 3 {
		w.broadcastSJN(subject_identity)
	}
}

func (w *World) finalizeMember(subject ANDPeerSession) {
	subject_identity := subject.ANDIdentity()
	w.entries[subject_identity] = &peerWorldSessionState{
		ANDPeerSession: subject,
		state:          WS_MEM,
		cnt:            0,
	}
	w.event_ch.In <- &EANDSessionReady{
		WSID:        w.WSID,
		ANDIdentity: subject_identity,
	}
	w.trickle.Add(subject_identity, func() { w.TrickleTimeout(subject_identity) })
}

func (w *World) acceptRemoteMember(member_info ANDFullPeerSessionInfo) {
	if member_info.PeerID == w.localID {
		return
	}

	entry, ok := w.entries[member_info.ANDIdentity]
	if !ok {
		w.fetcher.Fetch(w, member_info)
	} else if entry.state == WS_NOTIRCVD {
		w.sendMEM(entry.ANDPeerSession)
		w.finalizeMember(entry.ANDPeerSession)
	}
}

func (w *World) closeEntry(entry *peerWorldSessionState) {
	if entry.state == WS_MEM {
		w.trickle.Remove(entry.ANDIdentity())
		w.event_ch.In <- &EANDSessionClose{
			WSID:        w.WSID,
			ANDIdentity: entry.ANDIdentity(),
		}
	}
	delete(w.entries, entry.ANDIdentity())
}

// mustBeMemberGetEntry can only be used as a barrier for handling a message that must be sent from a member.
func (w *World) mustBeMemberGetEntry(peer_session ANDPeerSession) (*peerWorldSessionState, bool) {
	entry, ok := w.entries[peer_session.ANDIdentity()]
	if !ok {
		return nil, false
	}

	if entry.state != WS_MEM {
		// exists, but not a member. This is a sign of peer failure.
		w.sendRST(entry.ANDPeerSession, JNC_INVALID_STATES, JNM_INVALID_STATES)
		w.closeEntry(entry)
		return nil, false
	}

	return entry, true
}

func (w *World) JN(peer_session ANDPeerSession) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	entry, ok := w.entries[peer_session.ANDIdentity()]
	if ok {
		w.sendRST(entry.ANDPeerSession, JNC_INVALID_STATES, JNM_INVALID_STATES)
		w.closeEntry(entry)
		return
	}
	w.sendJOK_JNI(peer_session)
	w.finalizeMember(peer_session)
}

func (w *World) JOK(peer_session ANDPeerSession, env_url string, member_infos []ANDFullPeerSessionInfo) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	if w.join_target != peer_session.Peer.ID() {
		if entry, ok := w.entries[peer_session.ANDIdentity()]; ok {
			w.sendRST(entry.ANDPeerSession, JNC_INVALID_STATES, JNM_INVALID_STATES)
			w.closeEntry(entry)
			return
		}
	}
	w.event_ch.In <- &EANDWorldEnter{
		WSID: w.WSID,
		URL:  env_url,
	}

	w.finalizeMember(peer_session)
	for _, member_info := range member_infos {
		w.acceptRemoteMember(member_info)
	}
	w.join_target = ""
	w.env_url = env_url
}

func (w *World) JNI(peer_session ANDPeerSession, member_info ANDFullPeerSessionInfo) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	// only the members can send JNI.
	_, ok := w.mustBeMemberGetEntry(peer_session)
	if !ok {
		return
	}

	w.acceptRemoteMember(member_info)
}

func (w *World) MEM(peer_session ANDPeerSession) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	entry, ok := w.entries[peer_session.ANDIdentity()]
	if !ok {
		w.entries[peer_session.ANDIdentity()] = &peerWorldSessionState{
			ANDPeerSession: peer_session,
			state:          WS_NOTIRCVD,
			cnt:            0,
		}
	} else if entry.state == WS_NOTISENT {
		w.finalizeMember(peer_session)
	}
}

func (w *World) FetchReturn(peer_session ANDPeerSession) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	entry, ok := w.entries[peer_session.ANDIdentity()]
	if !ok {
		w.sendMEM(peer_session)
		w.entries[peer_session.ANDIdentity()] = &peerWorldSessionState{
			ANDPeerSession: peer_session,
			state:          WS_NOTISENT,
			cnt:            0,
		}
	} else if entry.state == WS_NOTIRCVD {
		w.sendMEM(peer_session)
		w.finalizeMember(peer_session)
	}
}

func (w *World) SJN(peer_session ANDPeerSession, member_infos []ANDIdentity) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	entry, ok := w.mustBeMemberGetEntry(peer_session)
	if !ok {
		return
	}

	missing_members := functional.Filter_ok(member_infos, func(e ANDIdentity) (ANDIdentity, bool) {
		if e.PeerID == w.localID {
			// exclude self
			return e, false
		}
		r_sji, ok := w.entries[e]
		if !ok {
			// peer not found
			return e, true
		}

		// peer with corresponding session exists.
		if r_sji.state == WS_MEM {
			r_sji.cnt++
		}
		return e, false
	})

	if len(missing_members) != 0 {
		w.sendCRR(entry.ANDPeerSession, missing_members)
	}
}

func (w *World) CRR(peer_session ANDPeerSession, member_infos []ANDIdentity) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	sender, ok := w.mustBeMemberGetEntry(peer_session)
	if !ok {
		return
	}

	for _, mem_info := range member_infos {
		entry, ok := w.entries[mem_info]
		if !ok || entry.state != WS_MEM {
			continue
		}
		w.sendJNI(entry.ANDPeerSession, sender.ANDPeerSession, false)
		w.sendJNI(sender.ANDPeerSession, entry.ANDPeerSession, true)
	}
}

func (w *World) RST(peer_session ANDPeerSession) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	entry, ok := w.entries[peer_session.ANDIdentity()]
	if !ok {
		return
	}

	w.closeEntry(entry)
}

func (w *World) Disconnect(PeerID string) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	for _, entry := range w.entries {
		if entry.Peer.ID() == PeerID {
			w.closeEntry(entry)
		}
	}
}

func (w *World) ObjectAppend(peer_session_identities []ANDIdentity, objects []ObjectInfo) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	for _, peer_session_identity := range peer_session_identities {
		entry, ok := w.entries[peer_session_identity]
		if !ok {
			// entry deleted
			break
		}
		w.sendSOA(entry.ANDPeerSession, objects)
	}
}

func (w *World) ObjectDelete(peer_session_identities []ANDIdentity, objectIDs []uuid.UUID) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	for _, peer_session_identity := range peer_session_identities {
		entry, ok := w.entries[peer_session_identity]
		if !ok {
			// entry deleted
			break
		}
		w.sendSOD(entry.ANDPeerSession, objectIDs)
	}
}

func (w *World) SOA(peer_session ANDPeerSession, objects []ObjectInfo) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	_, ok := w.mustBeMemberGetEntry(peer_session)
	if !ok {
		return
	}

	w.event_ch.In <- &EANDObjectAppend{
		WSID:        w.WSID,
		ANDIdentity: peer_session.ANDIdentity(),
		Objects:     objects,
	}
}

func (w *World) SOD(peer_session ANDPeerSession, objectIDs []uuid.UUID) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	_, ok := w.mustBeMemberGetEntry(peer_session)
	if !ok {
		return
	}

	w.event_ch.In <- &EANDObjectDelete{
		WSID:        w.WSID,
		ANDIdentity: peer_session.ANDIdentity(),
		ObjectIDs:   objectIDs,
	}
}
