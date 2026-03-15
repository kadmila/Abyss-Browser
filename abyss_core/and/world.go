package and

import (
	"sync"

	"github.com/google/uuid"

	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
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
		fwd bool,
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
}

func NewWorld_Open(fetcher IFetcher, event_ch *infchan.InfiniteChan[any], localID string, env_url string) (*World, error) {
	result := &World{
		fetcher:  fetcher,
		event_ch: event_ch,

		localID:     localID,
		WSID:        uuid.New(),
		join_target: "",
		env_url:     env_url,
		entries:     make(map[ANDIdentity]*peerWorldSessionState),
	}
	result.event_ch.In <- &EANDWorldEnter{
		WSID: result.WSID,
		URL:  env_url,
	}
	return result, nil
}

func NewWorld_Join(fetcher IFetcher, event_ch *infchan.InfiniteChan[any], localID string, target ani.IAbyssPeer, path string) (*World, error) {
	result := &World{
		fetcher:  fetcher,
		event_ch: event_ch,

		localID:     localID,
		WSID:        uuid.New(),
		join_target: target.ID(),
		env_url:     "",
		entries:     make(map[ANDIdentity]*peerWorldSessionState),
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
}

// IsActive checks if the world is active and ready for use.
func (w *World) IsActive() bool {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	return w.env_url != ""
}

func (w *World) finalizeMember(subject ANDPeerSession, fwd bool) {
	w.entries[subject.ANDIdentity()] = &peerWorldSessionState{
		ANDPeerSession: subject,
		state:          WS_MEM,
		fwd:            fwd,
		cnt:            0,
	}
	w.event_ch.In <- &EANDSessionReady{
		WSID:        w.WSID,
		ANDIdentity: subject.ANDIdentity(),
	}
}

func (w *World) acceptRemoteMember(member_info ANDFullPeerSessionInfo, fwd bool) {
	if member_info.PeerID == w.localID {
		return
	}

	entry, ok := w.entries[member_info.ANDIdentity]
	if !ok {
		w.fetcher.Fetch(w, member_info, fwd)
	} else if entry.state == WS_NOTIRCVD {
		w.sendMEM(entry.ANDPeerSession)
		w.finalizeMember(entry.ANDPeerSession, false)
	}
}

func (w *World) closeEntry(entry *peerWorldSessionState) {
	if entry.state == WS_MEM {
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
	w.finalizeMember(peer_session, false)
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

	w.finalizeMember(peer_session, false)
	for _, member_info := range member_infos {
		w.acceptRemoteMember(member_info, false)
	}
	w.join_target = ""
	w.env_url = env_url
}

func (w *World) JNI(peer_session ANDPeerSession, member_info ANDFullPeerSessionInfo, fwd bool) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	// only the members can send JNI.
	_, ok := w.mustBeMemberGetEntry(peer_session)
	if !ok {
		return
	}

	w.acceptRemoteMember(member_info, fwd)
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
		w.finalizeMember(peer_session, entry.fwd)
	}
}

func (w *World) FetchReturn(peer_session ANDPeerSession, fwd bool) {
	w.mtx.Lock()
	defer w.mtx.Unlock()

	entry, ok := w.entries[peer_session.ANDIdentity()]
	if !ok {
		w.sendMEM(peer_session)
		w.entries[peer_session.ANDIdentity()] = &peerWorldSessionState{
			ANDPeerSession: peer_session,
			state:          WS_NOTISENT,
			fwd:            fwd,
			cnt:            0,
		}
	} else if entry.state == WS_NOTIRCVD {
		w.sendMEM(peer_session)
		w.finalizeMember(peer_session, fwd)
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
