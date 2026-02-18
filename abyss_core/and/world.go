package and

import (
	"math/rand"
	"time"

	"github.com/google/uuid"
	"gonum.org/v1/gonum/stat/distuv"

	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/kadmila/Abyss-Browser/abyss_core/config"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/ds"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/functional"
)

// World is a state machine for a world and its member/related peers.
// Removing join target from a world breakes it, so be careful.
// A world must be externally locked, using the embedded sync.Mutex.
// This gives better control over call and event synchronization for the host.
type World struct {
	o *AND //origin

	weibull_dist *distuv.Weibull

	is_closed bool // this is set true after firing EANDWorldLeave.

	lsid         uuid.UUID                         // local world session id
	timestamp    time.Time                         // local world session creation timestamp
	join_target  *peerWorldSessionState            // (when constructed with Join) join target peer, turns null after firing EANDWorldEnter
	join_path    string                            // (when constructed with Join) world request path
	url          string                            // (when constructed with Open, or Join accepted) environmental content URL.
	entries      map[string]*peerWorldSessionState // key: id, value: peer states
	member_count int                               // the number of WS_MEM sessions
}

const INITIAL_WORLD_TIMER = 1000

func newWorld_Open(events ds.Queue, origin *AND, world_url string) *World {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	result := &World{
		o:            origin,
		weibull_dist: &distuv.Weibull{K: 2, Lambda: 2.0, Src: rng},
		lsid:         uuid.New(),
		timestamp:    time.Now(),
		join_target:  nil,
		join_path:    "",
		url:          world_url,
		entries:      make(map[string]*peerWorldSessionState),
	}
	events.Push(&EANDWorldEnter{
		World: result,
		URL:   world_url,
	})
	return result
}

func newWorld_Join(origin *AND, target ani.IAbyssPeer, path string) (*World, error) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	result := &World{
		o:            origin,
		weibull_dist: &distuv.Weibull{K: 2, Lambda: 2.0, Src: rng},
		lsid:         uuid.New(),
		timestamp:    time.Now(),
		join_target: &peerWorldSessionState{
			PeerID: target.ID(),
			Peer:   target,
		},
		join_path: path,
		url:       "",
		entries:   make(map[string]*peerWorldSessionState),
	}
	err := result.sendJN(result.join_target)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (w *World) SessionID() uuid.UUID {
	return w.lsid
}

func (w *World) CheckSanity() {
	if !config.DEBUG {
		return
	}

	if w.o == nil {
		panic("world origin nil")
	}
	if w.lsid == uuid.Nil {
		panic("world lsid nil")
	}
	if w.timestamp.After(time.Now()) {
		panic("invalid world timestamp")
	}
	// check member count
	mem_count := 0
	for _, entry := range w.entries {
		if entry.state == WS_MEM {
			mem_count++
		}
	}
	if mem_count != w.member_count {
		panic("mem count mismatch")
	}

	if w.join_target != nil {
		// joining
		if w.join_path == "" {
			panic("world join path nil")
		}
		if w.url != "" {
			panic("world url non-nil")
		}
		for id, entry := range w.entries {
			if id == "" {
				panic(entry.state.String() + " entry with nil id")
			}
			switch entry.state {
			case WS_DC_JNI:
				panic(entry.state.String() + " must not exist (no MEM)")
			case WS_CC:
				// expecting early MEM
				if id != entry.PeerID || id != entry.Peer.ID() {
					panic(entry.state.String() + " peer id mismatch")
				}
				if entry.SessionID != uuid.Nil {
					panic(entry.state.String() + " must have nil session id")
				}
				if !entry.TimeStamp.Equal(time.Time{}) {
					panic(entry.state.String() + " must have nil timestamp")
				}
				if entry.is_session_requested {
					panic(entry.state.String() + " is_session_requested true")
				}
			case WS_JN:
				panic("World too early to be exposed")
			case WS_RMEM_NJNI:
				// early MEM
				if id != entry.PeerID || id != entry.Peer.ID() {
					panic(entry.state.String() + " peer id mismatch")
				}
				if entry.SessionID != uuid.Nil {
					panic(entry.state.String() + " must have non-nil session id")
				}
				if entry.TimeStamp.Equal(time.Time{}) {
					panic(entry.state.String() + " must have non-nil timestamp")
				}
				if entry.is_session_requested {
					panic(entry.state.String() + " is_session_requested true")
				}
			case WS_JNI:
				panic(entry.state.String() + " must not exist (no MEM)")
			case WS_RMEM:
				panic(entry.state.String() + " must not exist (no JNI)")
			case WS_TMEM:
				panic(entry.state.String() + " must not exist (no JNI)")
			case WS_MEM:
				panic("MEM must not exist")
			default:
				panic(entry.state.String())
			}
		}
	} else {
		// working
		if w.join_path != "" {
			panic("world join path non-nil")
		}
		if w.url == "" {
			panic("world url nil")
		}
		for id, entry := range w.entries {
			if id == "" {
				panic(entry.state.String() + " entry with nil id")
			}
			switch entry.state {
			case WS_DC_JNI:
				if id != entry.PeerID {
					panic(entry.state.String() + " peer id mismatch")
				}
				if entry.Peer != nil {
					panic(entry.state.String() + " must have nil Peer")
				}
				if entry.SessionID == uuid.Nil {
					panic(entry.state.String() + " must have non nil session id")
				}
				if entry.TimeStamp.Equal(time.Time{}) {
					panic(entry.state.String() + " must have non nil TimeStamp")
				}
				if entry.is_session_requested {
					panic(entry.state.String() + " is_session_requested true")
				}
			case WS_CC:
				if id != entry.PeerID || id != entry.Peer.ID() {
					panic(entry.state.String() + " peer id mismatch")
				}
				if entry.SessionID != uuid.Nil {
					panic(entry.state.String() + " must have nil session id")
				}
				if !entry.TimeStamp.Equal(time.Time{}) {
					panic(entry.state.String() + " must have nil timestamp")
				}
				if entry.is_session_requested {
					panic(entry.state.String() + " is_session_requested true")
				}
			case WS_JN, WS_JNI, WS_RMEM, WS_TMEM, WS_MEM:
				if id != entry.PeerID || id != entry.Peer.ID() {
					panic(entry.state.String() + " peer id mismatch")
				}
				if entry.SessionID == uuid.Nil {
					panic(entry.state.String() + " must have non-nil session id")
				}
				if entry.TimeStamp.Equal(time.Time{}) {
					panic(entry.state.String() + " must have non-nil timestamp")
				}
				if !entry.is_session_requested {
					panic(entry.state.String() + " is_session_requested false")
				}
			case WS_RMEM_NJNI:
				if id != entry.PeerID || id != entry.Peer.ID() {
					panic(entry.state.String() + " peer id mismatch")
				}
				if entry.SessionID == uuid.Nil {
					panic(entry.state.String() + " must have non-nil session id")
				}
				if entry.TimeStamp.Equal(time.Time{}) {
					panic(entry.state.String() + " must have non-nil timestamp")
				}
				if entry.is_session_requested {
					panic(entry.state.String() + " is_session_requested true")
				}
			default:
				panic(entry.state.String())
			}
		}
	}
}

func (w *World) Peers() []ani.IAbyssPeer {
	peers := functional.Filter_MtS_ok(w.entries, func(s *peerWorldSessionState) (ani.IAbyssPeer, bool) {
		return s.Peer, s.Peer != nil
	})
	if w.join_target != nil {
		peers = append(peers, w.join_target.Peer)
	}
	return peers
}

// IsExposable checks if the world joining procedure is finished and the world information is set.
func (w *World) IsExposable() bool {
	if w.join_target != nil || w.url == "" {
		return false
	}
	return true
}

// removeEntry should only be called for unexpected malfunction of the opponent.
// is this a good design? IDK ¯\_(ツ)_/¯
// **note: when modifying this code, you may need to revise RST() also.
func (w *World) removeEntry(events ds.Queue, entry *peerWorldSessionState, code int, message string) {
	switch entry.state {
	case WS_DC_JNI:
		// no send
	case WS_JN:
		w.sendJDN(entry, code, message)
	case WS_MEM:
		w.member_count--
		w.sendRST(entry, code, message)
	default:
		if entry.SessionID != uuid.Nil {
			w.sendRST(entry, code, message)
		}
	}

	if entry.is_session_requested {
		events.Push(&EANDSessionClose{
			World:          w,
			ANDPeerSession: entry.ANDPeerSession(),
		})
	}
	if entry.Peer != nil {
		events.Push(&EANDPeerDiscard{
			World: w,
			Peer:  entry.Peer,
		})
	}
	delete(w.entries, entry.PeerID)
}

// removeEntrySilent is equivalent to removeEntry, but does not send ahmp message to the peer.
// This should only be used when the peer is disconnected, or the peer request seize of communication (RST)
func (w *World) removeEntrySilent(events ds.Queue, entry *peerWorldSessionState) {
	if entry.state == WS_MEM {
		w.member_count--
	}
	if entry.is_session_requested {
		events.Push(&EANDSessionClose{
			World:          w,
			ANDPeerSession: entry.ANDPeerSession(),
		})
	}
	if entry.Peer != nil {
		events.Push(&EANDPeerDiscard{
			World: w,
			Peer:  entry.Peer,
		})
	}
	delete(w.entries, entry.PeerID)
}

// tryOverwritePeerSession cleanly resets peer states if newer session id was given.
// This is kinda dangerous; impact is high. Can we ever prevent/detect forgery?
func (w *World) tryOverwritePeerSession(events ds.Queue, entry *peerWorldSessionState, session_id uuid.UUID, timestamp time.Time) bool {
	if entry.TimeStamp.Before(timestamp) {
		switch entry.state {
		case WS_JN:
			w.sendJDN(entry, JNC_OVERRUN, JNM_OVERRUN)
		case WS_MEM:
			w.member_count--
			w.sendRST(entry, JNC_OVERRUN, JNM_OVERRUN)
		default:
			if entry.SessionID != uuid.Nil {
				w.sendRST(entry, JNC_OVERRUN, JNM_OVERRUN)
			}
		}
		if entry.is_session_requested {
			events.Push(&EANDSessionClose{
				World:          w,
				ANDPeerSession: entry.ANDPeerSession(),
			})
		}
		entry.state = 0 // state must be defined right afterwards.
		entry.SessionID = session_id
		entry.TimeStamp = timestamp
		entry.is_session_requested = false
		return true
	} else {
		return false
	}
}

// mustBeMemberCheck can only be used as a barrier for handling a message that must be sent from a member.
func (w *World) mustBeMemberCheck(events ds.Queue, peer_session ANDPeerSession) (*peerWorldSessionState, bool) {
	entry, ok := w.entries[peer_session.Peer.ID()]
	if !ok {
		// this must be w.join_target - join target's fault
		if w.join_target != nil && w.join_target.Peer == peer_session.Peer {
			events.Push(&EANDWorldLeave{
				World:   w,
				Code:    JNC_INVALID_STATES,
				Message: JNM_INVALID_STATES,
			})
			w.is_closed = true
		} else {
			panic("world state corrupted")
		}
	}

	if entry.SessionID != peer_session.SessionID {
		// session expired
		w.sendRST_Direct(peer_session, JNC_OVERRUN, JNM_OVERRUN)
		return nil, false
	}

	if entry.state != WS_MEM {
		// same session, but not a member. This is a sign of peer failure.
		w.removeEntry(events, entry, JNC_INVALID_STATES, JNM_INVALID_STATES)
		return nil, false
	}

	return entry, true
}

// PeerConnected must never raise EANDPeerDiscard event for the connected peer.
func (w *World) PeerConnected(events ds.Queue, peer ani.IAbyssPeer) {
	if w.is_closed {
		return
	}

	config.IF_DEBUG(func() {
		if w.join_target != nil && w.join_target.PeerID == peer.ID() {
			panic("duplicate peer connection")
		}
	})

	entry, ok := w.entries[peer.ID()]
	if ok { // WS_DC_JNI
		config.IF_DEBUG(func() {
			if entry.state != WS_DC_JNI {
				panic("duplicate peer connection")
			}
		})
		entry.state = WS_JNI
		entry.Peer = peer
		events.Push(&EANDSessionRequest{
			World:          w,
			ANDPeerSession: entry.ANDPeerSession(),
		})
		entry.is_session_requested = true
		return
	}

	// new entry
	w.entries[peer.ID()] = &peerWorldSessionState{
		state:  WS_CC,
		PeerID: peer.ID(),
		Peer:   peer,
	}
}

func (w *World) JN(events ds.Queue, peer_session ANDPeerSession, timestamp time.Time) {
	if w.is_closed {
		return
	}

	config.IF_DEBUG(func() {
		if w.join_target != nil {
			panic("JN: yet world joining") // JN is only forwarded by path - which should not be binded yet.
		}
	})

	entry := w.entries[peer_session.Peer.ID()]
	config.IF_DEBUG(func() {
		if entry.Peer == nil {
			panic("JN from " + entry.state.String())
		}
	})

	if w.tryOverwritePeerSession(events, entry, peer_session.SessionID, timestamp) {
		entry.state = WS_JN
		events.Push(&EANDSessionRequest{
			World:          w,
			ANDPeerSession: peer_session,
		})
		entry.is_session_requested = true
	} else {
		w.sendJDN_Direct(peer_session, JNC_REDUNDANT, JNM_REDUNDANT)
	}
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

		w.entries[first_member.PeerID] = first_member

		events.Push(&EANDWorldEnter{
			World: w,
			URL:   world_url,
		})
		events.Push(&EANDSessionReady{
			World:          w,
			ANDPeerSession: first_member.ANDPeerSession(),
		})

		for _, mem_info := range member_infos {
			w.jni_mems(events, mem_info)
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

	w.jni_mems(events, member_info)
}

func (w *World) jni_mems(events ds.Queue, mem_info ANDFullPeerSessionInfo) {
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
			events.Push(&EANDPeerRequest{
				World:                      w,
				PeerID:                     mem_info.PeerID,
				AddressCandidates:          mem_info.AddressCandidates,
				RootCertificateDer:         mem_info.RootCertificateDer,
				HandshakeKeyCertificateDer: mem_info.HandshakeKeyCertificateDer,
			})
		} else {
			mem_entry.state = WS_JNI
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

func (w *World) AcceptSession(events ds.Queue, peer_session_identity ANDPeerSessionIdentity) {
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

func (w *World) DeclineSession(events ds.Queue, peer_session_identity ANDPeerSessionIdentity, code int, message string) {
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

func (w *World) ObjectAppend(peer_session_identities []ANDPeerSessionIdentity, objects []ObjectInfo) {
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

func (w *World) ObjectDelete(peer_session_identities []ANDPeerSessionIdentity, objectIDs []uuid.UUID) {
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
