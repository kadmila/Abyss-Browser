package and

import (
	"math/rand"
	"time"

	"github.com/google/uuid"

	"github.com/kadmila/Abyss-Browser/abyss_core/aurl"
	abyss "github.com/kadmila/Abyss-Browser/abyss_core/interfaces"
)

const (
	WS_DC_JT     int = iota + 1 //disconnected join target
	WS_DC_JNI                   //disconnected, JNI received
	WS_CC                       //connected, no info
	WS_JT                       //JN sent
	WS_JN                       //JN received
	WS_RMEM_NJNI                //MEM received, JNI not received
	WS_JNI                      //JNI received
	WS_RMEM                     //MEM received
	WS_TMEM                     //MEM sent
	WS_MEM                      //member
)

// ANDPeerSessionState represents the peer's state in world session lifecycle.
// timestamp is used only for JNI.
type ANDPeerSessionState struct {
	//latest
	abyss.ANDPeerSessionWithTimeStamp
	state int
	sjnp  bool //is sjn suppressed
	sjnc  int  //sjn receive count
}

func NewANDPeerSessionState(peer abyss.IANDPeer, session_id uuid.UUID, timestamp time.Time, state int) *ANDPeerSessionState {
	return &ANDPeerSessionState{
		abyss.ANDPeerSessionWithTimeStamp{
			ANDPeerSession: abyss.ANDPeerSession{
				Peer:          peer,
				PeerSessionID: session_id,
			},
			TimeStamp: timestamp,
		},
		state,
		false,
		0,
	}
}

func (s *ANDPeerSessionState) Clear() {
	s.PeerSessionID = uuid.Nil
	s.TimeStamp = time.Time{}
	if s.Peer != nil {
		s.state = WS_CC
	} else {
		panic("this peer must be removed, not cleared")
	}
	s.sjnp = false
	s.sjnc = 0
}

type ANDWorld struct {
	o *AND //origin (debug purpose)

	local     string //local hash
	lsid      uuid.UUID
	timestamp time.Time
	join_hash string                          //const
	join_path string                          //const
	wurl      string                          //const
	peers     map[string]*ANDPeerSessionState //key: hash

	ech chan abyss.NeighborEvent
}

func (w *ANDWorld) CheckSanity() {
	jc := 0
	for peer_id, peer := range w.peers {
		if peer_id == w.local {
			panic("and sanity check failed: loopback connection")
		}

		switch peer.state {
		case WS_DC_JT:
		case WS_DC_JNI:
		case WS_CC:
		case WS_JT:
		case WS_JN:
		case WS_RMEM_NJNI:
		case WS_JNI:
		case WS_RMEM:
		case WS_TMEM:
		case WS_MEM:
		default:
			panic("and sanity check failed: non-existing state")
		}
	}
	if w.join_hash == "" && jc != 0 {
		panic("and sanity check failed: both join and open")
	}
	if jc > 1 {
		panic("and sanity check failed: multiple join targets")
	}
}

func NewWorldOpen(origin *AND, local_hash string, local_session_id uuid.UUID, world_url string, connected_members map[string]abyss.IANDPeer, event_ch chan abyss.NeighborEvent) *ANDWorld {
	result := &ANDWorld{
		o:         origin,
		local:     local_hash,
		lsid:      local_session_id,
		timestamp: time.Now(),
		join_hash: "",
		join_path: "",
		wurl:      world_url,
		peers:     make(map[string]*ANDPeerSessionState),
		ech:       event_ch,
	}
	for peer_id, peer := range connected_members {
		origin.stat.W(0)

		result.peers[peer_id] = NewANDPeerSessionState(peer, uuid.Nil, time.Time{}, WS_CC)
	}
	result.ech <- abyss.NeighborEvent{
		Type:           abyss.ANDJoinSuccess,
		LocalSessionID: local_session_id,
		Text:           world_url,
	}
	result.ech <- abyss.NeighborEvent{
		Type:           abyss.ANDTimerRequest,
		LocalSessionID: result.lsid,
		Value:          500,
	}
	return result
}

func NewWorldJoin(origin *AND, local_hash string, local_session_id uuid.UUID, target *aurl.AURL, connected_members map[string]abyss.IANDPeer, event_ch chan abyss.NeighborEvent) *ANDWorld {
	result := &ANDWorld{
		o:         origin,
		local:     local_hash,
		lsid:      local_session_id,
		timestamp: time.Now(),
		join_hash: target.Hash,
		join_path: target.Path,
		peers:     make(map[string]*ANDPeerSessionState),
		ech:       event_ch,
	}
	for peer_id, peer := range connected_members {
		origin.stat.W(1)

		result.peers[peer_id] = NewANDPeerSessionState(peer, uuid.Nil, time.Time{}, WS_CC)
	}

	if connected_target, ok := result.peers[target.Hash]; ok {
		origin.stat.W(2)

		connected_target.state = WS_JT
		origin.stat.JN_TX++
		connected_target.Peer.TrySendJN(local_session_id, target.Path, result.timestamp)
	} else {
		origin.stat.W(3)

		result.peers[target.Hash] = NewANDPeerSessionState(nil, uuid.Nil, time.Time{}, WS_DC_JT)
		result.ech <- abyss.NeighborEvent{
			Type:   abyss.ANDConnectRequest,
			Object: target,
		}
	}
	return result
}

func (w *ANDWorld) ClearStates(peer_id string, info *ANDPeerSessionState, message string) {
	switch info.state {
	case WS_DC_JT, WS_DC_JNI:
		delete(w.peers, peer_id)
	case WS_CC:
		info.Clear()
	case WS_JT:
		w.o.stat.RST_TX++
		info.Peer.TrySendRST(w.lsid, info.PeerSessionID, "ClearStates::WS_JT "+message)
		w.ech <- abyss.NeighborEvent{
			Type:           abyss.ANDJoinFail,
			LocalSessionID: w.lsid,
			Text:           JNM_INVALID_STATES,
			Value:          JNC_INVALID_STATES,
		}
		info.Clear()
	case WS_JN:
		w.o.stat.JDN_TX++
		info.Peer.TrySendJDN(info.PeerSessionID, JNC_INVALID_STATES, JNM_INVALID_STATES)
		info.Clear()
	case WS_MEM:
		w.ech <- abyss.NeighborEvent{
			Type:           abyss.ANDSessionClose,
			LocalSessionID: w.lsid,
			ANDPeerSession: info.ANDPeerSession,
		}
		fallthrough
	case WS_RMEM_NJNI, WS_JNI, WS_RMEM, WS_TMEM:
		w.o.stat.RST_TX++
		info.Peer.TrySendRST(w.lsid, info.PeerSessionID, "ClearStates::else "+message)
		info.Clear()
	}
}

// TryUpdateSessionID returns (old session ID, success). old session ID is nil if not updated
func (w *ANDWorld) TryUpdateSessionID(s *ANDPeerSessionState, session_id uuid.UUID, timestamp time.Time) bool {
	if s.TimeStamp.Before(timestamp) {
		w.ClearStates(s.Peer.ID(), s, "session id update failure")
		s.PeerSessionID = session_id
		s.TimeStamp = timestamp
		return true
	} else {
		return false
	}
}
func (w *ANDWorld) IsProperMemberOrReset(info *ANDPeerSessionState, peer_session abyss.ANDPeerSession) bool {
	switch info.state {
	case WS_DC_JT, WS_DC_JNI:
		panic("not connected")
	case WS_MEM:
		if info.PeerSessionID == peer_session.PeerSessionID {
			return true
		}
		fallthrough
	default:
		w.ClearStates(info.Peer.ID(), info, "non-member reset")
	}
	return false
}

func (w *ANDWorld) PeerConnected(peer abyss.IANDPeer) {
	info, ok := w.peers[peer.ID()]
	if ok { // known peer
		w.o.stat.W(4)

		switch info.state {
		case WS_DC_JT:
			w.o.stat.W(5)

			info.Peer = peer
			w.o.stat.JN_TX++
			peer.TrySendJN(w.lsid, w.join_path, w.timestamp)
			info.state = WS_JT
		case WS_DC_JNI:
			w.o.stat.W(6)

			info.Peer = peer
			info.state = WS_JNI

			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDSessionRequest,
				LocalSessionID: w.lsid,
				ANDPeerSession: info.ANDPeerSession,
			}
		default:
			panic("and: duplicate connection")
		}

		return
	}
	//unknown peer
	w.peers[peer.ID()] = NewANDPeerSessionState(peer, uuid.Nil, time.Time{}, WS_CC)
}
func (w *ANDWorld) JN(peer_session abyss.ANDPeerSession, timestamp time.Time) {
	w.o.stat.JN_RX++

	info := w.peers[peer_session.Peer.ID()]
	switch info.state {
	case WS_CC:
		w.o.stat.W(7)

		info.ANDPeerSession = peer_session
		info.TimeStamp = timestamp
		info.state = WS_JN
		w.ech <- abyss.NeighborEvent{
			Type:           abyss.ANDSessionRequest,
			LocalSessionID: w.lsid,
			ANDPeerSession: peer_session,
		}
	case WS_JT: //should not happen. during joining, the world must be hidden, not accepting JN.
		w.o.stat.W(8)

		w.o.stat.JDN_TX++
		peer_session.Peer.TrySendJDN(peer_session.PeerSessionID, JNC_INVALID_STATES, JNM_INVALID_STATES)
	case WS_JN, WS_RMEM_NJNI, WS_JNI, WS_RMEM, WS_TMEM, WS_MEM:
		w.o.stat.W(9)

		if w.TryUpdateSessionID(info, peer_session.PeerSessionID, timestamp) {
			w.o.stat.W(10)

			info.state = WS_JN
			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDSessionRequest,
				LocalSessionID: w.lsid,
				ANDPeerSession: peer_session,
			}
		} else {
			w.o.stat.W(11)

			w.o.stat.JDN_TX++
			peer_session.Peer.TrySendJDN(peer_session.PeerSessionID, JNC_DUPLICATE, JNM_DUPLICATE) //must not happen
		}
	default:
		panic("and invalid state: JN")
	}
}
func (w *ANDWorld) JOK(peer_session abyss.ANDPeerSession, timestamp time.Time, world_url string, member_infos []abyss.ANDFullPeerSessionIdentity) {
	w.o.stat.JOK_RX++

	sender_id := peer_session.Peer.ID()
	info := w.peers[sender_id]
	if w.join_hash != sender_id ||
		info.state != WS_JT {
		w.o.stat.W(12)

		w.o.stat.RST_TX++
		peer_session.Peer.TrySendRST(w.lsid, peer_session.PeerSessionID, "JOK::not WS_JT")
		return
	}

	w.o.stat.W(13)

	info.ANDPeerSession = peer_session
	info.TimeStamp = timestamp
	w.ech <- abyss.NeighborEvent{
		Type:           abyss.ANDJoinSuccess,
		LocalSessionID: w.lsid,
		Text:           world_url,
	}
	w.ech <- abyss.NeighborEvent{
		Type:           abyss.ANDSessionRequest,
		LocalSessionID: w.lsid,
		ANDPeerSession: peer_session,
	}
	info.state = WS_RMEM
	info.sjnp = true

	for _, mem_info := range member_infos {
		w.o.stat.W(14)

		w.JNI_MEMS(sender_id, mem_info)
	}
}
func (w *ANDWorld) JDN(peer abyss.IANDPeer, code int, message string) { //no branch number here... :(
	w.o.stat.JDN_RX++

	info := w.peers[peer.ID()]
	if w.join_hash != peer.ID() ||
		info.state != WS_JT {
		w.o.stat.W(15)

		return
	}

	w.o.stat.W(16)

	w.ech <- abyss.NeighborEvent{
		Type:           abyss.ANDJoinFail,
		LocalSessionID: w.lsid,
		Text:           message,
		Value:          code,
	}
	info.Clear()
}

func (w *ANDWorld) JNI(peer_session abyss.ANDPeerSession, member_info abyss.ANDFullPeerSessionIdentity) {
	w.o.stat.JNI_RX++

	sender_id := peer_session.Peer.ID()
	info := w.peers[sender_id]

	if !w.IsProperMemberOrReset(info, peer_session) {
		w.o.stat.W(17)

		return
	}

	w.o.stat.W(18)

	w.JNI_MEMS(sender_id, member_info)
}
func (w *ANDWorld) JNI_MEMS(sender_id string, mem_info abyss.ANDFullPeerSessionIdentity) {
	peer_id := mem_info.AURL.Hash
	if peer_id == w.local {
		w.o.stat.W(19)
		return
	}

	info, ok := w.peers[peer_id]
	if !ok {
		w.o.stat.W(20)

		w.peers[peer_id] = NewANDPeerSessionState(nil, mem_info.SessionID, mem_info.TimeStamp, WS_DC_JNI)
		w.ech <- abyss.NeighborEvent{
			Type: abyss.ANDPeerRegister,
			Object: &abyss.PeerCertificates{
				RootCertDer:         mem_info.RootCertificateDer,
				HandshakeKeyCertDer: mem_info.HandshakeKeyCertificateDer,
			},
		}
		w.ech <- abyss.NeighborEvent{
			Type:   abyss.ANDConnectRequest,
			Object: mem_info.AURL,
		}
		return
	}

	switch info.state {
	case WS_DC_JT, WS_JT:
		panic("and: proper member check failed (JNI)")
	case WS_DC_JNI:
		w.o.stat.W(21)

		if info.TimeStamp.Before(mem_info.TimeStamp) {
			info.PeerSessionID = mem_info.SessionID
			info.TimeStamp = mem_info.TimeStamp
			info.state = WS_DC_JNI
		}
		//previously, tried connecting. may need to refresh connection trials
	case WS_CC:
		w.o.stat.W(22)

		info.PeerSessionID = mem_info.SessionID
		info.TimeStamp = mem_info.TimeStamp
		info.state = WS_JNI
		w.ech <- abyss.NeighborEvent{
			Type:           abyss.ANDSessionRequest,
			LocalSessionID: w.lsid,
			ANDPeerSession: info.ANDPeerSession,
		}
	case WS_JN:
		w.o.stat.W(23)

		if w.TryUpdateSessionID(info, mem_info.SessionID, mem_info.TimeStamp) {
			//unlikely to happen
			info.state = WS_JNI
			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDSessionRequest,
				LocalSessionID: w.lsid,
				ANDPeerSession: info.ANDPeerSession,
			}
		}
	case WS_RMEM_NJNI:
		w.o.stat.W(24)

		if w.TryUpdateSessionID(info, mem_info.SessionID, mem_info.TimeStamp) {
			w.o.stat.W(25)

			info.state = WS_JNI
			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDSessionRequest,
				LocalSessionID: w.lsid,
				ANDPeerSession: info.ANDPeerSession,
			}
			return
		}
		if info.PeerSessionID == mem_info.SessionID {
			w.o.stat.W(26)

			info.state = WS_RMEM
			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDSessionRequest,
				LocalSessionID: w.lsid,
				ANDPeerSession: info.ANDPeerSession,
			}
		}
		//else: old session
	case WS_JNI, WS_RMEM, WS_TMEM, WS_MEM:
		if w.TryUpdateSessionID(info, mem_info.SessionID, mem_info.TimeStamp) {
			w.o.stat.W(27)

			info.state = WS_JNI
			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDSessionRequest,
				LocalSessionID: w.lsid,
				ANDPeerSession: info.ANDPeerSession,
			}
			return
		}
		w.o.stat.W(28)

	default:
		panic("and invalid state: JNI_MEMS")
	}
}
func (w *ANDWorld) MEM(peer_session abyss.ANDPeerSession, timestamp time.Time) {
	w.o.stat.MEM_RX++

	info := w.peers[peer_session.Peer.ID()]
	switch info.state {
	case WS_CC:
		w.o.stat.W(29)

		info.ANDPeerSession = peer_session
		info.TimeStamp = timestamp
		info.state = WS_RMEM_NJNI
	case WS_JT:
		w.o.stat.W(30)

		w.ClearStates(peer_session.Peer.ID(), info, "received MEM from WS_JT")
	case WS_JN, WS_RMEM_NJNI, WS_RMEM, WS_MEM:
		if w.TryUpdateSessionID(info, peer_session.PeerSessionID, timestamp) {
			w.o.stat.W(31)

			info.state = WS_RMEM_NJNI
			return
		}
		w.o.stat.W(32)

	case WS_JNI:
		if w.TryUpdateSessionID(info, peer_session.PeerSessionID, timestamp) {
			w.o.stat.W(33)

			info.state = WS_RMEM_NJNI
			return
		}
		if info.PeerSessionID == peer_session.PeerSessionID {
			w.o.stat.W(34)

			info.state = WS_RMEM
		}
		w.o.stat.W(35)

	case WS_TMEM:
		w.o.stat.W(36)

		if w.TryUpdateSessionID(info, peer_session.PeerSessionID, timestamp) {
			w.o.stat.W(37)

			info.state = WS_RMEM_NJNI
			return
		}
		if info.PeerSessionID == peer_session.PeerSessionID {
			w.o.stat.W(38)

			info.state = WS_MEM
			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDSessionReady,
				LocalSessionID: w.lsid,
				ANDPeerSession: info.ANDPeerSession,
			}
		}
		w.o.stat.W(39)

	default:
		panic("and: impossible disconnected state")
	}
}
func (w *ANDWorld) SJN(peer_session abyss.ANDPeerSession, member_infos []abyss.ANDPeerSessionIdentity) {
	w.o.stat.SJN_RX++

	info := w.peers[peer_session.Peer.ID()]
	if !w.IsProperMemberOrReset(info, peer_session) {
		w.o.stat.W(40)

		return
	}
	for _, mem_info := range member_infos {
		w.o.stat.W(41)

		w.SJN_MEMS(peer_session, mem_info)
	}
}
func (w *ANDWorld) SJN_MEMS(origin abyss.ANDPeerSession, mem_info abyss.ANDPeerSessionIdentity) {
	if mem_info.PeerHash == w.local {
		w.o.stat.W(42)
		return
	}

	info, ok := w.peers[mem_info.PeerHash]
	if ok && info.state == WS_MEM && info.PeerSessionID == mem_info.SessionID {
		w.o.stat.W(43)

		info.sjnc++
		return
	}
	w.o.stat.CRR_TX++
	origin.Peer.TrySendCRR(w.lsid, origin.PeerSessionID, []abyss.ANDPeerSessionIdentity{mem_info})
}
func (w *ANDWorld) CRR(peer_session abyss.ANDPeerSession, member_infos []abyss.ANDPeerSessionIdentity) {
	w.o.stat.CRR_RX++

	info := w.peers[peer_session.Peer.ID()]
	if !w.IsProperMemberOrReset(info, peer_session) {
		w.o.stat.W(44)

		return
	}
	for _, mem_info := range member_infos {
		w.o.stat.W(45)

		w.CRR_MEMS(info, mem_info)
	}
}
func (w *ANDWorld) CRR_MEMS(origin *ANDPeerSessionState, mem_info abyss.ANDPeerSessionIdentity) {
	if mem_info.PeerHash == w.local {
		w.o.stat.W(46)
		return
	}

	info, ok := w.peers[mem_info.PeerHash]
	if ok && info.PeerSessionID == mem_info.SessionID {
		w.o.stat.W(47)

		w.o.stat.JNI_TX++
		origin.Peer.TrySendJNI(w.lsid, origin.PeerSessionID, info.ANDPeerSessionWithTimeStamp)
		w.o.stat.JNI_TX++
		info.Peer.TrySendJNI(w.lsid, info.PeerSessionID, origin.ANDPeerSessionWithTimeStamp)
	}
}
func (w *ANDWorld) SOA(peer_session abyss.ANDPeerSession, objects []abyss.ObjectInfo) {
	w.o.stat.SOA_RX++

	info := w.peers[peer_session.Peer.ID()]
	if info.PeerSessionID != peer_session.PeerSessionID {
		w.o.stat.W(48)

		w.o.stat.RST_TX++
		peer_session.Peer.TrySendRST(w.lsid, peer_session.PeerSessionID, "SOA::sessionID mismatch")
		return
	}
	switch info.state {
	case WS_MEM:
		w.o.stat.W(49)

		w.ech <- abyss.NeighborEvent{
			Type:           abyss.ANDObjectAppend,
			LocalSessionID: w.lsid,
			ANDPeerSession: peer_session,
			Object:         objects,
		}
	default:
		w.o.stat.W(50)
	}
}
func (w *ANDWorld) SOD(peer_session abyss.ANDPeerSession, objectIDs []uuid.UUID) {
	w.o.stat.SOD_RX++

	info := w.peers[peer_session.Peer.ID()]
	if info.PeerSessionID != peer_session.PeerSessionID {
		w.o.stat.W(51)

		w.o.stat.RST_TX++
		peer_session.Peer.TrySendRST(w.lsid, peer_session.PeerSessionID, "SOA::sessionID mismatch")
		return
	}
	switch info.state {
	case WS_MEM:
		w.o.stat.W(52)

		w.ech <- abyss.NeighborEvent{
			Type:           abyss.ANDObjectDelete,
			LocalSessionID: w.lsid,
			ANDPeerSession: peer_session,
			Object:         objectIDs,
		}
	default:
		w.o.stat.W(53)
	}
}
func (w *ANDWorld) RST(peer_session abyss.ANDPeerSession) {
	w.o.stat.RST_RX++

	info := w.peers[peer_session.Peer.ID()]
	w.ClearStates(info.Peer.ID(), info, "RST received")
}

func (w *ANDWorld) AcceptSession(peer_session abyss.ANDPeerSession) {
	info, ok := w.peers[peer_session.Peer.ID()]
	if !ok {
		w.o.stat.W(54)
		return
	}
	switch info.state {
	case WS_DC_JT:
		panic("and invalid state: AcceptSession")
	case WS_DC_JNI:
		w.o.stat.W(55)

	case WS_CC:
		w.o.stat.W(56)

		//ignore
	case WS_JT:
		panic("and invalid state: AcceptSession")
	case WS_JN:
		w.o.stat.W(57)

		if info.PeerSessionID != peer_session.PeerSessionID {
			w.o.stat.W(58)

			return
		}

		member_infos := make([]abyss.ANDPeerSessionWithTimeStamp, 0)
		for _, p := range w.peers {
			if p.state != WS_MEM {
				w.o.stat.W(59)

				continue
			}
			w.o.stat.W(60)

			member_infos = append(member_infos, abyss.ANDPeerSessionWithTimeStamp{
				ANDPeerSession: p.ANDPeerSession,
				TimeStamp:      p.TimeStamp,
			})
			w.o.stat.JNI_TX++
			p.Peer.TrySendJNI(w.lsid, p.PeerSessionID, info.ANDPeerSessionWithTimeStamp)
		}
		w.o.stat.JOK_TX++
		info.Peer.TrySendJOK(w.lsid, info.PeerSessionID, w.timestamp, w.wurl, member_infos)
		info.state = WS_TMEM
	case WS_RMEM_NJNI:
		w.o.stat.W(61)

		//ignore
	case WS_JNI:
		w.o.stat.W(62)

		if info.PeerSessionID != peer_session.PeerSessionID {
			w.o.stat.W(63)

			return
		}
		w.o.stat.W(64)

		w.o.stat.MEM_TX++
		info.Peer.TrySendMEM(w.lsid, info.PeerSessionID, w.timestamp)
		info.state = WS_TMEM
	case WS_RMEM:
		w.o.stat.W(65)

		if info.PeerSessionID != peer_session.PeerSessionID {
			w.o.stat.W(66)

			return
		}
		w.o.stat.W(67)

		w.o.stat.MEM_TX++
		info.Peer.TrySendMEM(w.lsid, info.PeerSessionID, w.timestamp)
		w.ech <- abyss.NeighborEvent{
			Type:           abyss.ANDSessionReady,
			LocalSessionID: w.lsid,
			ANDPeerSession: info.ANDPeerSession,
		}
		info.state = WS_MEM
	case WS_TMEM:
		w.o.stat.W(68)

		//ignore
	case WS_MEM:
		w.o.stat.W(69)

		//ignore
	default:
		w.o.stat.W(70)
	}
}
func (w *ANDWorld) DeclineSession(peer_session abyss.ANDPeerSession, code int, message string) {
	info, ok := w.peers[peer_session.Peer.ID()]
	if !ok {
		w.o.stat.W(71)
		return
	}
	if info.PeerSessionID == peer_session.PeerSessionID {
		w.o.stat.W(72)

		//TODO: proper JDN
		w.ClearStates(peer_session.Peer.ID(), info, "application-DeclineSession called")
	}
	w.o.stat.W(73)

}
func (w *ANDWorld) TimerExpire() {
	sjn_mem := make([]abyss.ANDPeerSessionIdentity, 0)
	for _, info := range w.peers {
		if info.state != WS_MEM ||
			time.Since(info.TimeStamp) < time.Second ||
			info.sjnp || info.sjnc > 3 {
			w.o.stat.W(74)

			continue
		}
		w.o.stat.W(75)

		sjn_mem = append(sjn_mem, abyss.ANDPeerSessionIdentity{
			PeerHash:  info.Peer.ID(),
			SessionID: info.PeerSessionID,
		})
		info.sjnc++
	}

	member_count := 0
	for _, info := range w.peers {
		if info.state != WS_MEM {
			w.o.stat.W(76)

			continue
		}
		member_count++
		if len(sjn_mem) != 0 {
			w.o.stat.W(77)

			w.o.stat.SJN_TX++
			info.Peer.TrySendSJN(w.lsid, info.PeerSessionID, sjn_mem)
		}
	}

	w.ech <- abyss.NeighborEvent{
		Type:           abyss.ANDTimerRequest,
		LocalSessionID: w.lsid,
		Value:          300 + rand.Intn(300*(member_count+1)),
	}
}

func (w *ANDWorld) RemovePeer(peer abyss.IANDPeer) {
	w.ClearStates(peer.ID(), w.peers[peer.ID()], "")
	delete(w.peers, peer.ID())
}
func (w *ANDWorld) Close() {
	for _, info := range w.peers {
		switch info.state {
		case WS_CC:
			//nothing
		case WS_JT:
			w.o.stat.W(78)

			w.o.stat.RST_TX++
			info.Peer.TrySendRST(w.lsid, info.PeerSessionID, "Close")

			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDJoinFail,
				LocalSessionID: w.lsid,
				Text:           JNM_CANCELED,
				Value:          JNC_CANCELED,
			}
		case WS_JN, WS_RMEM_NJNI, WS_JNI, WS_RMEM, WS_TMEM:
			w.o.stat.W(79)

			w.o.stat.RST_TX++
			info.Peer.TrySendRST(w.lsid, info.PeerSessionID, "Close")

		case WS_MEM:
			w.o.stat.W(80)

			w.o.stat.RST_TX++
			info.Peer.TrySendRST(w.lsid, info.PeerSessionID, "Close")

			w.ech <- abyss.NeighborEvent{
				Type:           abyss.ANDSessionClose,
				LocalSessionID: w.lsid,
				ANDPeerSession: info.ANDPeerSession,
			}
		}
	}
	w.o.stat.W(81)

	w.ech <- abyss.NeighborEvent{
		Type:           abyss.ANDWorldLeave,
		LocalSessionID: w.lsid,
	}
}
