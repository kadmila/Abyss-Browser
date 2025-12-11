package ann

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
)

// AuthenticatedConnection is a single QUIC connection
// that completed abyss handshake.
// It is passed to PeerConstructor.
type AuthenticatedConnection struct {
	*sec.AbyssPeerIdentity

	is_dialing   bool
	connection   quic.Connection
	remote_addr  netip.AddrPort
	ahmp_encoder *cbor.Encoder
	ahmp_decoder *cbor.Decoder
}

type BackLogEntry struct {
	peer *AbyssPeer
	err  error
}

// PeerConstructor handles appended peer/error, and writes to BackLog.
// When BackLog is full, Append() and AppendError() will block.
type PeerConstructor struct {
	local_id string
	BackLog  chan BackLogEntry

	mtx                  sync.Mutex
	connected_peers      map[string]*AbyssPeer
	internal_peer_id_cnt uint64
}

func NewPeerConstructor(local_id string) *PeerConstructor {
	return &PeerConstructor{
		local_id: local_id,
		BackLog:  make(chan BackLogEntry, 128),

		connected_peers: make(map[string]*AbyssPeer),
	}
}

// Append blocks until 1) context cancels, or 2) abyss peer is constructed.
// * Issue: it hard-blocks when BackLog is full.
func (c *PeerConstructor) Append(ctx context.Context, connection *AuthenticatedConnection) {
	// check who's in control.
	controller_id, err := TieBreak(c.local_id, connection.ID())
	if err != nil {
		c.AppendError(connection.remote_addr, connection.is_dialing, err)
		connection.connection.CloseWithError(AbyssQuicCryptoFail, "abyss tie breaking fail")
		return
	}
	if c.local_id == controller_id {
		// I'm in control. Append peer only when there is no active connection.
		var new_peer *AbyssPeer
		var is_new_peer_created bool

		c.mtx.Lock()
		{
			_, ok := c.connected_peers[connection.ID()]
			if !ok {
				c.internal_peer_id_cnt++
				new_peer = NewAbyssPeer(*connection, c, c.internal_peer_id_cnt)
				c.connected_peers[connection.ID()] = new_peer
				is_new_peer_created = true
			}
		}
		c.mtx.Unlock()

		// if this does not create a new peer, prune connection.
		if !is_new_peer_created {
			connection.connection.CloseWithError(AbyssQuicRedundantConnection, "")
			c.AppendError(connection.remote_addr, connection.is_dialing, errors.New("redundant connection"))
			return
		}

		// connection confirmation (handshake 3)
		code := 0
		err = connection.ahmp_encoder.Encode(code)
		if err != nil {
			connection.connection.CloseWithError(AbyssQuicAhmpStreamFail, "fail to send abyss confirmation")
			c.AppendError(connection.remote_addr, connection.is_dialing, err)
			return
		}

		c.BackLog <- BackLogEntry{
			peer: new_peer,
			err:  nil,
		}
		return
	} else {
		// Opponent is in control.
		// Wait for connection confirmation (handshake 3)
		var code int
		err := connection.ahmp_decoder.Decode(&code)
		if err != nil {
			// opponent killed the connection (or ahmp stream fail)
			connection.connection.CloseWithError(AbyssQuicAhmpStreamFail, "abyss confirmation fail")
			c.AppendError(connection.remote_addr, connection.is_dialing, err)
			return
		}
		var new_peer *AbyssPeer

		// This connection is accepted.
		c.mtx.Lock()
		{
			c.internal_peer_id_cnt++
			new_peer = NewAbyssPeer(*connection, c, c.internal_peer_id_cnt)

			// renew peer if old one exists.
			old_peer, ok := c.connected_peers[connection.ID()]
			if ok {
				old_peer.connection.CloseWithError(AbyssQuicOverride, "")
			}
			c.connected_peers[connection.ID()] = new_peer
		}
		c.mtx.Unlock()

		c.BackLog <- BackLogEntry{
			peer: new_peer,
			err:  nil,
		}
		return
	}
}

func (c *PeerConstructor) AppendError(addr netip.AddrPort, is_dialing bool, err error) {
	c.BackLog <- BackLogEntry{
		peer: nil,
		err:  err,
	}
}

func (c *PeerConstructor) ReportPeerClose(peer *AbyssPeer) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	old_peer, ok := c.connected_peers[peer.ID()]
	if ok && old_peer.Equal(peer) {
		delete(c.connected_peers, peer.ID())
	}
}

// Tie breaking
// handshake 2 is a request for connection confirmation.
// handshake 3 can only be sent once.
// when receiving hs 2:
// 1) I did not sent hs 3 yet -> send hs 3
// 2) I sent hs 3 -> drop connection.
// when receiving hs 3:
// 1) I have not sent hs 3 ->
// 2) I have sent hs 3 -> disconnect any of them.

// consumePendingInboundOrRegisterOutbound returns (completed_connection, ok, inbound_wait, redundant)
// func (n *AbyssNode) consumePendingInboundOrRegisterOutbound(id string, connection quic.Connection) (*AbyssConnection, bool, chan *InboundConnection, bool) {
// 	n.backlog_join_mtx.Lock()
// 	defer n.backlog_join_mtx.Unlock()

// 	if _, ok := n.peers[id]; ok {
// 		return nil, false, nil, true
// 	}
// 	if _, ok := n.outbound_backlog[id]; ok {
// 		return nil, false, nil, true
// 	}

// 	inbound, ok := n.inbound_backlog[id]
// 	if ok {
// 		delete(n.inbound_backlog, id)
// 		return &AbyssConnection{
// 			inbound_connection: inbound.conn,
// 			outbound_connection: connection,
// 			ahmp_encoder: ,
// 		}, true, nil, false
// 	}

// 	inbound_wait := make(chan *InboundConnection)
// 	n.outbound_backlog[id] = inbound_wait
// 	return nil, false, inbound_wait, false
// }

// func (n *AbyssNode) isDialRedundant(id string) bool {
// 	n.backlog_join_mtx.Lock()
// 	defer n.backlog_join_mtx.Unlock()

// 	_, ok := n.outbound_backlog[id]
// 	if ok {
// 		return true
// 	}

// 	_, ok = n.peers[id]
// 	if ok {
// 		return true
// 	}

// 	return false
// }

// func (n *AbyssNode) OutboundConnectionJoin(id string, connection quic.Connection, identity *sec.AbyssPeerIdentity) {
// 	n.backlog_join_mtx.Lock()
// 	defer n.backlog_join_mtx.Unlock()

// 	if _, ok := n.peers[id]; ok {
// 		conn.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
// 		return
// 	}

// 	outbound_conn, ok := n.outbound_backlog[id]
// 	if ok {
// 		conn.CloseWithError(AbyssQuicRedundantConnection, "redundant connection")
// 	}

// 	inbound_conn, ok := n.inbound_backlog[id]
// 	if ok {

// 	} else {
// 		n.outbound_backlog[id]
// 	}
// }

// TODO func (n *AbyssNode) NewAbystClient() (IAbystClient, error) {}

// TODO NewCollocatedHttp3Client() (http.Client, error)
