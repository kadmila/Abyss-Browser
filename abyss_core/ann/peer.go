package ann

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/kadmila/Abyss-Browser/abyss_core/tools/infchan"
	"github.com/quic-go/quic-go"
)

type AbyssPeer struct {
	*sec.AbyssPeerIdentity
	origin          *AbyssNode
	internal_id     uint64
	client_tls_cert *x509.Certificate // this is stupid

	connection   *quic.Conn
	remote_addr  netip.AddrPort
	ahmp_encoder *cbor.Encoder
	ahmp_decoder *cbor.Decoder

	running       bool
	send_ch       *infchan.InfiniteChan[*ahmp.AHMPMessage]
	recv_ch       *infchan.InfiniteChan[*ahmp.AHMPMessage]
	closed        chan bool
	send_done_err chan error
	recv_done_err chan error

	// is_closed should be referenced only from AbyssNode.
	is_closed atomic.Bool
}

func NewAbyssPeer(
	peer_identity *sec.AbyssPeerIdentity,
	origin *AbyssNode,
	client_tls_cert *x509.Certificate,
	connection *quic.Conn,
	remote_addr netip.AddrPort,
	ahmp_encoder *cbor.Encoder,
	ahmp_decoder *cbor.Decoder,
) *AbyssPeer {
	result := &AbyssPeer{
		AbyssPeerIdentity: peer_identity,
		origin:            origin,
		client_tls_cert:   client_tls_cert,
		connection:        connection,
		remote_addr:       remote_addr,
		ahmp_encoder:      ahmp_encoder,
		ahmp_decoder:      ahmp_decoder,

		running:       false,
		send_ch:       infchan.NewInfiniteChan[*ahmp.AHMPMessage](32),
		recv_ch:       infchan.NewInfiniteChan[*ahmp.AHMPMessage](32),
		closed:        make(chan bool, 1),
		send_done_err: make(chan error, 1),
		recv_done_err: make(chan error, 1),
	}
	return result
}

func (p *AbyssPeer) runWorkers() {
	p.running = true
	go func() {
		var err error
	SEND_LOOP:
		for {
			select {
			case <-p.closed:
				break SEND_LOOP
			case msg := <-p.send_ch.Out:
				err = p.ahmp_encoder.Encode(msg)
				//fmt.Println(time.Now().Format("15:04:05.00000") + "| Tx " + msg.Type.String() + " delay (mS): " + strconv.FormatInt(time.Since(msg.TimeStamp()).Milliseconds(), 10))
				if err != nil {
					break SEND_LOOP
				}
			}
		}
		p.send_done_err <- err
	}()
	go func() {
		var err error
		for {
			var msg ahmp.AHMPMessage
			if err = p.ahmp_decoder.Decode(&msg); err != nil {
				close(p.recv_ch.In)
				break
			}
			p.recv_ch.In <- &msg
		}
		p.recv_done_err <- err
	}()
}

func (p *AbyssPeer) RemoteAddr() netip.AddrPort {
	return p.remote_addr
}

func (p *AbyssPeer) Send(t ahmp.AHMPMsgType, v any) error {
	payload, err := cbor.Marshal(v)
	if err != nil {
		return err
	}
	p.send_ch.In <- ahmp.NewAHMPMessage(t, payload)
	return nil
}
func (p *AbyssPeer) Recv() (*ahmp.AHMPMessage, error) {
	msg, ok := <-p.recv_ch.Out
	if !ok {
		return nil, quic.ErrTransportClosed
	}
	return msg, nil
}
func (p *AbyssPeer) Context() context.Context {
	return p.connection.Context()
}

// Close must not be called twice.
func (p *AbyssPeer) Close() error {
	if !p.running {
		return nil
	}
	p.closed <- true
	err_send := <-p.send_done_err
	err_recv := <-p.recv_done_err
	return errors.Join(err_send, err_recv, p.origin.registry.ReportPeerClose(p))
}

func (p *AbyssPeer) Equal(subject *AbyssPeer) bool {
	return p.internal_id == subject.internal_id
}
