package ann

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

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

	send_ch  *infchan.InfiniteChan[*ahmp.AHMPMessage]
	closed   chan bool
	done_err chan error

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

		send_ch:  infchan.NewInfiniteChan[*ahmp.AHMPMessage](32),
		closed:   make(chan bool, 1),
		done_err: make(chan error, 1),
	}
	go func() {
		var err error
	SEND_LOOP:
		for {
			select {
			case <-result.closed:
				break SEND_LOOP
			case msg := <-result.send_ch.Out:
				err = result.ahmp_encoder.Encode(msg)
				fmt.Println(time.Now().Format("15:04:05.00000") + "| Tx " + msg.Type.String() + " delay (mS): " + strconv.FormatInt(time.Now().Sub(msg.TimeStamp()).Milliseconds(), 10))
				if err != nil {
					break SEND_LOOP
				}
			}
		}
		result.done_err <- err
	}()
	return result
}

func (p *AbyssPeer) RemoteAddr() netip.AddrPort {
	return p.remote_addr
}

func (p *AbyssPeer) Send(t ahmp.AHMPMsgType, v any) error {
	//fmt.Println(time.Now().Format("15:04:05.00000") + "| Send: " + p.origin.ID()[:8] + " > " + p.ID()[:8] + " | " + v.(fmt.Stringer).String())
	payload, err := cbor.Marshal(v)
	if err != nil {
		return err
	}
	p.send_ch.In <- ahmp.NewAHMPMessage(t, payload)
	return nil
}
func (p *AbyssPeer) Recv(v *ahmp.AHMPMessage) error {
	return p.ahmp_decoder.Decode(v)
}
func (p *AbyssPeer) Context() context.Context {
	return p.connection.Context()
}

func (p *AbyssPeer) Close() error {
	p.closed <- true
	err := <-p.done_err

	return errors.Join(err, p.origin.registry.ReportPeerClose(p))
}

func (p *AbyssPeer) Equal(subject *AbyssPeer) bool {
	return p.internal_id == subject.internal_id
}
