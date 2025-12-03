package net_service

import (
	"context"
	"crypto/x509"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"

	"github.com/kadmila/Abyss-Browser/abyss_core/aerr"
	"github.com/kadmila/Abyss-Browser/abyss_core/ahmp"
)

func (h *BetaNetService) PrepareAbyssInbound(listen_ctx context.Context, connection quic.Connection) {
	//watchdog.Info("inbound detected")
	var target *ContextedPeer
	var ahmp_decoder *cbor.Decoder
	var err error

	defer func() {
		if target == nil { //peer not found.
			return
		}

		target.mtx.Lock()
		defer target.mtx.Unlock()

		if err != nil {
			if target.err == nil {
				target.err = err
			}
			target.state = PNCS_CLOSED
		} else {
			switch target.state {
			case PNCS_DISCONNECTED:
				target.state = PNCS_INBOUND
				target.inbound_conn = connection
				target.ahmp_decoder = ahmp_decoder
				go target.listenAhmp()
			case PNCS_OUTBOUND:
				target.state = PNCS_CONNECTED
				target.inbound_conn = connection
				target.ahmp_decoder = ahmp_decoder
				go target.listenAhmp()
				h.abyssPeerCH <- target
			case PNCS_INBOUND, PNCS_CONNECTED:
				connection.CloseWithError(ABYSS_ALREADY_CONNECTED, ABYSS_ALREADY_CONNECTED_M)
			case PNCS_CLOSED:
				connection.CloseWithError(ABYSS_EARLY_RECONNECTION, ABYSS_EARLY_RECONNECTION_M)
			}
		}
	}()

	//get self-signed TLS certificate that the peer presented.
	tls_info := connection.ConnectionState().TLS
	client_tls_cert := tls_info.PeerCertificates[0] //*x509.Certificate, validated

	ahmp_stream, err := connection.AcceptStream(listen_ctx)
	if err != nil {
		err = aerr.NewConnErr(connection, nil, err)
		return
	}
	ahmp_encoder := cbor.NewEncoder(ahmp_stream)
	ahmp_decoder = cbor.NewDecoder(ahmp_stream)

	//receive connecter-side handshake1 self-authentication payload
	var handshake_1_raw []byte
	if err = ahmp_decoder.Decode(&handshake_1_raw); err != nil {
		err = aerr.NewConnErr(connection, nil, err)
		return
	}
	handshake_1, err := h.localIdentity.DecryptHandshake(handshake_1_raw)
	if err != nil {
		err = aerr.NewConnErr(connection, nil, err)
		return
	}
	var abyss_bind_cert []byte
	if err = cbor.Unmarshal(handshake_1, &abyss_bind_cert); err != nil {
		err = aerr.NewConnErr(connection, nil, err)
		return
	}
	abyss_bind_cert_x509, err := x509.ParseCertificate(abyss_bind_cert)
	if err != nil {
		err = aerr.NewConnErr(connection, nil, err)
		return
	}

	//****Important****
	//TODO: make sure that only one inbound connection is answered for a peer. use atomic.
	//retrieve known identity and verify
	peer_hash := abyss_bind_cert_x509.Issuer.CommonName
	target, err = h.peers.Wait(listen_ctx, peer_hash)
	if err != nil {
		err = aerr.NewConnErrM(connection, nil, "unknown peer")
		return
	}
	if err = target.identity.VerifyTLSBinding(abyss_bind_cert_x509, client_tls_cert); err != nil {
		err = aerr.NewConnErr(connection, nil, err)
		return
	}

	//send local tls-abyss binding cert
	if err = ahmp_encoder.Encode(h.tlsIdentity.abyss_bind_cert); err != nil {
		err = aerr.NewConnErr(connection, nil, err)
		return
	}

	//return: defer will update the peer.
}

func (p *AbyssPeer) listenAhmp() {
	var err error
	defer func() {
		p.mtx.Lock()
		p.state = PNCS_CLOSED
		p.err = err
		p.mtx.Unlock()
	}()

	for {
		var ahmp_type int
		err := p.ahmp_decoder.Decode(&ahmp_type)
		if err != nil {
			return
		}

		//fmt.Println(p.inbound_conn.LocalAddr().String() + " < " + p.inbound_conn.RemoteAddr().String() + " " + strconv.Itoa(ahmp_type))
		switch ahmp_type {
		case ahmp.JN_T:
			//fmt.Println("receiving JN")
			var raw_msg ahmp.RawJN
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing JN"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing JN"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.JOK_T:
			//fmt.Println("receiving JOK")
			var raw_msg ahmp.RawJOK
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing JOK"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing JOK"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.JDN_T:
			//fmt.Println("receiving JDN")
			var raw_msg ahmp.RawJDN
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing JDN"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing JDN"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.JNI_T:
			//fmt.Println("receiving JNI")
			var raw_msg ahmp.RawJNI
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing JNI"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing JNI"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.MEM_T:
			//fmt.Println("receiving MEM")
			var raw_msg ahmp.RawMEM
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing MEM"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing MEM"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.SJN_T:
			//fmt.Println("receiving SJN")
			var raw_msg ahmp.RawSJN
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing SJN"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing SJN"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.CRR_T:
			//fmt.Println("receiving CRR")
			var raw_msg ahmp.RawCRR
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing CRR"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing CRR"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.RST_T:
			//fmt.Println("receiving RST")
			var raw_msg ahmp.RawRST
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing RST"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing RST"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.SOA_T:
			//fmt.Println("receiving SOA")
			var raw_msg ahmp.RawSOA
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing SOA"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing SOA"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		case ahmp.SOD_T:
			//fmt.Println("receiving SOD")
			var raw_msg ahmp.RawSOD
			err = p.ahmp_decoder.Decode(&raw_msg)
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing SOD"), err)}
				return
			}
			parsed_msg, err := raw_msg.TryParse()
			if err != nil {
				p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.Join(errors.New("parsing SOD"), err)}
				return
			}
			p.ahmp_decoded_ch <- parsed_msg
		default:
			p.ahmp_decoded_ch <- &ahmp.INVAL{Err: errors.New("unknown AHMP message type")}
			return
		}
	}
}
