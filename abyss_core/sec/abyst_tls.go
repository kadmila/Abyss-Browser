package sec

import (
	"crypto"
	"crypto/sha3"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/kadmila/Abyss-Browser/abyss_core/ani"
	"github.com/quic-go/quic-go/http3"
)

const (
	NextProtoAbyss = "abyss"
)

// TLSIdentity is constructed from AbyssRootSecretes.NewTLSIdentity().
type TLSIdentity struct {
	priv_key        crypto.PrivateKey
	tls_self_cert   []byte //der
	abyss_bind_cert []byte //der
}

// VerifiedTlsCertMap relates sha-3 256 digests of verified mTLS certificates
// with the corresponding peer id.
// The TLS certificates are the ones used for ephemeral TLS handshake for abyss connection.
// This object is thread safe.
// TODO: the peer id will be attached as a http request header (X-Abyss-ID)
type VerifiedTlsCertMap struct {
	inner sync.Map // map[[32]byte]string
}

func NewVerifiedTlsCertMap() *VerifiedTlsCertMap {
	return &VerifiedTlsCertMap{
		inner: sync.Map{},
	}
}

func (m *VerifiedTlsCertMap) Store(key [32]byte, value string) {
	m.inner.Store(key, value)
}
func (m *VerifiedTlsCertMap) Load(key [32]byte) (string, bool) {
	value, ok := m.inner.Load(key)
	str, ok2 := value.(string)
	return str, ok && ok2
}
func (m *VerifiedTlsCertMap) Delete(key [32]byte) {
	m.inner.Delete(key)
}

func HashTlsCertificate(cert *x509.Certificate) [32]byte {
	return sha3.Sum256(cert.Raw)
}

// NewServerTlsConf provides *tls.Config for server-side
func (t *TLSIdentity) NewServerTlsConf(abyst_cert_checker ani.IAbystTlsCertChecker) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{t.tls_self_cert},
				PrivateKey:  t.priv_key,
			},
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) != 1 {
				return errors.New("only one TLS certificate should be presented from a client")
			}
			cert := cs.PeerCertificates[0]

			if err := cert.CheckSignatureFrom(cert); err != nil {
				return err
			}
			switch cs.NegotiatedProtocol {
			case http3.NextProtoH3:
				if _, ok := abyst_cert_checker.GetPeerIdFromTlsCertificate(cert); !ok {
					return errors.New("unknown peer")
				}
				return nil
			case NextProtoAbyss:
				// peer authentication will take part after connection establishment.
				return nil
			default:
				return errors.New("invalid protocol negotiated on ALPN")
			}
		},
		NextProtos: []string{NextProtoAbyss, http3.NextProtoH3},
		ClientAuth: tls.RequireAnyClientCert,
	}
}

// NewAbyssClientTlsConf provides *tls.Config for client-side (abyss)
func (t *TLSIdentity) NewAbyssClientTlsConf() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{t.tls_self_cert},
				PrivateKey:  t.priv_key,
			},
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return errors.New("only one TLS certificate should be presented from a client")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if err := cert.CheckSignatureFrom(cert); err != nil {
				return err
			}
			return nil
		},
		NextProtos:         []string{NextProtoAbyss},
		InsecureSkipVerify: true, // we do certificate verification afterwards.
	}
}

// NewAbystClientTlsConf provides *tls.Config for client-side (abyst)
func (t *TLSIdentity) NewAbystClientTlsConf(verified_tls_certs *VerifiedTlsCertMap) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{t.tls_self_cert},
				PrivateKey:  t.priv_key,
			},
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) != 1 {
				return errors.New("only one TLS certificate should be presented from a client")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if err := cert.CheckSignatureFrom(cert); err != nil {
				return err
			}
			cert_hash := HashTlsCertificate(cert)
			if _, ok := verified_tls_certs.Load(cert_hash); !ok {
				return errors.New("unknown peer")
			}
			return nil
		},
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: true, // we do certificate verification afterwards.
	}
}

func (t *TLSIdentity) AbyssBindingCertificate() []byte { return t.abyss_bind_cert }
