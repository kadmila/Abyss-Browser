package sec

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha3"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type AbyssPeerIdentity struct {
	id                  string
	root_self_cert_x509 *x509.Certificate
	handshake_pub_key   *rsa.PublicKey

	root_self_cert         string
	root_self_cert_der     []byte
	handshake_key_cert     string
	handshake_key_cert_der []byte
}

func NewAbyssPeerIdentityFromPEM(root_self_cert string, handshake_key_cert string) (*AbyssPeerIdentity, error) {
	root_self_cert_der, _ := pem.Decode([]byte(root_self_cert))
	if root_self_cert_der == nil {
		return nil, errors.New("failed to parse certificate")
	}
	handshake_key_cert_der, _ := pem.Decode([]byte(handshake_key_cert))
	if handshake_key_cert_der == nil {
		return nil, errors.New("failed to parse certificate")
	}
	return NewAbyssPeerIdentityFromDER(root_self_cert_der.Bytes, handshake_key_cert_der.Bytes)
}

func NewAbyssPeerIdentityFromDER(root_self_cert []byte, handshake_key_cert []byte) (*AbyssPeerIdentity, error) {
	root_self_cert_x509, err := x509.ParseCertificate(root_self_cert)
	if err != nil {
		return nil, err
	}
	handshake_key_cert_x509, err := x509.ParseCertificate(handshake_key_cert)
	if err != nil {
		return nil, err
	}
	return NewAbyssPeerIdentity(root_self_cert_x509, handshake_key_cert_x509)
}

// NewAbyssPeerIdentity conducts several verification for the certificates.
// root self certificate must have same Issuer and Subject, with correct hash digest.
// Abyss uses Common Name (CN).
func NewAbyssPeerIdentity(root_self_cert *x509.Certificate, handshake_key_cert *x509.Certificate) (*AbyssPeerIdentity, error) {
	// validate root self cert
	id, err := AbyssIDFromKey(root_self_cert.PublicKey)
	if err != nil {
		return nil, errors.New("invalid root certificate; failed to hash")
	}
	if root_self_cert.Issuer.CommonName != id {
		return nil, errors.New("invalid root certificate; name mismatch")
	}
	if root_self_cert.Subject.CommonName != id {
		return nil, errors.New("invalid root certificate; not self-signed")
	}

	// validate handshake key cert
	if handshake_key_cert.Issuer.CommonName != id {
		return nil, errors.New("invalid handshake certificate; issuer mismatch")
	}
	if err := handshake_key_cert.CheckSignatureFrom(root_self_cert); err != nil {
		return nil, err
	}
	// currently, we only support OAEP-SHA3-256-AES-256-GCM handhskake key. We may support more in the future.
	if handshake_key_cert.Subject.CommonName != "OAEP-SHA3-256-AES-256-GCM."+id {
		return nil, errors.New("unsupported public key encryption scheme: " + handshake_key_cert.Subject.CommonName)
	}
	pkey, ok := handshake_key_cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unsupported public key")
	}

	// re-encode der and pem. We don't re-use input values, for the sake of sanity.
	root_self_cert_der := root_self_cert.Raw
	handshake_key_cert_der := handshake_key_cert.Raw

	root_self_cert_pem_block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root_self_cert_der,
	}
	handshake_key_cert_pem_block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: handshake_key_cert_der,
	}

	var root_self_cert_pem_buf bytes.Buffer
	err = pem.Encode(&root_self_cert_pem_buf, root_self_cert_pem_block)
	if err != nil {
		return nil, err
	}
	var handshake_key_cert_pem_buf bytes.Buffer
	err = pem.Encode(&handshake_key_cert_pem_buf, handshake_key_cert_pem_block)
	if err != nil {
		return nil, err
	}

	root_self_cert_pem := root_self_cert_pem_buf.String()
	handshake_key_cert_pem := handshake_key_cert_pem_buf.String()

	return &AbyssPeerIdentity{
		root_self_cert_x509: root_self_cert,
		id:                  id,
		handshake_pub_key:   pkey,

		root_self_cert:         root_self_cert_pem,
		root_self_cert_der:     root_self_cert_der,
		handshake_key_cert:     handshake_key_cert_pem,
		handshake_key_cert_der: handshake_key_cert_der,
	}, nil
}

func (p *AbyssPeerIdentity) IDHash() string {
	return p.id
}
func (p *AbyssPeerIdentity) EncryptHandshake(payload []byte) ([]byte, error) {
	aesKey := make([]byte, 32) //AES-256 key
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12) //AES-GCM nonce
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encrypted_payload := aesGCM.Seal(nil, nonce, payload, nil)

	encrypted_key_nonce, err := rsa.EncryptOAEP(sha3.New256(), rand.Reader, p.handshake_pub_key, append(aesKey, nonce...), nil)
	return append(encrypted_key_nonce, encrypted_payload...), err
}
func (p *AbyssPeerIdentity) VerifyTLSBinding(abyss_bind_cert *x509.Certificate, tls_cert *x509.Certificate) error {
	if !abyss_bind_cert.PublicKey.(ed25519.PublicKey).Equal(tls_cert.PublicKey) {
		return errors.New("tls public key mismatch")
	}

	if abyss_bind_cert.Issuer.CommonName != p.id {
		return errors.New("issuer mismatch")
	}
	if abyss_bind_cert.Subject.CommonName != "tls."+p.id {
		return errors.New("subject mismatch")
	}
	if err := abyss_bind_cert.CheckSignatureFrom(p.root_self_cert_x509); err != nil {
		return err
	}
	return nil
}

func (p *AbyssPeerIdentity) ID() string                         { return p.id }
func (p *AbyssPeerIdentity) RootCertificate() string            { return p.root_self_cert }
func (p *AbyssPeerIdentity) RootCertificateDer() []byte         { return p.root_self_cert_der }
func (p *AbyssPeerIdentity) HandshakeKeyCertificate() string    { return p.handshake_key_cert }
func (p *AbyssPeerIdentity) HandshakeKeyCertificateDer() []byte { return p.handshake_key_cert_der }
