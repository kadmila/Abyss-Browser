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
	"time"
)

// AbyssPeerIdentity contains a set of keys and certificates that identifies a peer.
type AbyssPeerIdentity struct {
	id                  string
	root_self_cert_x509 *x509.Certificate
	handshake_pub_key   *rsa.PublicKey
	issue_time          time.Time

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
	id, err := abyssIDFromKey(root_self_cert.PublicKey)
	if err != nil {
		return nil, errors.New("invalid root certificate; failed to hash")
	}
	if root_self_cert.Issuer.CommonName != id {
		return nil, errors.New("invalid root certificate; unrecognized name")
	}
	if root_self_cert.Subject.CommonName != id {
		return nil, errors.New("invalid root certificate; not self-signed")
	}

	// validate handshake key cert
	if err := handshake_key_cert.CheckSignatureFrom(root_self_cert); err != nil {
		return nil, err
	}
	if handshake_key_cert.Issuer.CommonName != id {
		return nil, errors.New("invalid handshake key certificate; issuer mismatch")
	}
	if handshake_key_cert.Subject.CommonName != "h."+id {
		return nil, errors.New("invalid handshake key certificate name: " + handshake_key_cert.Subject.CommonName)
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
		issue_time:          handshake_key_cert.NotBefore,

		root_self_cert:         root_self_cert_pem,
		root_self_cert_der:     root_self_cert_der,
		handshake_key_cert:     handshake_key_cert_pem,
		handshake_key_cert_der: handshake_key_cert_der,
	}, nil
}

// EncryptHandshake encrypts the payload with the handshake encryption key.
// First, the payload is encrypted with a random AES-128 key and GCM nonce.
// Then, the key and nonce are encrypted with RSA OAEP.
// The return values are encrypted payload, encrypted aes secret, and error.
func (p *AbyssPeerIdentity) EncryptHandshake(payload []byte) ([]byte, []byte, error) {
	// Generate a random 32-byte AES-256 key
	aesKey := make([]byte, 32)
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, nil, err
	}
	// Generate a 12-byte nonce (standard size for AES-GCM)
	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}
	// Create a new AES block cipher using the generated key
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}
	// Wrap the AES block cipher in GCM mode, with AEAD
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	// Encrypt the payload using AES-GCM
	encrypted_payload := aesGCM.Seal(nil, nonce, payload, nil)

	// Encrypt the aes secret (key and nonce) in RSA OAEP
	aes_secret := append(aesKey, nonce...)
	encrypted_aes_secret, err := rsa.EncryptOAEP(sha3.New256(), rand.Reader, p.handshake_pub_key, aes_secret, nil)
	return encrypted_payload, encrypted_aes_secret, err
}
func (p *AbyssPeerIdentity) VerifyTLSBinding(abyss_bind_cert *x509.Certificate, tls_cert *x509.Certificate) error {
	if err := abyss_bind_cert.CheckSignatureFrom(p.root_self_cert_x509); err != nil {
		return err
	}
	if !abyss_bind_cert.PublicKey.(ed25519.PublicKey).Equal(tls_cert.PublicKey) {
		return errors.New("invalid TLS binding key certificate; TLS public key mismatch")
	}
	if abyss_bind_cert.Issuer.CommonName != p.id {
		return errors.New("invalid TLS binding key certificate; issuer mismatch")
	}
	if abyss_bind_cert.Subject.CommonName != "tls."+p.id {
		return errors.New("invalid root certificate; unrecognized name")
	}
	return nil
}

func (p *AbyssPeerIdentity) ID() string                         { return p.id }
func (p *AbyssPeerIdentity) RootCertificate() string            { return p.root_self_cert }
func (p *AbyssPeerIdentity) RootCertificateDer() []byte         { return p.root_self_cert_der }
func (p *AbyssPeerIdentity) HandshakeKeyCertificate() string    { return p.handshake_key_cert }
func (p *AbyssPeerIdentity) HandshakeKeyCertificateDer() []byte { return p.handshake_key_cert_der }
func (p *AbyssPeerIdentity) IssueTime() time.Time               { return p.issue_time }
