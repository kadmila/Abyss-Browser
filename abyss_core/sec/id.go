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
	"net/netip"
	"slices"
	"sync"
	"time"
)

// AbyssPeerIdentity contains a set of keys and certificates that identifies a peer.
type AbyssPeerIdentity struct {
	id                  string
	root_self_cert_x509 *x509.Certificate
	root_self_cert      string
	root_self_cert_der  []byte

	// handshake info is mutable.
	handshake_info_mtx      sync.RWMutex
	handshake_info_cert     string
	handshake_info_cert_der []byte
	handshake_pub_key       *rsa.PublicKey
	address_candidates      []netip.AddrPort
	issue_time              time.Time
}

// NewAbyssPeerIdentity conducts several verification for the certificates.
// root self certificate must have same Issuer and Subject, with correct hash digest.
// Abyss uses Common Name (CN).
func NewAbyssPeerIdentity(root_self_cert *x509.Certificate, handshake_info_cert *x509.Certificate) (*AbyssPeerIdentity, error) {
	// validate root self cert
	id, err := abyssIDFromKey(root_self_cert.PublicKey)
	if err != nil {
		return nil, errors.New("invalid root certificate; failed to hash")
	}
	if root_self_cert.Issuer.CommonName != id {
		return nil, errors.New("invalid root certificate; unrecognized name: " + root_self_cert.Issuer.CommonName)
	}
	if root_self_cert.Subject.CommonName != id {
		return nil, errors.New("invalid root certificate; not self-signed: " + root_self_cert.Subject.CommonName)
	}

	// re-encode der and pem. We don't re-use input values, for the sake of sanity.
	root_self_cert_der := root_self_cert.Raw
	root_self_cert_pem_block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root_self_cert_der,
	}
	var root_self_cert_pem_buf bytes.Buffer
	err = pem.Encode(&root_self_cert_pem_buf, root_self_cert_pem_block)
	if err != nil {
		return nil, err
	}
	root_self_cert_pem := root_self_cert_pem_buf.String()

	result := &AbyssPeerIdentity{
		id:                  id,
		root_self_cert_x509: root_self_cert,
		root_self_cert:      root_self_cert_pem,
		root_self_cert_der:  root_self_cert_der,
	}
	return result, result.UpdateHandshakeInfo(handshake_info_cert)
}

func (p *AbyssPeerIdentity) UpdateHandshakeInfo(handshake_info_cert *x509.Certificate) error {
	// validate handshake key cert
	if err := handshake_info_cert.CheckSignatureFrom(p.root_self_cert_x509); err != nil {
		return err
	}
	if handshake_info_cert.Issuer.CommonName != p.id {
		return errors.New("invalid handshake key certificate; issuer mismatch")
	}
	if handshake_info_cert.Subject.CommonName != "h."+p.id {
		return errors.New("invalid handshake key certificate name: " + handshake_info_cert.Subject.CommonName)
	}
	pkey, ok := handshake_info_cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("unsupported public key")
	}

	// check if the certificate is newer
	if p.issue_time.After(handshake_info_cert.NotBefore) {
		return nil // ignore
	}

	// parse address candidates
	address_candidates := make([]netip.AddrPort, 0, len(handshake_info_cert.URIs))
	ip_seen := make(map[netip.Addr]bool)
	if len(handshake_info_cert.URIs) > 7 {
		return errors.New("invalid handshake info certificate; too many address candidates")
	}
	for _, uri := range handshake_info_cert.URIs {
		// Verify scheme
		if uri.Scheme != "udp" {
			continue
		}

		// Parse address
		addr, err := netip.ParseAddrPort(uri.Host)
		if err != nil {
			continue // Skip invalid addresses
		}

		// Step 5: Check IP duplicates
		ip := addr.Addr()
		if ip_seen[ip] {
			return errors.New("invalid address certificate; duplicate ip")
		}

		ip_seen[ip] = true
		address_candidates = append(address_candidates, addr)
	}
	address_candidates = slices.Clip(address_candidates)

	handshake_info_cert_der := handshake_info_cert.Raw
	handshake_info_cert_pem_block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: handshake_info_cert_der,
	}
	var handshake_info_cert_pem_buf bytes.Buffer
	if err := pem.Encode(&handshake_info_cert_pem_buf, handshake_info_cert_pem_block); err != nil {
		return err
	}
	handshake_info_cert_pem := handshake_info_cert_pem_buf.String()

	p.handshake_info_mtx.Lock()
	defer p.handshake_info_mtx.Unlock()

	p.handshake_info_cert = handshake_info_cert_pem
	p.handshake_info_cert_der = handshake_info_cert_der
	p.handshake_pub_key = pkey
	p.address_candidates = address_candidates
	p.issue_time = handshake_info_cert.NotBefore
	return nil
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

	p.handshake_info_mtx.RLock()
	encrypted_aes_secret, err := rsa.EncryptOAEP(sha3.New256(), rand.Reader, p.handshake_pub_key, aes_secret, nil)
	p.handshake_info_mtx.RUnlock()

	return encrypted_payload, encrypted_aes_secret, err
}
func (p *AbyssPeerIdentity) VerifyTLSBinding(tls_binding_cert *x509.Certificate, tls_cert *x509.Certificate) error {
	if err := tls_binding_cert.CheckSignatureFrom(p.root_self_cert_x509); err != nil {
		return err
	}
	if !tls_binding_cert.PublicKey.(ed25519.PublicKey).Equal(tls_cert.PublicKey) {
		return errors.New("invalid TLS binding key certificate; TLS public key mismatch")
	}
	if tls_binding_cert.Issuer.CommonName != p.id {
		return errors.New("invalid TLS binding key certificate; issuer mismatch")
	}
	if tls_binding_cert.Subject.CommonName != "tls."+p.id {
		return errors.New("invalid root certificate; unrecognized name")
	}
	return nil
}

func (p *AbyssPeerIdentity) ID() string                 { return p.id }
func (p *AbyssPeerIdentity) RootCertificate() string    { return p.root_self_cert }
func (p *AbyssPeerIdentity) RootCertificateDer() []byte { return p.root_self_cert_der }
func (p *AbyssPeerIdentity) HandshakeKeyCertificate() string {
	p.handshake_info_mtx.RLock()
	defer p.handshake_info_mtx.RUnlock()
	return p.handshake_info_cert
}
func (p *AbyssPeerIdentity) HandshakeKeyCertificateDer() []byte {
	p.handshake_info_mtx.RLock()
	defer p.handshake_info_mtx.RUnlock()
	return p.handshake_info_cert_der
}
func (p *AbyssPeerIdentity) AddressCandidates() []netip.AddrPort {
	p.handshake_info_mtx.RLock()
	defer p.handshake_info_mtx.RUnlock()
	return p.address_candidates
}
func (p *AbyssPeerIdentity) IssueTime() time.Time {
	p.handshake_info_mtx.RLock()
	defer p.handshake_info_mtx.RUnlock()
	return p.issue_time
}
