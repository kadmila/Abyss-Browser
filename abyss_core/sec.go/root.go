package sec

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha3"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// PrivateKey is stupid but handy ad-hoc interface.
// golang should revise standard crypto.PrivateKey interface.
type PrivateKey interface {
	Public() crypto.PublicKey
}

func NewRootPrivateKey() (PrivateKey, error) {
	_, privkey, err := ed25519.GenerateKey(rand.Reader)
	return privkey, err
}

// AbyssRootSecrets is the root identity of a user.
type AbyssRootSecrets struct {
	root_priv_key       PrivateKey
	root_self_cert_x509 *x509.Certificate
	root_self_cert      string //pem
	root_id_hash        string

	handshake_priv_key *rsa.PrivateKey //may support others in future
	handshake_key_cert string          //pem
}

func NewAbyssRootSecrets(root_private_key PrivateKey) (*AbyssRootSecrets, error) {
	root_public_key := root_private_key.Public()

	//root certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	peer_hash, err := AbyssIDFromKey(root_public_key)
	if err != nil {
		return nil, err
	}
	r_template := x509.Certificate{
		Issuer: pkix.Name{
			CommonName: peer_hash,
		},
		Subject: pkix.Name{
			CommonName: peer_hash,
		},
		NotBefore:             time.Now().Add(time.Duration(-1) * time.Second), //1-sec backdate, for badly synced peers.
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	r_derBytes, err := x509.CreateCertificate(rand.Reader, &r_template, &r_template, root_public_key, root_private_key)
	if err != nil {
		return nil, err
	}
	r_x509, err := x509.ParseCertificate(r_derBytes)
	if err != nil {
		return nil, err
	}

	//handshake key
	handshake_private_key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	h_template := x509.Certificate{
		Issuer: pkix.Name{
			CommonName: peer_hash,
		},
		Subject: pkix.Name{
			CommonName: "H-" + peer_hash + "-OAEP-SHA3-256-AES-256-GCM", //handshake encryption key, RSA OAEP + AES-256 encryption
		},
		NotBefore:             time.Now().Add(time.Duration(-1) * time.Second), //1-sec backdate, for badly synced peers.
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageEncipherOnly,
		BasicConstraintsValid: true,
	}
	h_derBytes, err := x509.CreateCertificate(rand.Reader, &h_template, &r_template, &handshake_private_key.PublicKey, root_private_key)
	if err != nil {
		return nil, err
	}

	var root_cert_buf bytes.Buffer
	err = pem.Encode(&root_cert_buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: r_derBytes,
	})
	if err != nil {
		return nil, err
	}

	var handshake_cert_buf bytes.Buffer
	err = pem.Encode(&handshake_cert_buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: h_derBytes,
	})
	if err != nil {
		return nil, err
	}
	return &AbyssRootSecrets{
		root_priv_key:       root_private_key,
		root_self_cert_x509: r_x509,
		root_self_cert:      root_cert_buf.String(),
		root_id_hash:        peer_hash,

		handshake_priv_key: handshake_private_key,
		handshake_key_cert: handshake_cert_buf.String(),
	}, nil
}

func (r *AbyssRootSecrets) IDHash() string {
	return r.root_id_hash
}
func (r *AbyssRootSecrets) DecryptHandshake(body []byte) ([]byte, error) {
	key_block_size := r.handshake_priv_key.Size()
	aes_key_nonce, err := rsa.DecryptOAEP(sha3.New256(), nil, r.handshake_priv_key, body[:key_block_size], nil)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aes_key_nonce[:32])
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesGCM.Open(nil, aes_key_nonce[32:], body[key_block_size:], nil)

	return plaintext, err
}
func (r *AbyssRootSecrets) RootCertificate() string {
	return r.root_self_cert
}
func (r *AbyssRootSecrets) HandshakeKeyCertificate() string {
	return r.handshake_key_cert
}

type TLSIdentity struct {
	priv_key        crypto.PrivateKey
	tls_self_cert   []byte //der
	abyss_bind_cert []byte //der
}

func (r *AbyssRootSecrets) NewTLSIdentity() (*TLSIdentity, error) {
	ed25519_public_key, ed25519_private_key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	self_template := x509.Certificate{
		NotBefore:             time.Now().Add(time.Duration(-1) * time.Second), //1-sec backdate, for badly synced peers.
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),              // Valid for 7 days
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	self_derBytes, err := x509.CreateCertificate(rand.Reader, &self_template, &self_template, ed25519_public_key, ed25519_private_key)
	if err != nil {
		return nil, err
	}

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	auth_template := x509.Certificate{
		Issuer: pkix.Name{
			CommonName: r.root_id_hash,
		},
		Subject: pkix.Name{
			CommonName: "T-" + r.root_id_hash,
		},
		NotBefore:             time.Now().Add(time.Duration(-1) * time.Second), //1-sec backdate, for badly synced peers.
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),              // Valid for 7 days
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	auth_derBytes, err := x509.CreateCertificate(rand.Reader, &auth_template, r.root_self_cert_x509, ed25519_public_key, r.root_priv_key)
	if err != nil {
		return nil, err
	}

	return &TLSIdentity{
		priv_key:        ed25519_private_key,
		tls_self_cert:   self_derBytes,
		abyss_bind_cert: auth_derBytes,
	}, nil
}
