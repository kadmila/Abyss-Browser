// package sec provides security-related functions for abyss.
// This package includes implementations for abyss certificate
// chain and its verification.
//
// In abyss certificate chain, subdomain represents a specific role/use case.
// h.{id} indicates a handshake encryption key for OAEP-SHA3-256-AES-256-GCM.
// tls.{id} indicates a TLS binding certificate.
// loc.{id} indicates a short-lived address location certificate (< 1 hour validity).
package sec

import (
	"crypto"
	"crypto/sha3"
	"crypto/x509"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
)

func abyssIDFromKey(pub crypto.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("unable to marshal public key to DER: %v", err)
	}
	hasher := sha3.New512()
	hasher.Write(derBytes)
	return "H-" + base58.Encode(hasher.Sum(nil)), nil
}
