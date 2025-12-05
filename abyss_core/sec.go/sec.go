// package sec provides security-related functions for abyss.
// This package includes implementations for abyss certificate
// chain and its verification.
package sec

import (
	"crypto"
	"crypto/sha3"
	"crypto/x509"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
)

func AbyssIDFromKey(pub crypto.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("unable to marshal public key to DER: %v", err)
	}
	hasher := sha3.New512()
	hasher.Write(derBytes)
	return "H-" + base58.Encode(hasher.Sum(nil)), nil
}
