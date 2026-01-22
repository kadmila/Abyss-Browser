package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha3"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
)

func VerifyCollocatedHttp3PeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	is_success := false
	defer func() {
		if !is_success {
			fmt.Println("peer authentication failed")
		}
	}()

	if len(rawCerts) < 3 {
		return fmt.Errorf("insufficient client certificates")
	}

	// ensure tls cert is self-signed.
	tls_self_cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	if err := tls_self_cert.CheckSignatureFrom(tls_self_cert); err != nil {
		return err
	}

	// validate abyss self signed certificate.
	abyss_self_cert, err := x509.ParseCertificate(rawCerts[2])
	if err != nil {
		return err
	}
	id, err := abyssIDFromKey(abyss_self_cert.PublicKey)
	if err != nil {
		return errors.New("invalid root certificate; failed to hash")
	}
	if abyss_self_cert.Issuer.CommonName != id {
		return errors.New("invalid root certificate; unrecognized name")
	}
	if abyss_self_cert.Subject.CommonName != id {
		return errors.New("invalid root certificate; not self-signed")
	}

	// ensure binding cert has the same public key with the tls cert.
	// validate binding
	abyss_bind_cert, err := x509.ParseCertificate(rawCerts[1])
	if err != nil {
		return err
	}
	if !abyss_bind_cert.PublicKey.(ed25519.PublicKey).Equal(tls_self_cert.PublicKey) {
		return errors.New("invalid TLS binding key certificate; TLS public key mismatch")
	}
	if abyss_bind_cert.Issuer.CommonName != id {
		return errors.New("invalid TLS binding key certificate; issuer mismatch")
	}
	if abyss_bind_cert.Subject.CommonName != "tls."+id {
		return errors.New("invalid root certificate; unrecognized name")
	}
	if err := abyss_bind_cert.CheckSignatureFrom(abyss_self_cert); err != nil {
		return err
	}

	// TODO: work with cert
	is_success = true
	fmt.Println("peer: " + abyss_self_cert.Issuer.CommonName)
	return nil // handshake continues
}

func abyssIDFromKey(pub crypto.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("unable to marshal public key to DER: %v", err)
	}
	hasher := sha3.New512()
	hasher.Write(derBytes)
	return "H-" + base58.Encode(hasher.Sum(nil)), nil
}
