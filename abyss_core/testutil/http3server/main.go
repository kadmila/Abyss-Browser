package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha3"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/quic-go/quic-go/http3"
)

func cacheHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=120, stale-while-revalidate=30")
	w.Header().Set("ETag", "\"a1b2c3d4\"")
	w.Header().Set("Expires", "Thu, 01 Dec 2027 16:00:00 GMT")

	w.Write([]byte("This content should be cached"))
}

func peerIdentityQueryHandler(w http.ResponseWriter, r *http.Request) {
	tls_self_cert := r.TLS.PeerCertificates[2]

	w.Write([]byte("you are " + tls_self_cert.Issuer.CommonName))
	w.WriteHeader(500)
}

func main() {
	// Generate self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatal("Failed to generate certificate:", err)
	}

	// Serve current directory
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(".")))
	mux.Handle("/c/", http.StripPrefix("/c/", http.HandlerFunc(cacheHandler)))
	mux.Handle("/i/", http.StripPrefix("/i/", http.HandlerFunc(peerIdentityQueryHandler)))

	// Configure HTTP/3 server
	server := &http3.Server{
		Addr:    ":4433",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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
			},
		},
	}

	log.Printf("Starting HTTP/3 server on https://localhost:4433")
	log.Printf("Serving files from current directory")
	log.Fatal(server.ListenAndServe())
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

func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Abyss Test Server"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create tls.Certificate
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
