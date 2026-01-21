package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

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
	fmt.Println("AA")

	tls := r.TLS
	if tls == nil || len(r.TLS.PeerCertificates) < 1 {
		w.Write([]byte("no peer certificate"))
		w.WriteHeader(400)
		return
	}

	fmt.Println("BB")

	tls_self_cert := r.TLS.PeerCertificates[0]
	if tls_self_cert == nil {
		w.Write([]byte("nil peer certificate"))
		w.WriteHeader(400)
		return
	}

	//fmt.Println("client: " + tls_self_cert

	w.Write([]byte("you are the peer"))
	w.WriteHeader(500)

	fmt.Println("CC")
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
				fmt.Println("verifying one peer")

				if len(rawCerts) == 0 {
					return fmt.Errorf("no client certificate")
				}

				cert, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return err
				}

				if err := cert.CheckSignatureFrom(cert); err != nil {
					return err
				}

				// TODO: work with cert

				fmt.Println("good")
				return nil // handshake continues
			},
		},
	}

	log.Printf("Starting HTTP/3 server on https://localhost:4433")
	log.Printf("Serving files from current directory")
	log.Fatal(server.ListenAndServe())
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
