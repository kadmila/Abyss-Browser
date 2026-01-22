package main

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go/http3"
)

func NewCollocatedH3Server(cert tls.Certificate, handler http.Handler) *http3.Server {
	return &http3.Server{
		Addr:    ":4433",
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates:          []tls.Certificate{cert},
			ClientAuth:            tls.RequireAnyClientCert,
			VerifyPeerCertificate: VerifyCollocatedHttp3PeerCertificate,
		},
	}
}
