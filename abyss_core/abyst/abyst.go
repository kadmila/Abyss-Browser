// abyst package provides abyst gateway
package abyst

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/kadmila/Abyss-Browser/abyss_core/sec"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// AbystGateway handles dynamic routing and reverse proxy configuration.
type AbystGateway struct {
	internalMux atomic.Pointer[http.ServeMux]
}

func NewAbystGateway() *AbystGateway {
	result := &AbystGateway{}
	result.internalMux.Store(http.NewServeMux())
	return result
}

// SetInternalMuxFromJson constructs and sets a new abyst service mux from json string.
func (g *AbystGateway) SetInternalMuxFromJson(config_str string) error {
	var config map[string]any
	err := json.Unmarshal([]byte(config_str), &config)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	err = dfsConstructHttpMux(mux, config, "")
	if err != nil {
		return err
	}
	g.internalMux.Store(mux)
	return nil
}

func dfsConstructHttpMux(mux *http.ServeMux, data map[string]any, prev_path string) error {
	for path, entry := range data {
		current_path := prev_path + "/" + path

		switch e := entry.(type) {
		case map[string]any:
			dfsConstructHttpMux(mux, e, current_path)
		case string:
			url, err := url.Parse(e)
			if err != nil {
				return err
			}
			switch url.Scheme {
			case "http", "https":
				mux.Handle(current_path+"/", http.StripPrefix(current_path, httputil.NewSingleHostReverseProxy(url)))
			case "dir":
				mux.Handle(current_path+"/", http.StripPrefix(current_path, http.FileServer(http.Dir(strings.TrimLeft(e[4:], "/")))))
			default:
				return errors.New("cannot process entry: " + current_path)
			}
		default:
			return errors.New("cannot process entry: " + current_path)
		}
	}
	return nil
}

// ServeConnection creates a dedicated handler for the abyst connection, and serve it.
func (g *AbystGateway) ServeConnection(conn quic.Connection, peer_identity *sec.AbyssPeerIdentity) error {
	server := &http3.Server{
		Handler: g.newAbystHandler(peer_identity),
	}
	return server.ServeQUICConn(conn)
}

type AbystHandler struct {
	abyst_hub     *AbystGateway
	peer_identity *sec.AbyssPeerIdentity
}

func (g *AbystGateway) newAbystHandler(peer_identity *sec.AbyssPeerIdentity) *AbystHandler {
	return &AbystHandler{
		abyst_hub:     g,
		peer_identity: peer_identity,
	}
}

func (h *AbystHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// shallow copy of request.
	r_copy := new(http.Request)
	*r_copy = *r

	r_copy.Header.Set("X-Abyss-ID", h.peer_identity.ID())

	h.abyst_hub.internalMux.Load().ServeHTTP(w, r_copy)
}
