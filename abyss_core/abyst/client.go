package abyst

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"

	"github.com/quic-go/quic-go"
)

// We do a bit of workaround here.
// (peer id, path) is translated to
// https://{peer id}.com/path
// In IHost, uno reverse

type IHost interface {
	AbystDial(ctx context.Context, addr string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error)
}

type AbystClient struct {
	Client *http.Client
}

func (c *AbystClient) Get(id string, path string) (resp *http.Response, err error) {
	return c.Client.Get("https://" + id + ".abyst/" + path)
}
func (c *AbystClient) Head(id string, path string) (resp *http.Response, err error) {
	return c.Client.Head("https://" + id + ".abyst/" + path)
}
func (c *AbystClient) Post(id string, path, contentType string, body io.Reader) (resp *http.Response, err error) {
	return c.Client.Post("https://"+id+".abyst/"+path, contentType, body)
}
