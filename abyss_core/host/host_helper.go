package host

import (
	"context"

	abyss_and "github.com/kadmila/Abyss-Browser/abyss_core/and"
	abyss_net "github.com/kadmila/Abyss-Browser/abyss_core/net_service"

	"github.com/quic-go/quic-go/http3"
)

func NewBetaAbyssHost(ctx context.Context, root_private_key abyss_net.PrivateKey, abyst_server *http3.Server) (*AbyssHost, *SimplePathResolver, error) {
	address_selector, err := abyss_net.NewBetaAddressSelector()
	if err != nil {
		return nil, nil, err
	}
	path_resolver := NewSimplePathResolver()
	netserv, _ := abyss_net.NewBetaNetService(ctx, root_private_key, address_selector, abyst_server)

	return NewAbyssHost(netserv, abyss_and.NewAND(netserv.LocalAURL().Hash), path_resolver), path_resolver, nil
}
