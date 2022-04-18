package main

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"

	"github.com/armon/go-socks5"
	"golang.org/x/net/context"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type TunnelResolver struct {
	socks5.NameResolver
	tnet *netstack.Net
}

func NewTunnelResolver(tnet *netstack.Net) (resolver *TunnelResolver) {
	resolver = new(TunnelResolver)
	resolver.tnet = tnet
	return resolver
}

func (r TunnelResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := r.tnet.LookupContextHost(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	naddr := len(addrs)
	if naddr == 0 {
		return nil, nil, fmt.Errorf("no address found for: %s", name)
	}

	rand.Shuffle(naddr, func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	var addr netip.Addr
	for _, saddr := range addrs {
		addr, err = netip.ParseAddr(saddr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, nil, err
	}

	return ctx, addr.AsSlice(), nil
}
