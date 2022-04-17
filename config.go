package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"gopkg.in/ini.v1"
	"net"
	"net/netip"
	"strings"
)

type Peer struct {
	PublicKey    string
	Endpoint     string
	PresharedKey string
	Keepalive    int64
}

type Interface struct {
	PrivateKey string
	Address    []netip.Addr
	DNS        []netip.Addr
	MTU        int
}

type Config struct {
	Interface *Interface
	Peers     []*Peer
}

func parseBase64Key(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string")
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes")
	}
	return hex.EncodeToString(decoded), nil
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func parseAddrsWithoutPrefix(s []string) (addrs []netip.Addr, err error) {
	return parseAddrsOrPrefixes(s, true)
}

func parseAddrs(s []string) (addrs []netip.Addr, err error) {
	return parseAddrsOrPrefixes(s, false)
}

func parseAddrsOrPrefixes(s []string, parsePrefix bool) (addrs []netip.Addr, err error) {
	var addr netip.Addr
	for _, str := range s {
		str = strings.TrimSpace(str)
		if strings.Contains(str, "/") && parsePrefix {
			prefix, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, err
			}
			addr = prefix.Addr()
		} else {
			addr, err = netip.ParseAddr(str)
			if err != nil {
				return nil, err
			}
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func parseInterface(section *ini.Section) (*Interface, error) {
	iface := new(Interface)

	value, err := section.GetKey("PrivateKey")
	if err != nil {
		return nil, err
	}
	iface.PrivateKey, err = parseBase64Key(value.String())
	if err != nil {
		return nil, err
	}

	value, err = section.GetKey("Address")
	if err != nil {
		return nil, err
	}
	iface.Address, err = parseAddrsWithoutPrefix(value.Strings(","))
	if err != nil {
		return nil, err
	}

	value, err = section.GetKey("DNS")
	if err != nil {
		return nil, err
	}
	iface.DNS, err = parseAddrs(value.Strings(","))
	if err != nil {
		return nil, err
	}

	iface.MTU = section.Key("MTU").MustInt(0)

	return iface, nil
}

func parsePeer(section *ini.Section) (*Peer, error) {
	peer := new(Peer)

	value, err := section.GetKey("PublicKey")
	if err != nil {
		return nil, err
	}
	peer.PublicKey, err = parseBase64Key(value.String())
	if err != nil {
		return nil, err
	}

	value, err = section.GetKey("Endpoint")
	if err != nil {
		return nil, err
	}
	peer.Endpoint, err = resolveIPPAndPort(value.String())
	if err != nil {
		return nil, err
	}

	peer.Keepalive, err = section.Key("PersistentKeepalive").Int64()
	if err != nil {
		return nil, err
	}

	peer.PresharedKey = section.Key("PresharedKey").String()

	return peer, nil
}

func NewConfigFromWgQuick(path string) (*Config, error) {
	iniFile, err := ini.InsensitiveLoad(path)
	if err != nil {
		return nil, err
	}

	conf := new(Config)

	ifaceSections, err := iniFile.SectionsByName("Interface")
	if err != nil {
		return nil, err
	}
	if len(ifaceSections) != 1 {
		return nil, errors.New("Configuration file must include one (and only one) interface section")
	}
	conf.Interface, err = parseInterface(ifaceSections[0])
	if err != nil {
		return nil, err
	}

	peerSections, err := iniFile.SectionsByName("Peer")
	if err != nil {
		return nil, err
	}
	if len(peerSections) == 0 {
		return nil, errors.New("Configuration file must include at least one peer section")
	}

	conf.Peers = make([]*Peer, len(peerSections))
	for i, p := range peerSections {
		conf.Peers[i], err = parsePeer(p)
		if err != nil {
			return nil, err
		}
	}

	return conf, nil
}
