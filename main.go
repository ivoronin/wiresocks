package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"gopkg.in/ini.v1"

	"github.com/armon/go-socks5"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const default_preshared_key = "0000000000000000000000000000000000000000000000000000000000000000"
const default_mtu = 1420

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

func parseIPs(s []string) ([]netip.Addr, error) {
	ips := []netip.Addr{}
	for _, str := range s {
		str = strings.TrimSpace(str)
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func createIPCRequest(conf *ini.File) (string, error) {
	iface := conf.Section("Interface")
	peer := conf.Section("Peer")

	key, err := iface.GetKey("PrivateKey")
	if err != nil {
		return "", err
	}
	private_key, err := parseBase64Key(key.String())
	if err != nil {
		return "", err
	}

	key, err = peer.GetKey("PublicKey")
	if err != nil {
		return "", err
	}
	peer_public_key, err := parseBase64Key(key.String())
	if err != nil {
		return "", err
	}

	key, err = peer.GetKey("Endpoint")
	if err != nil {
		return "", err
	}
	peer_endpoint, err := resolveIPPAndPort(key.String())
	if err != nil {
		return "", err
	}

	keepalive := peer.Key("PersistentKeepalive").MustInt64(0)
	peer_preshared_key := peer.Key("PresharedKey").MustString(default_preshared_key)

	request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0`, private_key, peer_public_key, peer_endpoint, keepalive, peer_preshared_key)

	return request, nil
}

func startSocks(conf *ini.File, tnet *netstack.Net) error {
	addr := conf.Section("Socks5").Key("BindAddress").MustString("127.0.0.1:1080")

	socks_conf := &socks5.Config{Dial: tnet.DialContext}
	server, err := socks5.New(socks_conf)
	if err != nil {
		return err
	}

	if err := server.ListenAndServe("tcp", addr); err != nil {
		return err
	}

	return nil
}

func startWireguard(conf *ini.File) (*netstack.Net, error) {
	iface := conf.Section("Interface")

	key, err := iface.GetKey("Address")
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParseAddr(key.String())
	if err != nil {
		return nil, err
	}

	key, err = iface.GetKey("DNS")
	if err != nil {
		return nil, err
	}
	dns, err := parseIPs(key.Strings(","))
	if err != nil {
		return nil, err
	}

	mtu := iface.Key("MTU").MustInt(default_mtu)

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, dns, mtu)
	if err != nil {
		return nil, err
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))

	request, err := createIPCRequest(conf)
	if err != nil {
		return nil, err
	}
	dev.IpcSet(request)

	if err = dev.Up(); err != nil {
		return nil, err
	}

	return tnet, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: wiresocks [config file path]")
		return
	}

	conf, err := ini.InsensitiveLoad(os.Args[1])
	if err != nil {
		log.Panic(err)
	}

	tnet, err := startWireguard(conf)
	if err != nil {
		log.Panic(err)
	}

	err = startSocks(conf, tnet)
	if err != nil {
		log.Panic(err)
	}
}
