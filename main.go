package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
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

const (
	defaultMtu       = 1420
	defaultKeepalive = 0
	defaultSocksAddr = "127.0.0.1:1080"
)

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
	privateKey, err := parseBase64Key(key.String())
	if err != nil {
		return "", err
	}

	key, err = peer.GetKey("PublicKey")
	if err != nil {
		return "", err
	}
	peerPublicKey, err := parseBase64Key(key.String())
	if err != nil {
		return "", err
	}

	key, err = peer.GetKey("Endpoint")
	if err != nil {
		return "", err
	}
	peerEndpoint, err := resolveIPPAndPort(key.String())
	if err != nil {
		return "", err
	}

	keepAlive := peer.Key("PersistentKeepalive").MustInt64(defaultKeepalive)
	peerPresharedKey := peer.Key("PresharedKey").MustString(strings.Repeat("0", 64))

	request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0`, privateKey, peerPublicKey, peerEndpoint, keepAlive, peerPresharedKey)

	return request, nil
}

func startSocks(conf *ini.File, tnet *netstack.Net) error {
	addr := conf.Section("Socks5").Key("BindAddress").MustString(defaultSocksAddr)

	server, err := socks5.New(&socks5.Config{Dial: tnet.DialContext})
	if err != nil {
		return err
	}

	log.Printf("Starting SOCKS5 proxy at %s", addr)

	if err := server.ListenAndServe("tcp", addr); err != nil {
		return err
	}

	return nil
}

func startWireguard(conf *ini.File, verbose bool) (*netstack.Net, error) {
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

	mtu := iface.Key("MTU").MustInt(defaultMtu)

	request, err := createIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, dns, mtu)
	if err != nil {
		return nil, err
	}

	logLevel := device.LogLevelError
	if verbose {
		logLevel = device.LogLevelVerbose
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))

	if err = dev.IpcSet(request); err != nil {
		return nil, err
	}

	if err = dev.Up(); err != nil {
		return nil, err
	}

	return tnet, nil
}

func main() {
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()
	args := flag.Args()

	if len(args) != 1 {
		fmt.Println("Usage: wiresocks [-v] [config file path]")
		return
	}

	var cfgSrc interface{}
	if args[0] == "-" {
		cfgSrc = bufio.NewReader(os.Stdin)
	} else {
		cfgSrc = args[0]
	}

	conf, err := ini.InsensitiveLoad(cfgSrc)
	if err != nil {
		log.Fatal(err)
	}

	tnet, err := startWireguard(conf, *verbose)
	if err != nil {
		log.Fatal(err)
	}

	err = startSocks(conf, tnet)
	if err != nil {
		log.Fatal(err)
	}
}
