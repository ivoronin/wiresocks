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

type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	deviceAddr *netip.Addr
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

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func parseIPs(s string) ([]netip.Addr, error) {
	ips := []netip.Addr{}
	for _, str := range strings.Split(s, ",") {
		str = strings.TrimSpace(str)
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func createIPCRequest(conf *ini.File) (*DeviceSetting, error) {
	root := conf.Section("")

	key, err := root.GetKey("peerpublickey")
	if err != nil {
		return nil, err
	}
	peerPK, err := parseBase64Key(key.String())
	if err != nil {
		return nil, err
	}

	key, err = root.GetKey("selfsecretkey")
	if err != nil {
		return nil, err
	}
	selfSK, err := parseBase64Key(key.String())
	if err != nil {
		return nil, err
	}

	key, err = root.GetKey("peerendpoint")
	if err != nil {
		return nil, err
	}
	peerEndpoint, err := resolveIPPAndPort(key.String())
	if err != nil {
		return nil, err
	}

	key, err = root.GetKey("selfendpoint")
	if err != nil {
		return nil, err
	}
	selfEndpoint, err := netip.ParseAddr(key.String())
	if err != nil {
		return nil, err
	}

	key, err = root.GetKey("dns")
	if err != nil {
		return nil, err
	}
	dns, err := parseIPs(key.String())
	if err != nil {
		return nil, err
	}

	keepAlive := root.Key("keepalive").MustInt64(0)
	preSharedKey := root.Key("presharedkey").MustString("0000000000000000000000000000000000000000000000000000000000000000")

	request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0`, selfSK, peerPK, peerEndpoint, keepAlive, preSharedKey)

	setting := &DeviceSetting{ipcRequest: request, dns: dns, deviceAddr: &selfEndpoint}
	return setting, nil
}

func socks5Routine(conf *ini.File) (func(*netstack.Net), error) {
	bindAddr := conf.Section("Socks5").Key("bindaddress").String()

	routine := func(tnet *netstack.Net) {
		conf := &socks5.Config{Dial: tnet.DialContext}
		server, err := socks5.New(conf)
		if err != nil {
			log.Panic(err)
		}

		if err := server.ListenAndServe("tcp", bindAddr); err != nil {
			log.Panic(err)
		}
	}

	return routine, nil
}

func startWireguard(setting *DeviceSetting) (*netstack.Net, error) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{*(setting.deviceAddr)}, setting.dns, 1420)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	dev.IpcSet(setting.ipcRequest)
	err = dev.Up()
	if err != nil {
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

	setting, err := createIPCRequest(conf)
	if err != nil {
		log.Panic(err)
	}

	tnet, err := startWireguard(setting)
	if err != nil {
		log.Panic(err)
	}

	routine, err := socks5Routine(conf)
	if err != nil {
		log.Panic(err)
	}
    go routine(tnet)

	select {} // sleep etnerally
}
