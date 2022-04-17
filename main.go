package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/armon/go-socks5"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	defaultMTU          = 1420
	defaultPresharedKey = "0000000000000000000000000000000000000000000000000000000000000000"
	defaultSocksAddr    = "127.0.0.1:1080"
)

func createIPCRequest(iface *Interface, peer *Peer) string {
	psk := defaultPresharedKey
	if peer.PresharedKey != "" {
		psk = peer.PresharedKey
	}
	return fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0
allowed_ip=::0/0`,
		iface.PrivateKey,
		peer.PublicKey,
		peer.Endpoint,
		peer.Keepalive,
		psk,
	)
}

func startSocks(addr string, tnet *netstack.Net) error {
	server, err := socks5.New(&socks5.Config{
		Dial:     tnet.DialContext,
		Resolver: NewTunnelResolver(tnet),
	})
	if err != nil {
		return err
	}

	log.Printf("Starting SOCKS5 proxy at %s", addr)

	if err := server.ListenAndServe("tcp", addr); err != nil {
		return err
	}

	return nil
}

func startWireguard(conf *Config, verbose bool) (*netstack.Net, error) {
	mtu := defaultMTU
	if conf.Interface.MTU != 0 {
		mtu = conf.Interface.MTU
	}
	tun, tnet, err := netstack.CreateNetTUN(
		conf.Interface.Address,
		conf.Interface.DNS,
		mtu,
	)
	if err != nil {
		return nil, err
	}

	logLevel := device.LogLevelError
	if verbose {
		logLevel = device.LogLevelVerbose
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))

	request := createIPCRequest(conf.Interface, conf.Peers[0])
	if err = dev.IpcSet(request); err != nil {
		return nil, err
	}

	if err = dev.Up(); err != nil {
		return nil, err
	}

	return tnet, nil
}

func usage() {
	fmt.Println("Usage: wiresocks [-v] [-l addr:port] <config file path>")
	flag.PrintDefaults()
}

func main() {
	verbose := flag.Bool("v", false, "verbose")
	socksAddr := flag.String("l", defaultSocksAddr, "SOCKS5 proxy listen address")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(1)
	}

	conf, err := NewConfigFromWgQuick(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	tnet, err := startWireguard(conf, *verbose)
	if err != nil {
		log.Fatal(err)
	}

	err = startSocks(*socksAddr, tnet)
	if err != nil {
		log.Fatal(err)
	}
}
