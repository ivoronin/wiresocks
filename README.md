# wiresocks
Wiresocks client that exposes itself as a socks5 proxy

# What is this
wiresocks is a completely userspace application that connects to a wireguard peer,
and exposes a socks5 proxy on the machine. This can be useful if you need
to connect to certain sites via a wireguard peer, but do not want to setup a new network
interface for whatever reasons.

# Why you might want this
- You simply want wireguard as a way to proxy some traffic
- You don't want root permission just to change wireguard settings

Currently I am running wiresocks connected to a wireguard server in another country,
and configured my browser to use wiresocks for certain sites. It is pretty useful since
wiresocks is completely isolated from my network interfaces, also I don't need root to configure
anything.

# Usage
`./wiresocks [config file path]`

# Sample config file
```
# SelfSecretKey is the secret key of your wireguard peer
SelfSecretKey = uCTIK+56CPyCvwJxmU5dBfuyJvPuSXAq1FzHdnIxe1Q=
# SelfEndpoint is the IP of your wireguard peer
SelfEndpoint = 172.16.31.2
# PeerPublicKey is the public key of the wireguard server you want to connec to
PeerPublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=
# PeerEndpoint is the endpoint of the wireguard server you want to connec to
PeerEndpoint = 172.16.0.1:53
# DNS is the nameservers that will be used by wiresocks.
# Multple nameservers can be specified as such: DNS = 1.1.1.1, 1.0.0.1
DNS = 1.1.1.1
# KeepAlive is the persistent keep alive interval of the wireguard device
# usually not needed
# KeepAlive = 25
# PreSharedKey is the pre shared key of your wireguard device
# if you don't know what this is you don't need it
# PreSharedKey = UItQuvLsyh50ucXHfjF0bbR4IIpVBd74lwKc8uIPXXs=

[Socks5]
BindAddress = 127.0.0.1:25344
```
