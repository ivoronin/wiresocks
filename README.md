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
`./wiresocks [-v] [-l addr:port] [config file path]`

# Sample config file
Wiresocks supports subset of the `wg-quick` file format.

```
[Interface]
PrivateKey = uCTIK+56CPyCvwJxmU5dBfuyJvPuSXAq1FzHdnIxe1Q=
Address = 172.16.31.2
DNS = 1.1.1.1
# MTU = 1420

[Peer]
PublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=
Endpoint = 172.16.0.1:53
# PersistentKeepalive = 25
# PreSharedKey = UItQuvLsyh50ucXHfjF0bbR4IIpVBd74lwKc8uIPXXs=
```
