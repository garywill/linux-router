#  Linux-router

Share your Linux's Internet access to other devices. 

The goal is to easily set/unset your Linux PC/embedded device as a gateway/hotspot/transparent proxy. It wraps the complicated `iptables`, `dnsmasq` etc. stuff. Use in one command, restore by `control-c`.

It works on wired, wireless and virtual networks.
 
##  Features

Basic features:

- Create a NATed sub-network
- Share Internet to the sub-network
- DHCP server
- DNS server 
- Creating Wifi hotspot:
  - Channel selecting
  - Choose encryptions: WPA2/WPA, WPA2, WPA, No encryption
  - Hidden SSID
  - Create AP on the same interface you are getting Internet (require same channel)
- Transparent proxy (redsocks)
- DNS proxy

**For many other features, see below [CLI usage](#cli-usage-and-other-features)**

### Useful in these situations
```
Internet----(eth0/wlan0)-Linux-(wlanX)AP
                                       |--client
                                       |--client
```

```
                                    Internet
Wifi AP(no DHCP)                        |
    |----(wlan1)-Linux-(eth0/wlan0)------
    |           (DHCP)
    |--client
    |--client
```

```
                                    Internet
 Switch                                 |
    |---(eth1)-Linux-(eth0/wlan0)--------
    |--client
    |--client
```

```
Internet----(eth0/wlan0)-Linux-(eth1)------Another PC
```

```
Internet----(eth0/wlan0)-Linux-(virtual interface)-----VM guests/container guests
```
 
## Usage

### Share Internet to an interface

```
# lnxrouter -i eth1
```

### Create Wifi hotspot

```
# lnxrouter --ap wlan0 MyAccessPoint --password MyPassPhrase
```

### LAN without Internet

```
# lnxrouter -i eth1 -n
# lnxrouter --ap wlan0 MyAccessPoint --password MyPassPhrase -n
```

### Transparent proxy with tor

```
# lnxrouter -i eth1 --tp 9040 --dns-proxy 9053
```

In `torrc`

```
TransPort 0.0.0.0:9040 
DNSPort 0.0.0.0:9053
```
### Use for LXC
Create a bridge
```
# brctl addbr lxcbr5
```
In LXC container `config`
```
lxc.network.type = veth
lxc.network.flags = up
lxc.network.link = lxcbr5
lxc.network.hwaddr = xx:xx:xx:xx:xx:xx
```
```
# lnxrouter -i lxcbr5
```

### Use as transparent proxy for LXD
Create a bridge
```
# brctl addbr lxdbr5
```
Create and add LXD profile
```
$ lxc profile create profile5
$ lxc profile edit profile5

### profile content ###
config: {}
description: ""
devices:
  eth0:
    name: eth0
    nictype: bridged
    parent: lxdbr5
    type: nic
name: profile5

$ lxc profile add <container> profile5
```
That should make one container have 2 profiles. `profile5` will override `eth0`.
```
# lnxrouter -i lxdbr5 --tp 9040 --dns-proxy 9053
```
To remove that new profile from container
```
$ lxc profile remove <container> profile5
```
### Use as transparent proxy for VirtualBox
On VirtualBox's global settings, create a host-only network `vboxnet5` with DHCP disabled.
```
# lnxrouter -i vboxnet5 --tp 9040 --dns-proxy 9053
```
### CLI usage and other features

```
Usage: lnxrouter [options] 

Options:
  -h, --help              Show this help
  --version               Print version number

  -i <interface>          Interface to share Internet to. An NATed subnet is made upon it.
                          To create Wifi hotspot use '--ap' instead
  -n                      Disable Internet sharing
  --tp <port>             Transparent proxy (redsocks), redirect tcp and udp traffic to port.
                          Usually use with --dns-proxy

  -g <gateway>            Set Gateway IPv4 address, netmask is /24 (default: 192.168.18.1)
  --dns-proxy <port>      Redirect incoming port 53 to DNS proxy port. DNS server is disabled
  --no-serve-dns          Disable DNS server
  --no-dnsmasq            Disable dnsmasq server completely (DHCP and DNS)
  --log-dns               Show DNS server query log
  --dhcp-dns <IP1[,IP2]>|no
                          Set DNS offered by DHCP, or no DNS offered (default: gateway as DNS)
  -d                      DNS server will take into account /etc/hosts
  -e <hosts_file>         DNS server will take into account additional hosts file

  --mac <MAC>             Set MAC address

 Wifi hotspot options:
  --ap <wlan card interface> <access point name>
                          Create Wifi access point using wlan card, and set SSID
  --password <passphrase> Wifi password

  --hidden                Make the Access Point hidden (do not broadcast the SSID)
  --no-virt               Do not create virtual interface. 
                          Using this you can't use same wlan card as Internet and AP
  -c <channel>            Channel number (default: 1)
  --country <code>        Set two-letter country code for regularity (example: US)
  --freq-band <GHz>       Set frequency band. Valid inputs: 2.4, 5 (default: 2.4)
  --driver                Choose your WiFi adapter driver (default: nl80211)
  -w <WPA version>        Use 1 for WPA, use 2 for WPA2, use 1+2 for both (default: 1+2)
  --psk                   Use 64 hex digits pre-shared-key instead of passphrase
  --mac-filter            Enable Wifi hotspot MAC address filtering
  --mac-filter-accept     Location of Wifi hotspot MAC address filter list (defaults to /etc/hostapd/hostapd.accept)
  --hostapd-debug <level> With level between 1 and 2, passes arguments -d or -dd to hostapd for debugging.
  --isolate-clients       Disable communication between clients
  --ieee80211n            Enable IEEE 802.11n (HT)
  --ieee80211ac           Enable IEEE 802.11ac (VHT)
  --ht_capab <HT>         HT capabilities (default: [HT40+])
  --vht_capab <VHT>       VHT capabilities
  --no-haveged            Do not run 'haveged' automatically when needed

 Instance managing:
  --daemon                Run lnxrouter in the background
  --list-running          Show the lnxrouter processes that are already running
  --stop <id>             Send stop command to an already running lnxrouter. For an <id>
                          you can put the PID of lnxrouter or interface. You can
                          get them with --list-running
  --list-clients <id>     List the clients connected to lnxrouter instance associated with <id>.
                          For an <id> you can put the PID of lnxrouter or interface.
                          If virtual WiFi interface was created, then use that one.
                          You can get them with --list-running
```


## Dependencies
- bash
- procps or procps-ng
- iproute2
- dnsmasq
- iptables

Wifi hotspot:

- hostapd
- iw
- iwconfig (you only need this if 'iw' can not recognize your adapter)
- haveged (optional)

## TODO

- Option to ban private network access
- IPv6 support 
- Option to random MAC, IP, SSID, password
- Option to specify out-going interface
- Option to catch and redirect all dns connections

## Thanks

Many thanks to project [create_ap](https://github.com/oblique/create_ap).
