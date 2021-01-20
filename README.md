# Linux-router

Set Linux as router in one command. Able to Provide Internet, or create Wifi hotspot. Support transparent proxy (redsocks). Also useful for routing VM/containers.

It wraps `iptables`, `dnsmasq` etc. stuff. Use in one command, restore in one command or by `control-c`.

[Buy me a coffee](https://github.com/garywill/receiving/blob/master/receiving_methods.md) :)

## Features

Basic features:

- Create a NATed sub-network
- Provide Internet
- DHCP server and RA
- DNS server 
- IPv6 (behind NATed LAN, like IPv4)
- Creating Wifi hotspot:
  - Channel selecting
  - Choose encryptions: WPA2/WPA, WPA2, WPA, No encryption
  - Create AP on the same interface you are getting Internet (require same channel)
- Transparent proxy (redsocks)
- DNS proxy
- Compatible with NetworkManager (automatically set interface as unmanaged)

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
Internet----(eth0/wlan0)-Linux-(virtual interface)-----VM/container
```

## Usage

### Provide Internet to an interface

```
sudo lnxrouter -i eth1
```

### Provide an interface's Internet to another interface

```
sudo lnxrouter -i eth1 -o vpn0 --dhcp-dns 1.1.1.1
```
> Read _Notice 1_

### Create Wifi hotspot

```
sudo lnxrouter --ap wlan0 MyAccessPoint -p MyPassPhrase
```

### LAN without Internet

```
sudo lnxrouter -n -i eth1
sudo lnxrouter -n --ap wlan0 MyAccessPoint -p MyPassPhrase
```

> Read _Notice 1_


### Internet for LXC

Create a bridge

```
sudo brctl addbr lxcbr5
```

In LXC container `config`

```
lxc.network.type = veth
lxc.network.flags = up
lxc.network.link = lxcbr5
lxc.network.hwaddr = xx:xx:xx:xx:xx:xx
```

```
sudo lnxrouter -i lxcbr5
```

### Transparent proxy with Tor

```
sudo lnxrouter -i eth1 --tp 9040 --dns 9053 -g 192.168.55.1 --p6 fd00:5:6:7::
```

In `torrc`

```
TransPort 192.168.55.1:9040 
DNSPort 192.168.55.1:9053
TransPort [fd00:5:6:7::1]:9040 
DNSPort [fd00:5:6:7::1]:9053
```

### Clients-in-sandbox network

To not give our infomation to clients:

```
sudo lnxrouter -i eth1 \
    --tp 9040 --dns 9053 \
    --random-mac \
    --ban-priv \
    --catch-dns --log-dns   # optional
```

> This script comes with no warrenty, use on your own risk


### Use as transparent proxy for LXD

Create a bridge

```
sudo brctl addbr lxdbr5
```

Create and add a new LXD profile overriding container's `eth0`

```
lxc profile create profile5
lxc profile edit profile5

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

lxc profile add <container> profile5
```

```
sudo lnxrouter -i lxdbr5 --tp 9040 --dns 9053
```

To remove that new profile from container

```
lxc profile remove <container> profile5
```

#### To not use profile

Add new `eth0` to container overriding default `eth0`

```
lxc config device add <container> eth0 nic name=eth0 nictype=bridged parent=lxdbr5
```

To remove the customized `eth0` to restore default `eth0`

```
lxc config device remove <container> eth0
```

### Use as transparent proxy for VirtualBox

On VirtualBox's global settings, create a host-only network `vboxnet5` with DHCP disabled.

```
sudo lnxrouter -i vboxnet5 --tp 9040 --dns 9053
```

### Use as transparent proxy for firejail

Create a bridge

```
sudo brctl addbr firejail5
```

```
sudo lnxrouter -i firejail5 -g 192.168.55.1 --tp 9040 --dns 9053 
firejail --net=firejail5 --dns=192.168.55.1 --blacklist=/var/run/nscd
```

### CLI usage and other features

```
Usage: lnxrouter <options>

Options:
    -h, --help              Show this help
    --version               Print version number

    -i <interface>          Interface to make NATed sub-network,
                            and to provide Internet to
                            (To create Wifi hotspot use '--ap' instead)
    -o <interface>          Specify an inteface to provide Internet from.
                            (Note using this with default DNS option may leak
                            queries to other interfaces)
    -n                      Do not provide Internet (See Notice 1)
    --ban-priv              Disallow clients to access my private network
    
    -g <ip>                 Set this host's IPv4 address, netmask is 24 
    -6                      Enable IPv6 (NAT)
    --no4                   Disable IPv4 Internet (not forwarding IPv4)
                            (See Notice 1). Usually used with '-6'
                            
    --p6 <prefix>           Set IPv6 LAN address prefix (length 64) 
                            (example: fd00:1:2:3::) Using this enables '-6'
                            
    --dns <ip>|<port>|<ip:port>
                            DNS server's upstream DNS.
                            Use ',' to seperate multiple servers
                            (default: use /etc/resolve.conf)
                            (Note IPv6 addresses need '[]' around)
    --no-dns                Do not serve DNS
    --no-dnsmasq            Disable dnsmasq server (DHCP, DNS, RA)
    --catch-dns             Transparent DNS proxy, redirect packets(TCP/UDP) 
                            whose destination port is 53 to this host
    --log-dns               Show DNS query log
    --dhcp-dns <IP1[,IP2]>|no
                            Set IPv4 DNS offered by DHCP (default: this host)
    --dhcp-dns6 <IP1[,IP2]>|no
                            Set IPv6 DNS offered by DHCP (RA) 
                            (default: this host)
                            (Note IPv6 addresses need '[]' around)
    --hostname <name>       DNS server associate this name with this host.
                            Use '-' to read name from /etc/hostname
    -d                      DNS server will take into account /etc/hosts
    -e <hosts_file>         DNS server will take into account additional 
                            hosts file
    
    --mac <MAC>             Set MAC address
    --random-mac            Use random MAC address
 
    --tp <port>             Transparent proxy,
                            redirect non-LAN TCP and UDP traffic to port.
                            Usually used with '--dns'
    
  Wifi hotspot options:
    --ap <wifi interface> <SSID>
                            Create Wifi access point
    -p, --password <password>   
                            Wifi password
    --qr                    Show Wifi QR code in terminal
    
    --hidden                Hide access point (not broadcast SSID)
    --no-virt               Do not create virtual interface
                            Using this you can't use same wlan interface
                            for both Internet and AP
    -c <channel>            Channel number (default: 1)
    --country <code>        Set two-letter country code for regularity
                            (example: US)
    --freq-band <GHz>       Set frequency band: 2.4 or 5 (default: 2.4)
    --driver                Choose your WiFi adapter driver (default: nl80211)
    -w <WPA version>        '2' for WPA2, '1' for WPA, '1+2' for both
                            (default: 2)
    --psk                   Use 64 hex digits pre-shared-key instead of
                            passphrase
    --mac-filter            Enable Wifi hotspot MAC address filtering
    --mac-filter-accept     Location of Wifi hotspot MAC address filter list
                            (defaults to /etc/hostapd/hostapd.accept)
    --hostapd-debug <level> 1 or 2. Passes -d or -dd to hostapd
    --isolate-clients       Disable wifi communication between clients
    
    --ieee80211n            Enable IEEE 802.11n (HT)
    --ieee80211ac           Enable IEEE 802.11ac (VHT)
    --ht_capab <HT>         HT capabilities (default: [HT40+])
    --vht_capab <VHT>       VHT capabilities
    
    --no-haveged            Do not run haveged automatically when needed

  Instance managing:
    --daemon                Run in background
    --list-running          Show running instances
    --list-clients <id>     List clients of an instance
    --stop <id>             Stop a running instance
        For <id> you can use PID or subnet interface name.
        You can get them with '--list-running'

    Notice 1:   This script assume your host's default policy won't forward
                packets, so the script won't explictly ban forwarding in any
                mode. In some unexpected case may cause unwanted packets 
                leakage between 2 networks, which you should be aware of if you
                want isolated network
```

> These changes to system will not be restored by script's cleanup:
> 1. `/proc/sys/net/ipv4/ip_forward = 1` and `/proc/sys/net/ipv6/conf/all/forwarding = 1`, needed by NAT Internet sharing.
> 2. dnsmasq in Apparmor complain mode
> 3. The wifi device which is used to create hotspot is `rfkill unblock`ed

## Dependencies

- bash
- procps or procps-ng
- iproute2
- dnsmasq
- iptables
- WiFi hotspot dependencies
   - hostapd
   - iw
   - iwconfig (you only need this if 'iw' can not recognize your adapter)
   - haveged (optional)
   - qrencode (opional)

## TODO

- WPA3
- Global IPv6
- Refactor clients(neighbors) listing function
- Explictly ban forwarding if not needed

## Donate

[Buy me a coffee](https://github.com/garywill/receiving/blob/master/receiving_methods.md) , this project took me lots of time!

（ ^\_^）o自自o（^_^ ）

No? Okay, or just give me a star!

## Thanks

Many thanks to project [create_ap](https://github.com/oblique/create_ap).
