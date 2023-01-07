# Linux-router

Set Linux as router in one command. Able to provide Internet, or create WiFi hotspot. Support transparent proxy (redsocks). Also useful for routing VM/containers.

It wraps `iptables`, `dnsmasq` etc. stuff. Use in one command, restore in one command or by `control-c` (or even by closing terminal window).

[Linux-Router News & Developer Notes 📰](https://github.com/garywill/linux-router/issues/28) | [More tools and projects 🛠️](https://garywill.github.io) | [🍻 Buy me a coffee ❤️](https://github.com/garywill/receiving/blob/master/receiving_methods.md)

## Features

Basic features:

- Create a NATed sub-network
- Provide Internet
- DHCP server (and RA)
  - Specify what DNS the DHCP server assigns to clients
- DNS server
  - Specify upstream DNS (kind of a plain DNS proxy)
- IPv6 (behind NATed LAN, like IPv4)
- Creating WiFi hotspot:
  - Channel selecting
  - Choose encryptions: WPA2/WPA, WPA2, WPA, No encryption
  - Create AP on the same interface you are getting Internet (usually require same channel)
- Transparent proxy (redsocks)
- Transparent DNS proxy (hijack port 53 packets)
- Detect NetworkManager and make sure it won't interfere (handle interface (un)managed status)
- You can run many instances, to create many different networks. Has instances managing feature.

**For many other features, see below [CLI usage](#cli-usage-and-other-features)**

### Useful in these situations

```
Internet----(eth0/wlan0)-Linux-(wlanX)AP
                                       |--client
                                       |--client
```

```
                                    Internet
WiFi AP(no DHCP)                        |
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

no matter which interface (other than `eth1`) you're getting Internet from.

### Create WiFi hotspot

```
sudo lnxrouter --ap wlan0 MyAccessPoint -p MyPassPhrase
```

no matter which interface you're getting Internet from (even from `wlan0`). Will create virtual Interface `x0wlan0` for hotspot.

### Provide an interface's Internet to another interface

Clients access Internet through only `isp5`

<details>

```
sudo lnxrouter -i eth1 -o isp5  --no-dns  --dhcp-dns 1.1.1.1  -6 --dhcp-dns6 [2606:4700:4700::1111]
```

> In this case of usage, it's recommended to:
> 
> 1. Stop serving local DNS
> 2. Tell clients which DNS to use ISP5's DNS. (Or, a safe public DNS, like above example)

> Also, read *Notice 1*

</details>

### LAN without Internet

<details>

```
sudo lnxrouter -n -i eth1
sudo lnxrouter -n --ap wlan0 MyAccessPoint -p MyPassPhrase
```

> Read _Notice 1_

</details>

### Internet for LXC

<details>

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

</details>

### Transparent proxy

All clients' Internet traffic go through, for example, Tor (notice this example is NOT an anonymity use)

<details>

```
sudo lnxrouter -i eth1 --tp 9040 --dns 9053 -g 192.168.55.1 -6 --p6 fd00:5:6:7::
```

In `torrc`

```
TransPort 192.168.55.1:9040 
DNSPort 192.168.55.1:9053
TransPort [fd00:5:6:7::1]:9040 
DNSPort [fd00:5:6:7::1]:9053
```

> **Warn**: Tor's anonymity relies on a purpose-made browser. Using Tor like this (sharing Tor's network to LAN clients) will NOT ensure anonymity.
> 
> Although we use Tor as example here, Linux-router does NOT ensure nor is NOT aiming at anonymity.

</details>

### Clients-in-sandbox network

To not give our infomation to clients. Clients can still access Internet.

<details>

```
sudo lnxrouter -i eth1 \
    --tp 9040 --dns 9053 \
    --random-mac \
    --ban-priv \
    --catch-dns --log-dns   # optional
```

</details>

> Linux-router comes with no warranty. Use on your own risk

### Use as transparent proxy for LXD

<details>

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

</details>

### Use as transparent proxy for VirtualBox

<details>

In VirtualBox's global settings, create a host-only network `vboxnet5` with DHCP disabled.

```
sudo lnxrouter -i vboxnet5 --tp 9040 --dns 9053
```

</details>

### Use as transparent proxy for firejail

<details>

Create a bridge

```
sudo brctl addbr firejail5
```

```
sudo lnxrouter -i firejail5 -g 192.168.55.1 --tp 9040 --dns 9053 
firejail --net=firejail5 --dns=192.168.55.1 --blacklist=/var/run/nscd
```

Firejail's `/etc/resolv.conf` doesn't obtain DNS from DHCP, so we need to assign.

nscd is domain name cache service, which shouldn't be accessed from in jail here.

</details>

### CLI usage and other features

<details>

```
Usage: lnxrouter <options>

Options:
    -h, --help              Show this help
    --version               Print version number

    -i <interface>          Interface to make NATed sub-network,
                            and to provide Internet to
                            (To create WiFi hotspot use '--ap' instead)
    -o <interface>          Specify an inteface to provide Internet from.
                            (See Notice 1)
                            (Note using this with default DNS option may leak
                            queries to other interfaces)
    -n                      Do not provide Internet (See Notice 1)
    --ban-priv              Disallow clients to access my private network
    
    -g <ip>                 This host's IPv4 address in subnet (mask is /24)
                            (example: '192.168.5.1' or '5' shortly)
    -6                      Enable IPv6 (NAT)
    --no4                   Disable IPv4 Internet (not forwarding IPv4)
                            (See Notice 1). Usually used with '-6'
                            
    --p6 <prefix>           Set IPv6 LAN address prefix (length 64) 
                            (example: 'fd00:0:0:5::' or '5' shortly) 
                            Using this enables '-6'
                            
    --dns <ip>|<port>|<ip:port>
                            DNS server's upstream DNS.
                            Use ',' to seperate multiple servers
                            (default: use /etc/resolve.conf)
                            (Note IPv6 addresses need '[]' around)
    --no-dns                Do not serve DNS
    --no-dnsmasq            Disable dnsmasq server (DHCP, DNS, RA)
    --catch-dns             Transparent DNS proxy, redirect packets(TCP/UDP) 
                            whose destination port is 53 to this host
    --log-dns               Show DNS query log (dnsmasq)
    --dhcp-dns <IP1[,IP2]>|no
                            Set IPv4 DNS offered by DHCP (default: this host).
    --dhcp-dns6 <IP1[,IP2]>|no
                            Set IPv6 DNS offered by DHCP (RA) 
                            (default: this host)
                            (Note IPv6 addresses need '[]' around)
                            Using both above two will enable '--no-dns' 
    --hostname <name>       DNS server associate this name with this host.
                            Use '-' to read name from /etc/hostname
    -d                      DNS server will take into account /etc/hosts
    -e <hosts_file>         DNS server will take into account additional 
                            hosts file
    --dns-nocache           DNS server no cache
    
    --mac <MAC>             Set MAC address
    --random-mac            Use random MAC address
 
    --tp <port>             Transparent proxy,
                            redirect non-LAN TCP and UDP(not tested) traffic to
                            port. (usually used with '--dns')
    
  WiFi hotspot options:
    --ap <wifi interface> <SSID>
                            Create WiFi access point
    -p, --password <password>   
                            WiFi password
    --qr                    Show WiFi QR code in terminal (need qrencode)
    
    --hidden                Hide access point (not broadcast SSID)
    --no-virt               Do not create virtual interface
                            Using this you can't use same wlan interface
                            for both Internet and AP
    --virt-name <name>      Set name of virtual interface
    -c <channel>            Channel number (default: 1)
    --country <code>        Set two-letter country code for regularity
                            (example: US)
    --freq-band <GHz>       Set frequency band: 2.4 or 5 (default: 2.4)
    --driver                Choose your WiFi adapter driver (default: nl80211)
    -w <WPA version>        '2' for WPA2, '1' for WPA, '1+2' for both
                            (default: 2)
    --psk                   Use 64 hex digits pre-shared-key instead of
                            passphrase
    --mac-filter            Enable WiFi hotspot MAC address filtering
    --mac-filter-accept     Location of WiFi hotspot MAC address filter list
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
    -l, --list-running      Show running instances
    --lc, --list-clients <id|interface>     
                            List clients of an instance. Or list neighbors of
                            an interface, even if it isn't handled by us.
                            (passive mode)
    --stop <id>             Stop a running instance
        For <id> you can use PID or subnet interface name.
        You can get them with '--list-running'
```

</details>

## Notice

<details>

```
    Notice 1:   This script assume your host's default policy won't forward
                packets, so the script won't explictly ban forwarding in any
                mode. In some unexpected case (eg. mistaken configurations) may
                cause unwanted packets leakage between 2 networks, which you
                should be aware of if you want isolated network
```

</details>

## What changes are done to Linux system

On exit of a linux-router instance, script **will do cleanup**, i.e. undo most changes to system. Though, **some** changes (if needed) will **not** be undone, which are:

1. `/proc/sys/net/ipv4/ip_forward = 1` and `/proc/sys/net/ipv6/conf/all/forwarding = 1`
2. dnsmasq in Apparmor complain mode
3. hostapd in Apparmor complain mode
4. Kernel module `nf_nat_pptp` loaded
5. The wifi device which is used to create hotspot is `rfkill unblock`ed
6. WiFi country code, if user assigns

## Install

1-file-script. Download and run (meet the dependencies).

I'm currently not packaging for any distro. If you do, open a PR and add the link (can be with a version badge) to list here:

| Linux distro |                                                                                                            |
| ------------ | ---------------------------------------------------------------------------------------------------------- |
| Any          | download [1-file-script](https://raw.githubusercontent.com/garywill/linux-router/master/lnxrouter) and run |

## Dependencies

- bash
- procps or procps-ng
- iproute2
- dnsmasq
- iptables (or nftables with `iptables-nft` translation linked)
- WiFi hotspot dependencies
  - hostapd
  - iw
  - iwconfig (you only need this if 'iw' can not recognize your adapter)
  - haveged (optional)

## TODO

Sooner is better:
- Detect firewalld and make sure it won't interfere our interface

Future:
- WPA3
- Global IPv6
- Explictly ban forwarding if not needed
- Bring bridging method back

## License

linux-router is LGPL licensed

<details>

```
linux-router
Copyright (C) 2018  garywill

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
```

</details>

Upstream create_ap was BSD licensed

<details>

```
Copyright (c) 2013, oblique
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

</details>

## Meet developer(s) and become one of them

Visit [**my homepage** 🏡](https://garywill.github.io) to see **more tools and projects** 🛠️.

> [❤️ Buy me a coffee](https://github.com/garywill/receiving/blob/master/receiving_methods.md) , this project took me lots of time! ([❤️ 扫码领红包并打赏一个!](https://github.com/garywill/receiving/blob/master/receiving_methods.md))
> 
> 🥂 ( ^\_^) o自自o (^_^ ) 🍻

🤝 Bisides, thank [create_ap](https://github.com/oblique/create_ap) by [oblique](https://github.com/oblique). This script was forked from create\_ap. Now they are quite different. (See `history` branch for how I modified create_ap). 🤝 Also thank those who contributed to that project.

👨‍💻 You can be contributor, too! 🍃 There're some TO-DOs listed, at both [above](#todo) and [in the code file](https://github.com/garywill/linux-router/search?q=TODO&type=code). 🍃 Also some [unfulfilled enhancements in the Issues](https://github.com/garywill/linux-router/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement). Your name can be here!
