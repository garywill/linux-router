#  Linux-router

 Share your Linux's Internet access to other devices.
 This is a fork of [create_ap](https://github.com/oblique/create_ap).
 
##  Features

- Create Wifi hotspot and share Internet
- Transparent proxy (redsocks)
- DNS server and query log
- DHCP server

 
## Usage

### NAT Internet sharing

```
# lnxrouter --ap wlan0 MyAccessPoint --password MyPassPhrase
```

### Transparent proxy with tor

```
# lnxrouter --ap wlan0 MyAccessPoint --password MyPassPhrase --tp 9040 --dns-proxy 9053
```

In `torrc`

```
TransPort 0.0.0.0:9040 
DNSPort 0.0.0.0:9053
```



## TODO


- Share Internet not creating Wifi hotspot
- Ban private network access
- IPv6 support 