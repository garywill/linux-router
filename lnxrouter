#!/bin/bash

VERSION=0.5.3
PROGNAME="$(basename $0)"

export LC_ALL=C

SCRIPT_UMASK=0122
umask $SCRIPT_UMASK

usage() {
    cat << EOF
linux-router $VERSION (https://github.com/garywill/linux-router)

Usage: $PROGNAME <options>

Options:
    -h, --help              Show this help
    --version               Print version number

    -i <interface>          Interface to make NATed sub-network,
                            and to provide Internet to
                            (To create Wifi hotspot use '--ap' instead)
    -o <interface>          Specify an inteface to provide Internet from.
                            (Note using this with default DNS option may leak
                            queries to other interfaces)
    -n                      Do not provide Internet
    
    -g <ip>                 Set this host's IPv4 address, netmask is 24 
    -6                      Enable IPv6 (NAT)
    --p6 <prefix>           Set IPv6 prefix (length 64) (example: fd00:1:2:3::)
                            
    --dns <ip>|<port>|<ip:port>
                            DNS server's upstream DNS.
                            Use ',' to seperate multiple servers
                            (default: use /etc/resolve.conf)
                            (Note IPv6 addresses need '[]' around)
    --no-dns                Do not serve DNS
    --no-dnsmasq            Disable dnsmasq server (DHCP, DNS, RA)
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
 
    --tp <port>             Transparent proxy,
                            redirect non-LAN tcp and udp traffic to port.
                            Usually used with '--dns'
    
  Wifi hotspot options:
    --ap <wifi interface> <SSID>
                            Create Wifi access point
    --password <password>   Wifi password
    
    --hidden                Hide access point (not broadcast SSID)
    --no-virt               Do not create virtual interface
                            Using this you can't use same wlan interface
                            for both Internet and AP
    -c <channel>            Channel number (default: 1)
    --country <code>        Set two-letter country code for regularity
                            (example: US)
    --freq-band <GHz>       Set frequency band: 2.4 or 5 (default: 2.4)
    --driver                Choose your WiFi adapter driver (default: nl80211)
    -w <WPA version>        Use 1 for WPA, use 2 for WPA2, use 1+2 for both
                            (default: 1+2)
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

Examples:
    $PROGNAME -i eth1
    $PROGNAME --ap wlan0 MyAccessPoint
    $PROGNAME --ap wlan0 MyAccessPoint --password MyPassPhrase
    $PROGNAME -n --ap wlan0 MyAccessPoint --password MyPassPhrase
    $PROGNAME -i eth1 --tp <transparent-proxy> --dns <dns-proxy>
EOF
}

if [[ "$1" == "" ]]; then
    usage
    exit 0
fi

GATEWAY=
PREFIX6=
IID6=1
IPV6=0
ROUTE_ADDRS=
DHCP_DNS=gateway
DHCP_DNS6=gateway
dnsmasq_NO_DNS=0
NO_DNSMASQ=0
SHOW_DNS_QUERY=0
ETC_HOSTS=0
ADDN_HOSTS=
SUBNET_IFACE=
CONN_IFACE=
INTERNET_IFACE=
THISHOSTNAME=

SHARE_METHOD=nat
TP_PORT=
DNS=

NEW_MACADDR=
OLD_MACADDR=
DAEMONIZE=0

HIDDEN=0
WIFI_IFACE=
VWIFI_IFACE=
AP_IFACE=
CHANNEL=default
WPA_VERSION=1+2
MAC_FILTER=0
MAC_FILTER_ACCEPT=/etc/hostapd/hostapd.accept
IEEE80211N=0
IEEE80211AC=0
HT_CAPAB='[HT40+]'
VHT_CAPAB=
DRIVER=nl80211
NO_VIRT=0
COUNTRY=
FREQ_BAND=2.4
NO_HAVEGED=0
HOSTAPD_DEBUG_ARGS=
USE_PSK=0
ISOLATE_CLIENTS=0

LIST_RUNNING=0
STOP_ID=
LIST_CLIENTS_ID=
CONFDIR=

ARGS=( "$@" )

while [[ -n "$1" ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --version)
            echo $VERSION
            exit 0
            ;;
        -i)
            shift
            CONN_IFACE="$1"
            shift
            ;;
        -o)
            shift
            INTERNET_IFACE="$1"
            shift
            ;;
        -n)
            shift
            SHARE_METHOD=none
            ;;
        --tp)
            shift
            TP_PORT="$1"
            shift
            ;;
            
            
        -g)
            shift
            GATEWAY="$1"
            shift
            ;;
        -6)
            shift
            IPV6=1
            ;;
        --p6)
            shift
            PREFIX6="$1"
            shift
            ;;
        --mac)
            shift
            NEW_MACADDR="$1"
            shift
            ;;
            
        --dns)
            shift
            DNS="$1"
            shift
            ;;
        --no-dns)
            shift
            dnsmasq_NO_DNS=1
            ;;
        --no-dnsmasq)
            shift
            NO_DNSMASQ=1
            ;;
        --dhcp-dns)
            shift
            DHCP_DNS="$1"
            shift
            ;;
        --dhcp-dns6)
            shift
            DHCP_DNS6="$1"
            shift
            ;;
        --log-dns)
            shift
            SHOW_DNS_QUERY=1
            ;;
        --hostname)
            shift
            THISHOSTNAME="$1"
            shift
            ;;
        -d)
            shift
            ETC_HOSTS=1
            ;;
        -e)
            shift
            ADDN_HOSTS="$1"
            shift
            ;;
        
        --isolate-clients)
            shift
            ISOLATE_CLIENTS=1
            ;;
            
        --ap)
            shift
            WIFI_IFACE="$1"
            shift
            SSID="$1"
            shift
            ;;
        --password)
            shift
            PASSPHRASE="$1"
            shift
            ;;
            
            
        --hidden)
            shift
            HIDDEN=1
            ;;
        --mac-filter)
            shift
            MAC_FILTER=1
            ;;
        --mac-filter-accept)
            shift
            MAC_FILTER_ACCEPT="$1"
            shift
            ;;

        -c)
            shift
            CHANNEL="$1"
            shift
            ;;
        -w)
            shift
            WPA_VERSION="$1"
            [[ "$WPA_VERSION" == "2+1" ]] && WPA_VERSION=1+2
            shift
            ;;



        --ieee80211n)
            shift
            IEEE80211N=1
            ;;
        --ieee80211ac)
            shift
            IEEE80211AC=1
            ;;
        --ht_capab)
            shift
            HT_CAPAB="$1"
            shift
            ;;
        --vht_capab)
            shift
            VHT_CAPAB="$1"
            shift
            ;;
        --driver)
            shift
            DRIVER="$1"
            shift
            ;;
        --no-virt)
            shift
            NO_VIRT=1
            ;;

        --country)
            shift
            COUNTRY="$1"
            shift
            ;;
        --freq-band)
            shift
            FREQ_BAND="$1"
            shift
            ;;
        --no-haveged)
            shift
            NO_HAVEGED=1
            ;;
        --hostapd-debug)
            shift
            if [ "x$1" = "x1" ]; then
                HOSTAPD_DEBUG_ARGS="-d"
            elif [ "x$1" = "x2" ]; then
                HOSTAPD_DEBUG_ARGS="-dd"
            else
                printf "Error: argument for --hostapd-debug expected 1 or 2, got %s\n" "$1"
                exit 1
            fi
            shift
            ;;
        --psk)
            shift
            USE_PSK=1
            ;;

        --daemon)
            shift
            DAEMONIZE=1
            ;;
        --stop)
            shift
            STOP_ID="$1"
            shift
            ;;
        --list-running)
            shift
            LIST_RUNNING=1
            ;;
        --list-clients)
            shift
            LIST_CLIENTS_ID="$1"
            shift
            ;;



        *)
            echo  "Invalid parameter: $1" 1>&2
            exit 1
            ;;
    esac
done

sep_ip_port() {
    local IP
    local PORT
    local INPUT
    INPUT="$1"
    if (echo $INPUT | grep '\.' >/dev/null 2>&1) ;then  
        if (echo $INPUT | grep ':' >/dev/null 2>&1) ;then
            # ipv4 + port
            IP="$(echo $INPUT | cut -d: -f1)"
            PORT="$(echo $INPUT | cut -d: -f2)"
        else
            # ipv4
            IP="$INPUT"
        fi
    elif (echo $INPUT | grep '\]' >/dev/null 2>&1) ;then 
        if (echo $INPUT | grep '\]\:' >/dev/null 2>&1) ;then
            # ipv6 + port
            IP="$(echo $INPUT | cut -d']' -f1 | cut -d'[' -f2)"
            PORT="$(echo $INPUT | cut -d']' -f2 |cut -d: -f2)"
        else
            # ipv6
            IP="$(echo $INPUT | cut -d']' -f1 | cut -d'[' -f2)"
        fi
    else 
        # port
        IP='127.0.0.1'
        PORT="$INPUT"
    fi
    printf -v "$2" %s "$IP"
    printf -v "$3" %s "$PORT"
}

USE_IWCONFIG=0

is_interface() {
    [[ -z "$1" ]] && return 1
    [[ -d "/sys/class/net/${1}" ]]
}

get_phy_device() { # only for wifi interface
    local x
    for x in /sys/class/ieee80211/*; do
        [[ ! -e "$x" ]] && continue
        if [[ "${x##*/}" = "$1" ]]; then
            echo $1
            return 0
        elif [[ -e "$x/device/net/$1" ]]; then
            echo ${x##*/}
            return 0
        elif [[ -e "$x/device/net:$1" ]]; then
            echo ${x##*/}
            return 0
        fi
    done
    echo "Failed to get phy interface" >&2
    return 1
}

get_adapter_info() { # only for wifi interface
    local PHY
    PHY=$(get_phy_device "$1")
    [[ $? -ne 0 ]] && return 1
    iw phy $PHY info
}

get_adapter_kernel_module() {
    local MODULE
    MODULE=$(readlink -f "/sys/class/net/$1/device/driver/module")
    echo ${MODULE##*/}
}

can_be_sta_and_ap() {
    # iwconfig does not provide this information, assume false
    [[ $USE_IWCONFIG -eq 1 ]] && return 1
    if [[ "$(get_adapter_kernel_module "$1")" == "brcmfmac" ]]; then
        echo "WARN: brmfmac driver doesn't work properly with virtual interfaces and" >&2
        echo "      it can cause kernel panic. For this reason we disallow virtual" >&2
        echo "      interfaces for your adapter." >&2
        echo "      For more info: https://github.com/oblique/create_ap/issues/203" >&2
        return 1
    fi
    get_adapter_info "$1" | grep -E '{.* managed.* AP.*}' > /dev/null 2>&1 && return 0
    get_adapter_info "$1" | grep -E '{.* AP.* managed.*}' > /dev/null 2>&1 && return 0
    return 1
}

can_be_ap() {
    # iwconfig does not provide this information, assume true
    [[ $USE_IWCONFIG -eq 1 ]] && return 0
    get_adapter_info "$1" | grep -E '\* AP$' > /dev/null 2>&1 && return 0
    return 1
}

can_transmit_to_channel() {
    local IFACE CHANNEL_NUM CHANNEL_INFO
    IFACE=$1
    CHANNEL_NUM=$2

    if [[ $USE_IWCONFIG -eq 0 ]]; then
        if [[ $FREQ_BAND == 2.4 ]]; then
            CHANNEL_INFO=$(get_adapter_info ${IFACE} | grep " 24[0-9][0-9] MHz \[${CHANNEL_NUM}\]")
        else
            CHANNEL_INFO=$(get_adapter_info ${IFACE} | grep " \(49[0-9][0-9]\|5[0-9]\{3\}\) MHz \[${CHANNEL_NUM}\]")
        fi
        [[ -z "${CHANNEL_INFO}" ]] && return 1
        [[ "${CHANNEL_INFO}" == *no\ IR* ]] && return 1
        [[ "${CHANNEL_INFO}" == *disabled* ]] && return 1
        return 0
    else
        CHANNEL_NUM=$(printf '%02d' ${CHANNEL_NUM})
        CHANNEL_INFO=$(iwlist ${IFACE} channel | grep -E "Channel[[:blank:]]${CHANNEL_NUM}[[:blank:]]?:")
        [[ -z "${CHANNEL_INFO}" ]] && return 1
        return 0
    fi
}

# taken from iw/util.c
ieee80211_frequency_to_channel() {
    local FREQ=$1
    if [[ $FREQ -eq 2484 ]]; then
        echo 14
    elif [[ $FREQ -lt 2484 ]]; then
        echo $(( ($FREQ - 2407) / 5 ))
    elif [[ $FREQ -ge 4910 && $FREQ -le 4980 ]]; then
        echo $(( ($FREQ - 4000) / 5 ))
    elif [[ $FREQ -le 45000 ]]; then
        echo $(( ($FREQ - 5000) / 5 ))
    elif [[ $FREQ -ge 58320 && $FREQ -le 64800 ]]; then
        echo $(( ($FREQ - 56160) / 2160 ))
    else
        echo 0
    fi
}

is_5ghz_frequency() {
    [[ $1 =~ ^(49[0-9]{2})|(5[0-9]{3})$ ]]
}

is_wifi_connected() {
    if [[ $USE_IWCONFIG -eq 0 ]]; then
        iw dev "$1" link 2>&1 | grep -E '^Connected to' > /dev/null 2>&1 && return 0
    else
        iwconfig "$1" 2>&1 | grep -E 'Access Point: [0-9a-fA-F]{2}:' > /dev/null 2>&1 && return 0
    fi
    return 1
}


is_unicast_macaddr() {
    local x
    x=$(echo "$1" | cut -d: -f1)
    x=$(printf '%d' "0x${x}")
    [[ $(expr $x % 2) -eq 0 ]]
}

get_macaddr() {
    is_interface "$1" || return
    cat "/sys/class/net/${1}/address"
}


alloc_new_iface() { # only for wifi
    local i=0
    local v_iface_name=
    while :; do
        v_iface_name="x$i${WIFI_IFACE}"
        if ! is_interface ${v_iface_name} && [[ ! -f $COMMON_CONFDIR/ifaces/${v_iface_name} ]]; then
            mkdir -p $COMMON_CONFDIR/ifaces
            touch $COMMON_CONFDIR/ifaces/${v_iface_name}
            echo ${v_iface_name}
            return
        fi
        i=$((i + 1))
    done
}

dealloc_iface() {
    rm -f $COMMON_CONFDIR/ifaces/$1
}

#======

get_all_macaddrs() {
    cat /sys/class/net/*/address
}

get_new_macaddr() {
    local OLDMAC NEWMAC LAST_BYTE i
    OLDMAC=$(get_macaddr "$1")
    LAST_BYTE=$(printf %d 0x${OLDMAC##*:})
    for i in {10..240}; do
        NEWMAC="${OLDMAC%:*}:$(printf %02x $(( ($LAST_BYTE + $i) % 256 )))"
        (get_all_macaddrs | grep "$NEWMAC" > /dev/null 2>&1) || break
    done
    echo $NEWMAC
}

is_ip4_range_available() {
    ( ip -4 address | grep "inet 192\.168\.$1\." > /dev/null 2>&1 ) && return 1
    ( ip -4 route | grep "^192\.168\.$1\." > /dev/null 2>&1 ) && return 1
    ( ip -4 route get 192.168.$1.0 | grep "\bvia\b" > /dev/null 2>&1 ) && \
    ( ip -4 route get 192.168.$1.255 | grep "\bvia\b" > /dev/null 2>&1 )  && return 0
    return 1
}
is_ip6_range_available() {
    ( ip -6 address | grep -i "inet6 fd$1:$2$3:$4$5:$6$7:" > /dev/null 2>&1 ) && return 1
    ( ip -6 route | grep -i "^fd$1:$2$3:$4$5:$6$7:" > /dev/null 2>&1 ) && return 1
    ( ip -6 route get fd$1:$2$3:$4$5:$6$7:: | grep "\bvia\b" > /dev/null 2>&1 ) && \
    ( ip -6 route get fd$1:$2$3:$4$5:$6$7:ffff:ffff:ffff:ffff | grep "\bvia\b" > /dev/null 2>&1 )  && return 0
    return 1
}

generate_random_ip4() {
    local random_ip4
    while :; do
        random_ip4=$(($RANDOM%256))
        is_ip4_range_available $random_ip4 && break
    done
    GATEWAY="192.168.$random_ip4.1"
}
generate_random_ip6() {
    local r1 r2 r3 r4 r5 r6 r7
    while :; do
        r1=$( printf "%x" $(($RANDOM%240+16)) )
        r2=$( printf "%x" $(($RANDOM%240+16)) )
        r3=$( printf "%x" $(($RANDOM%240+16)) )
        r4=$( printf "%x" $(($RANDOM%240+16)) )
        r5=$( printf "%x" $(($RANDOM%240+16)) )
        r6=$( printf "%x" $(($RANDOM%240+16)) )
        r7=$( printf "%x" $(($RANDOM%240+16)) )
        is_ip6_range_available $r1 $r2 $r3 $r4 $r5 $r6 $r7 && break
    done
    PREFIX6="fd$r1:$r2$r3:$r4$r5:$r6$r7::"
}

# start haveged when needed
haveged_watchdog() {
    local show_warn=1
    while :; do
        if [[ $(cat /proc/sys/kernel/random/entropy_avail) -lt 1000 ]]; then
            if ! which haveged > /dev/null 2>&1; then
                if [[ $show_warn -eq 1 ]]; then
                    echo "WARN: Low entropy detected. We recommend you to install \`haveged'" 1>&2
                    show_warn=0
                fi
            elif ! pidof haveged > /dev/null 2>&1; then
                echo "Low entropy detected, starting haveged" 1>&2
                # boost low-entropy
                haveged -w 1024 -p $COMMON_CONFDIR/haveged.pid
            fi
        fi
        sleep 2
    done
}

#========


# only support NetworkManager >= 0.9.9
NM_RUNNING=0
NM_UNM_LIST=
if (which nmcli >/dev/null 2>&1 ) && (nmcli -t -f RUNNING g 2>&1 | grep -E '^running$' >/dev/null 2>&1 ) ; then
    NM_RUNNING=1
fi

nm_knows() {
    (nmcli dev show $1 | grep -E "^GENERAL.STATE:" >/dev/null 2>&1 ) && return 0 # nm sees
    return 1 # nm doesn't see this interface
}
nm_get_manage() { # get an interface's managed state
    local s
    s=$(nmcli dev show $1 | grep -E "^GENERAL.STATE:") || return 2 # no such interface
    (echo $s | grep "unmanaged" >/dev/null 2>&1) && return 1 # unmanaged
    return 0 # managed
}
nm_set_unmanaged() {
    while ! nm_knows $1 ; do # wait for virtual wifi interface seen by NM
        sleep 0.5
    done
    if nm_get_manage $1 ;then
        echo "Set $1 unmanaged by NetworkManager"
        nmcli dev set $1 managed no || die "Failed to set $1 unmanaged by NetworkManager"
        NM_UNM_LIST=$1
        sleep 1
    fi
}

nm_set_managed() {
    nmcli dev set $1 managed yes
    NM_UNM_LIST=
}
nm_restore_manage() {
    if [[ $NM_UNM_LIST ]]; then
        echo "Restore $NM_UNM_LIST managed by NetworkManager"
        nm_set_managed $NM_UNM_LIST
        sleep 0.5
    fi
}


#=========

iptables_()
{
    iptables -w $@ -m comment --comment "lnxrouter-$$-$SUBNET_IFACE"
    return $?
}
ip6tables_()
{
    ip6tables -w $@ -m comment --comment "lnxrouter-$$-$SUBNET_IFACE"
    return $?
}

start_nat() {
    if [[ $INTERNET_IFACE ]]; then
        IPTABLES_NAT_OUT="-o ${INTERNET_IFACE}"
        IPTABLES_NAT_IN="-i ${INTERNET_IFACE}"
        MASQUERADE_NOTOUT=""
    else
        MASQUERADE_NOTOUT="! -o ${SUBNET_IFACE}"
    fi
    echo
    echo "iptables: NAT "
    iptables_ -v -t nat -I POSTROUTING -s ${GATEWAY%.*}.0/24 $IPTABLES_NAT_OUT $MASQUERADE_NOTOUT ! -d ${GATEWAY%.*}.0/24  -j MASQUERADE || die
    iptables_ -v -I FORWARD -i ${SUBNET_IFACE} $IPTABLES_NAT_OUT -s ${GATEWAY%.*}.0/24 -j ACCEPT || die
    iptables_ -v -I FORWARD -o ${SUBNET_IFACE} $IPTABLES_NAT_IN  -d ${GATEWAY%.*}.0/24 -j ACCEPT || die
    if [[ $IPV6 -eq 1 ]]; then
        ip6tables_ -v -t nat -I POSTROUTING -s ${PREFIX6}/64 $IPTABLES_NAT_OUT $MASQUERADE_NOTOUT ! -d ${PREFIX6}/64  -j MASQUERADE || die
        ip6tables_ -v -I FORWARD -i ${SUBNET_IFACE} $IPTABLES_NAT_OUT -s ${PREFIX6}/64 -j ACCEPT || die
        ip6tables_ -v -I FORWARD -o ${SUBNET_IFACE} $IPTABLES_NAT_IN   -d ${PREFIX6}/64 -j ACCEPT || die
    fi
}
stop_nat() {
    echo "iptables: stop NAT"
    iptables_ -t nat -D POSTROUTING -s ${GATEWAY%.*}.0/24 $IPTABLES_NAT_OUT $MASQUERADE_NOTOUT ! -d ${GATEWAY%.*}.0/24  -j MASQUERADE
    iptables_ -D FORWARD -i ${SUBNET_IFACE} $IPTABLES_NAT_OUT -s ${GATEWAY%.*}.0/24 -j ACCEPT
    iptables_ -D FORWARD -o ${SUBNET_IFACE} $IPTABLES_NAT_IN  -d ${GATEWAY%.*}.0/24 -j ACCEPT
    if [[ $IPV6 -eq 1 ]]; then
        ip6tables_ -t nat -D POSTROUTING -s ${PREFIX6}/64 $IPTABLES_NAT_OUT $MASQUERADE_NOTOUT ! -d ${PREFIX6}/64  -j MASQUERADE
        ip6tables_ -D FORWARD -i ${SUBNET_IFACE} $IPTABLES_NAT_OUT -s ${PREFIX6}/64 -j ACCEPT
        ip6tables_ -D FORWARD -o ${SUBNET_IFACE} $IPTABLES_NAT_IN  -d ${PREFIX6}/64 -j ACCEPT
    fi
}

allow_dns_port() {
    echo
    echo "iptables: allow DNS port access"
    iptables_ -v -I INPUT -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -d ${GATEWAY} -p tcp -m tcp --dport 53 -j ACCEPT || die
    iptables_ -v -I INPUT -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -d ${GATEWAY} -p udp -m udp --dport 53 -j ACCEPT || die
    if [[ $IPV6 -eq 1 ]]; then
        ip6tables_ -v -I INPUT -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -d ${GATEWAY6} -p tcp -m tcp --dport 53 -j ACCEPT || die
        ip6tables_ -v -I INPUT -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -d ${GATEWAY6} -p udp -m udp --dport 53 -j ACCEPT || die
    fi
}
unallow_dns_port() {
    echo "iptables: stop allowing DNS"
    iptables_ -D INPUT -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -d ${GATEWAY} -p tcp -m tcp --dport 53 -j ACCEPT
    iptables_ -D INPUT -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -d ${GATEWAY}  -p udp -m udp --dport 53 -j ACCEPT
    if [[ $IPV6 -eq 1 ]]; then
        ip6tables_ -D INPUT -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -d ${GATEWAY6} -p tcp -m tcp --dport 53 -j ACCEPT
        ip6tables_ -D INPUT -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -d ${GATEWAY6} -p udp -m udp --dport 53 -j ACCEPT
    fi
}

start_dhcp() {
    echo 
    echo "iptables: allow DHCP port access"
    iptables_ -v -I INPUT -i ${SUBNET_IFACE} -p udp -m udp --dport 67 -j ACCEPT || die
    if [[ $IPV6 -eq 1 ]]; then
        ip6tables_ -v -I INPUT -i ${SUBNET_IFACE} -p udp -m udp --dport 547 -j ACCEPT || die
    fi
}
stop_dhcp() {
    echo "iptables: stop dhcp"
    iptables_ -D INPUT -i ${SUBNET_IFACE} -p udp -m udp --dport 67 -j ACCEPT
    if [[ $IPV6 -eq 1 ]]; then
        ip6tables_ -D INPUT -i ${SUBNET_IFACE} -p udp -m udp --dport 547 -j ACCEPT
    fi
}

start_redsocks() {
    echo
    echo "iptables: transparent proxy non-LAN TCP/UDP traffic to port ${TP_PORT}"
    iptables_ -t nat -N REDSOCKS-${SUBNET_IFACE} || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 0.0.0.0/8 -j RETURN || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 10.0.0.0/8 -j RETURN || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 100.64.0.0/10  -j RETURN || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 127.0.0.0/8 -j RETURN || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 169.254.0.0/16 -j RETURN || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 172.16.0.0/12 -j RETURN || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 192.168.0.0/16 -j RETURN || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 224.0.0.0/4 -j RETURN || die
    iptables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d 255.255.255.255 -j RETURN || die
    
    iptables_ -v -t nat -A REDSOCKS-${SUBNET_IFACE} -p tcp -j REDIRECT --to-ports ${TP_PORT} || die
    iptables_ -v -t nat -A REDSOCKS-${SUBNET_IFACE} -p udp -j REDIRECT --to-ports ${TP_PORT} || die

    iptables_ -v -t nat -I PREROUTING -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -j REDSOCKS-${SUBNET_IFACE} || die

    iptables_ -v -I INPUT -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -p tcp -m tcp --dport ${TP_PORT}  -j ACCEPT || die
    iptables_ -v -I INPUT -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -p udp -m udp --dport ${TP_PORT}  -j ACCEPT || die
    
    if [[ $IPV6 -eq 1 ]]; then
        ip6tables_ -t nat -N REDSOCKS-${SUBNET_IFACE} || die
        ip6tables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d fc00::/7 -j RETURN || die
        ip6tables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d fe80::/10 -j RETURN || die
        ip6tables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d ff00::/8 -j RETURN || die
        ip6tables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d ::1 -j RETURN || die
        ip6tables_ -t nat -A REDSOCKS-${SUBNET_IFACE} -d :: -j RETURN || die

        ip6tables_ -v -t nat -A REDSOCKS-${SUBNET_IFACE} -p tcp -j REDIRECT --to-ports ${TP_PORT} || die
        ip6tables_ -v -t nat -A REDSOCKS-${SUBNET_IFACE} -p udp -j REDIRECT --to-ports ${TP_PORT} || die

        ip6tables_ -v -t nat -I PREROUTING -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -j REDSOCKS-${SUBNET_IFACE} || die

        ip6tables_ -v -I INPUT -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -p tcp -m tcp --dport ${TP_PORT}  -j ACCEPT || die
        ip6tables_ -v -I INPUT -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -p udp -m udp --dport ${TP_PORT}  -j ACCEPT || die   
    fi
}
stop_redsocks() {
    echo "iptables: stop transparent proxy"
    iptables_ -t nat -D PREROUTING -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24  -j REDSOCKS-${SUBNET_IFACE}
    iptables_ -t nat -F REDSOCKS-${SUBNET_IFACE}
    iptables_ -t nat -X REDSOCKS-${SUBNET_IFACE}
    
    iptables_ -D INPUT -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -p tcp -m tcp --dport ${TP_PORT}  -j ACCEPT
    iptables_ -D INPUT -i ${SUBNET_IFACE} -s ${GATEWAY%.*}.0/24 -p udp -m udp --dport ${TP_PORT}  -j ACCEPT
    
    if [[ $IPV6 -eq 1 ]]; then
        ip6tables_ -t nat -D PREROUTING -i ${SUBNET_IFACE} -s ${PREFIX6}/64  -j REDSOCKS-${SUBNET_IFACE}
        ip6tables_ -t nat -F REDSOCKS-${SUBNET_IFACE}
        ip6tables_ -t nat -X REDSOCKS-${SUBNET_IFACE}
        
        ip6tables_ -D INPUT -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -p tcp -m tcp --dport ${TP_PORT}  -j ACCEPT
        ip6tables_ -D INPUT -i ${SUBNET_IFACE} -s ${PREFIX6}/64 -p udp -m udp --dport ${TP_PORT}  -j ACCEPT
    fi
}

kill_processes() {
    #echo "Killing processes"
    local x  pid
    for x in $CONFDIR/*.pid; do
        # even if the $CONFDIR is empty, the for loop will assign
        # a value in $x. so we need to check if the value is a file
        if [[ -f $x ]] &&  sleep 0.3  && [[ -f $x ]]; then
            pid=$(cat $x)
            pn=$( ps -p $pid -o comm= ) 
            #echo "Killing $pid $pn ... "
            kill $pid 2>/dev/null && ( echo "Killed $pid $pn" && rm $x ) || echo "Failed to kill $pid $pn, it may have exited"
        fi
    done
    
}
_cleanup() {
    local x

    ip addr flush ${SUBNET_IFACE}
    
    if [[ -d $CONFDIR/sys_6_conf_iface ]]; then
        cp -f $CONFDIR/sys_6_conf_iface/* /proc/sys/net/ipv6/conf/$SUBNET_IFACE/
    fi
    rm -rf $CONFDIR
    
    if [[ $WIFI_IFACE && $NO_VIRT -eq 0 ]]; then
        ip link set down dev ${AP_IFACE}
        iw dev ${VWIFI_IFACE} del
        dealloc_iface $VWIFI_IFACE
    else
        if [[ -n "$NEW_MACADDR" ]]; then
            ip link set dev ${TARGET_IFACE} address ${OLD_MACADDR} && echo "Restore ${TARGET_IFACE} to old MAC address ${OLD_MACADDR}"
        fi
    fi
    
    
    if ! has_running_instance; then
        echo "Exiting: This is the only running instance"
        # kill common processes
        for x in $COMMON_CONFDIR/*.pid; do
            [[ -f $x ]] && kill -9 $(cat $x) && rm $x
        done
        
        rm -d $COMMON_CONFDIR/ifaces
        rm -d $COMMON_CONFDIR
        rm -d $TMPDIR
    else
        echo "Exiting: This is NOT the only running instance"
    fi
    
    nm_restore_manage
}

clean_iptables() {

    if [[ "$SHARE_METHOD" == "nat" ]]; then
        stop_nat
    elif [[ "$SHARE_METHOD" == "redsocks" ]]; then
        stop_redsocks
    fi
    
    if [[ "$DHCP_DNS" == "gateway" || "$DHCP_DNS6" == "gateway" ]]; then
        unallow_dns_port
    fi
    
    
    if [[ $NO_DNSMASQ -eq 0 ]]; then
        stop_dhcp
    fi
}

cleanup() {
    trap "" SIGINT SIGUSR1 SIGUSR2 EXIT SIGTERM
    echo
    echo
    echo "Doing cleanup.. "
    kill_processes
    clean_iptables  2> /dev/null
    _cleanup 2> /dev/null
    
    pgid=$(ps opgid= $$ |awk '{print $1}' )
    kill -15 -$pgid
    sleep 1 
    echo "Cleaning up done"
    kill -9 -$pgid
}

die() { # SIGUSR2
    echo "Error occured"
    [[ -n "$1" ]] && echo -e "\nERROR: $1\n" >&2
    # send die signal to the main process
    [[ $BASHPID -ne $$ ]] && kill -USR2 $$ || cleanup
    exit 1
}

clean_exit() { # SIGUSR1
    # send clean_exit signal to the main process
    [[ $BASHPID -ne $$ ]] && kill -USR1 $$ || cleanup
    exit 0
}

#========

list_running_conf() {
    local x
    for x in $TMPDIR/lnxrouter.*; do
        if [[ -f $x/pid && -f $x/subn_iface && -d /proc/$(cat $x/pid) ]]; then
            echo $x
        fi
    done
}

list_running() {
    local IFACE subn_iface x
    for x in $(list_running_conf); do
        IFACE=${x#*.}
        IFACE=${IFACE%%.*}
        subn_iface=$(cat $x/subn_iface)

        if [[ $IFACE == $subn_iface ]]; then
            echo $(cat $x/pid) $IFACE
        else
            echo $(cat $x/pid) $IFACE '('$(cat $x/subn_iface)')'
        fi
    done
}

get_subn_iface_from_pid() {
    list_running | awk '{print $1 " " $NF}' | tr -d '\(\)' | grep -E "^${1} " | cut -d' ' -f2
}

get_pid_from_subn_iface() {
    list_running | awk '{print $1 " " $NF}' | tr -d '\(\)' | grep -E " ${1}$" | cut -d' ' -f1
}

get_confdir_from_pid() {
    local IFACE x
    for x in $(list_running_conf); do
        if [[ $(cat $x/pid) == "$1" ]]; then
            echo $x
            break
        fi
    done
}

print_client_by_mac() {
    local line ipaddr hostname
    local mac="$1"

    if [[ -f $CONFDIR/dnsmasq.leases ]]; then
        line=$(grep " $mac " $CONFDIR/dnsmasq.leases | tail -n 1)
        ipaddr=$(echo $line | cut -d' ' -f3)
        hostname=$(echo $line | cut -d' ' -f4)
    fi

    [[ -z "$ipaddr" ]] && ipaddr="*"
    [[ -z "$hostname" ]] && hostname="*"

    printf "%-20s %-18s %s\n" "$mac" "$ipaddr" "$hostname"
}

print_clients_in_leases() {
    local line ipaddr hostname
    local mac

    if [[ -f $CONFDIR/dnsmasq.leases ]]; then
        while read line
        do
            mac=$(echo $line | cut -d' ' -f2)
            ipaddr=$(echo $line | cut -d' ' -f3)
            hostname=$(echo $line | cut -d' ' -f4)
            
            printf "%-20s %-18s %s\n" "MAC" "IP" "Hostname"
            printf "%-20s %-18s %s\n" "$mac" "$ipaddr" "$hostname"
        done < $CONFDIR/dnsmasq.leases
    fi
}

list_clients() {
    local subn_iface pid

    # If PID is given, get the associated wifi iface
    if [[ "$1" =~ ^[1-9][0-9]*$ ]]; then
        pid="$1"
        subn_iface=$(get_subn_iface_from_pid "$pid")
        [[ -z "$subn_iface" ]] && die "'$pid' is not the pid of a running $PROGNAME instance."
    fi

    [[ -z "$subn_iface" ]] && subn_iface="$1"

    [[ -z "$pid" ]] && pid=$(get_pid_from_subn_iface "$subn_iface")
    [[ -z "$pid" ]] && die "'$subn_iface' is not used from $PROGNAME instance.\n\
       Maybe you need to pass the virtual interface instead.\n\
       Use --list-running to find it out."
    [[ -z "$CONFDIR" ]] && CONFDIR=$(get_confdir_from_pid "$pid")

    if [[ -f $CONFDIR/hostapd.conf  && $USE_IWCONFIG -eq 0 ]]; then
        local awk_cmd='($1 ~ /Station$/) {print $2}'
        local client_list=$(iw dev "$subn_iface" station dump | awk "$awk_cmd")

        if [[ -z "$client_list" ]]; then
            echo "No clients connected"
            return
        fi

        printf "%-20s %-18s %s\n" "MAC" "IP" "Hostname"

        local mac
        for mac in $client_list; do
            print_client_by_mac $mac
        done
    else
        echo "Listing clients via DNS lease file. non-DHCPed clients won't be showed"
        print_clients_in_leases
    fi 
}

has_running_instance() {
    local PID x

    for x in $TMPDIR/lnxrouter.*; do
        if [[ -f $x/pid ]]; then
            PID=$(cat $x/pid)
            if [[ -d /proc/$PID ]]; then
                return 0
            fi
        fi
    done

    return 1
}

is_running_pid() {
    list_running | grep -E "^${1} " > /dev/null 2>&1
}

send_stop() {
    local x

    # send stop signal to specific pid
    if is_running_pid $1; then
        kill -USR1 $1
        return
    fi

    # send stop signal to specific interface
    for x in $(list_running | grep -E " \(?${1}( |\)?\$)" | cut -f1 -d' '); do
        kill -USR1 $x
    done
}


## ========================================================
## ========================================================

if [[ -d /dev/shm ]]; then
    TMPD=/dev/shm
elif [[ -d /run/shm ]]; then
    TMPD=/run/shm
else
    TMPD=/tmp
fi
TMPDIR=$TMPD/lnxrouter_tmp

#======

if [[ $LIST_RUNNING -eq 1 ]]; then
    echo -e "List of running $PROGNAME instances:\n"
    list_running
    exit 0
fi

if [[ -n "$LIST_CLIENTS_ID" ]]; then
    list_clients "$LIST_CLIENTS_ID"
    exit 0
fi

if [[ $(id -u) -ne 0 ]]; then
    echo "You must run it as root." >&2
    exit 1
fi

if [[ -n "$STOP_ID" ]]; then
    echo "Trying to kill $PROGNAME instance associated with $STOP_ID..."
    send_stop "$STOP_ID"
    exit 0
fi

#=============================================
#=============================================

if [[ $DAEMONIZE -eq 1 && $RUNNING_AS_DAEMON -eq 0 ]]; then
    echo "Running as Daemon..."
    # run a detached lnxrouter
    RUNNING_AS_DAEMON=1 setsid "$0" "${ARGS[@]}" &
    exit 0
fi

if [[ $WIFI_IFACE ]]; then

    if [[ $FREQ_BAND != 2.4 && $FREQ_BAND != 5 ]]; then
        echo "ERROR: Invalid frequency band" >&2
        exit 1
    fi

    if [[ $CHANNEL == default ]]; then
        if [[ $FREQ_BAND == 2.4 ]]; then
            CHANNEL=1
        else
            CHANNEL=36
        fi
    fi

    if [[ $FREQ_BAND != 5 && $CHANNEL -gt 14 ]]; then
        echo "Channel number is greater than 14, assuming 5GHz frequency band"
        FREQ_BAND=5
    fi

    if ! can_be_ap ${WIFI_IFACE}; then
        echo "ERROR: Your adapter does not support AP (master) mode" >&2
        exit 1
    fi

    if ! can_be_sta_and_ap ${WIFI_IFACE}; then
        if is_wifi_connected ${WIFI_IFACE}; then
            echo "ERROR: Your adapter can not be a station (i.e. be connected) and an AP at the same time" >&2
            exit 1
        elif [[ $NO_VIRT -eq 0 ]]; then
            echo "WARN: Your adapter does not fully support AP virtual interface, enabling --no-virt" >&2
            NO_VIRT=1
        fi
    fi

    HOSTAPD=$(which hostapd)

    if [[ $(get_adapter_kernel_module ${WIFI_IFACE}) =~ ^(8192[cd][ue]|8723a[sue])$ ]]; then
        if ! strings "$HOSTAPD" | grep -m1 rtl871xdrv > /dev/null 2>&1; then
            echo "ERROR: You need to patch your hostapd with rtl871xdrv patches." >&2
            exit 1
        fi

        if [[ $DRIVER != "rtl871xdrv" ]]; then
            echo "WARN: Your adapter needs rtl871xdrv, enabling --driver=rtl871xdrv" >&2
            DRIVER=rtl871xdrv
        fi
    fi
    
    if [[ ${#SSID} -lt 1 || ${#SSID} -gt 32 ]]; then
        echo "ERROR: Invalid SSID length ${#SSID} (expected 1..32)" >&2
        exit 1
    fi

    if [[ $USE_PSK -eq 0 ]]; then
        if [[ ${#PASSPHRASE} -gt 0 && ${#PASSPHRASE} -lt 8 ]] || [[ ${#PASSPHRASE} -gt 63 ]]; then
            echo "ERROR: Invalid passphrase length ${#PASSPHRASE} (expected 8..63)" >&2
            exit 1
        fi
    elif [[ ${#PASSPHRASE} -gt 0 && ${#PASSPHRASE} -ne 64 ]]; then
        echo "ERROR: Invalid pre-shared-key length ${#PASSPHRASE} (expected 64)" >&2
        exit 1
    fi

    if [[ $(get_adapter_kernel_module ${WIFI_IFACE}) =~ ^rtl[0-9].*$ ]]; then
        if [[ $WPA_VERSION == '1' || $WPA_VERSION == '1+2' ]]; then
            echo "WARN: Realtek drivers usually have problems with WPA1, WPA2 is recommended" >&2
        fi
        echo "WARN: If AP doesn't work, read https://github.com/oblique/create_ap/blob/master/howto/realtek.md" >&2
    fi

fi

if [[ -n "$NEW_MACADDR" ]]; then
    if ! is_unicast_macaddr "$NEW_MACADDR"; then
        echo "ERROR: The first byte of MAC address (${NEW_MACADDR}) must be even" >&2
        exit 1
    fi

    if [[ $(get_all_macaddrs | grep -c ${NEW_MACADDR}) -ne 0 ]]; then
        echo "WARN: MAC address '${NEW_MACADDR}' already exists" >&2
    fi
fi

# checks finished

## ========================================================
## ========================================================
echo "PID: $$"

TARGET_IFACE=   # This is the existing physical interface to use
if [[ $CONN_IFACE ]]; then
    TARGET_IFACE=$CONN_IFACE
elif [[ $WIFI_IFACE ]]; then
    TARGET_IFACE=$WIFI_IFACE
else
    echo "No target interface specified" 1>&2
    exit 1
fi
echo "Target interface is ${TARGET_IFACE}"


if [[ ! -n $GATEWAY ]]; then
    generate_random_ip4
    echo "Use random IPv4 address $GATEWAY"
fi
if [[ $IPV6 -eq 1 && ! -n $PREFIX6 ]]; then
    generate_random_ip6
    echo "Use random IPv6 address ${PREFIX6}${IID6}"
fi
if [[ $IPV6 -eq 1 ]]; then
    GATEWAY6=${PREFIX6}${IID6}
fi

if [[ $TP_PORT ]]; then
    SHARE_METHOD=redsocks
fi

if [[ $DHCP_DNS != 'gateway' && $DHCP_DNS6 != 'gateway' ]]; then
    dnsmasq_NO_DNS=1
fi

#=================
# begin to do some change on config files and system

trap "cleanup" EXIT
trap "clean_exit" SIGINT SIGUSR1 SIGTERM
trap "die" SIGUSR2

mkdir -p $TMPDIR
chmod 755 $TMPDIR 2>/dev/null
cd $TMPDIR

CONFDIR=$(mktemp -d $TMPDIR/lnxrouter.${TARGET_IFACE}.conf.XXX)
chmod 755 $CONFDIR
#echo "Config dir: $CONFDIR"
echo $$ > $CONFDIR/pid


COMMON_CONFDIR=$TMPDIR/lnxrouter_common.conf
mkdir -p $COMMON_CONFDIR



if [[ $WIFI_IFACE ]]; then

    if [[ $USE_IWCONFIG -eq 0 ]]; then
        iw dev ${WIFI_IFACE} set power_save off
    fi
    
    if [[ $NO_VIRT -eq 0 ]]; then
    ## Generate virtual wifi interface
    
        VWIFI_IFACE=$(alloc_new_iface)

        if is_wifi_connected ${WIFI_IFACE}; then
            WIFI_IFACE_FREQ=$(iw dev ${WIFI_IFACE} link | grep -i freq | awk '{print $2}')
            WIFI_IFACE_CHANNEL=$(ieee80211_frequency_to_channel ${WIFI_IFACE_FREQ})
            echo "${WIFI_IFACE} already in channel ${WIFI_IFACE_CHANNEL} (${WIFI_IFACE_FREQ} MHz)"
            if is_5ghz_frequency $WIFI_IFACE_FREQ; then
                FREQ_BAND=5
            else
                FREQ_BAND=2.4
            fi
            if [[ $WIFI_IFACE_CHANNEL -ne $CHANNEL ]]; then
                echo "Channel fallback to ${WIFI_IFACE_CHANNEL}"
                CHANNEL=$WIFI_IFACE_CHANNEL
            else
                echo
            fi
        fi

        VIRTDIEMSG="Maybe your WiFi adapter does not fully support virtual interfaces.
        Try again with --no-virt."
        echo "Creating a virtual WiFi interface... "

        if iw dev ${WIFI_IFACE} interface add ${VWIFI_IFACE} type __ap; then
            echo "${VWIFI_IFACE} created."
            sleep 2
        else
            VWIFI_IFACE=
            die "$VIRTDIEMSG"
        fi
        OLD_MACADDR=$(get_macaddr ${VWIFI_IFACE})
        if [[ -z "$NEW_MACADDR" && $(get_all_macaddrs | grep -c ${OLD_MACADDR}) -ne 1 ]]; then
            NEW_MACADDR=$(get_new_macaddr ${VWIFI_IFACE})
        fi
        AP_IFACE=${VWIFI_IFACE}
    else
        OLD_MACADDR=$(get_macaddr ${WIFI_IFACE})
        AP_IFACE=${WIFI_IFACE}
    fi

fi

if [[ $WIFI_IFACE ]]; then
    SUBNET_IFACE=${AP_IFACE}
else
    SUBNET_IFACE=${TARGET_IFACE}
fi

echo $SUBNET_IFACE > $CONFDIR/subn_iface

if [[ $WIFI_IFACE ]]; then

    if [[ -n "$COUNTRY" && $USE_IWCONFIG -eq 0 ]]; then
        iw reg set "$COUNTRY"
    fi

    can_transmit_to_channel ${AP_IFACE} ${CHANNEL} || die "Your adapter can not transmit to channel ${CHANNEL}, frequency band ${FREQ_BAND}GHz."


    [[ $HIDDEN -eq 1 ]] && echo "Access Point's SSID is hidden!"

    [[ $MAC_FILTER -eq 1 ]] && echo "MAC address filtering is enabled!"

    [[ $ISOLATE_CLIENTS -eq 1 ]] && echo "Access Point's clients will be isolated!"

    # hostapd config
    cat <<- EOF > $CONFDIR/hostapd.conf
		beacon_int=100
		ssid=${SSID}
		interface=${AP_IFACE}
		driver=${DRIVER}
		channel=${CHANNEL}
		ctrl_interface=$CONFDIR/hostapd_ctrl
		ctrl_interface_group=0
		ignore_broadcast_ssid=$HIDDEN
		ap_isolate=$ISOLATE_CLIENTS
	EOF

    if [[ -n "$COUNTRY" ]]; then
        cat <<- EOF >> $CONFDIR/hostapd.conf
			country_code=${COUNTRY}
			ieee80211d=1
		EOF
    fi

    if [[ $FREQ_BAND == 2.4 ]]; then
        echo "hw_mode=g" >> $CONFDIR/hostapd.conf
    else
        echo "hw_mode=a" >> $CONFDIR/hostapd.conf
    fi

    if [[ $MAC_FILTER -eq 1 ]]; then
        cat <<- EOF >> $CONFDIR/hostapd.conf
			macaddr_acl=${MAC_FILTER}
			accept_mac_file=${MAC_FILTER_ACCEPT}
		EOF
    fi

    if [[ $IEEE80211N -eq 1 ]]; then
        cat <<- EOF >> $CONFDIR/hostapd.conf
			ieee80211n=1
			ht_capab=${HT_CAPAB}
		EOF
    fi

    if [[ $IEEE80211AC -eq 1 ]]; then
        echo "ieee80211ac=1" >> $CONFDIR/hostapd.conf
    fi

    if [[ -n "$VHT_CAPAB" ]]; then
        echo "vht_capab=${VHT_CAPAB}" >> $CONFDIR/hostapd.conf
    fi

    if [[ $IEEE80211N -eq 1 ]] || [[ $IEEE80211AC -eq 1 ]]; then
        echo "wmm_enabled=1" >> $CONFDIR/hostapd.conf
    fi

    if [[ -n "$PASSPHRASE" ]]; then
        [[ "$WPA_VERSION" == "1+2" ]] && WPA_VERSION=3
        if [[ $USE_PSK -eq 0 ]]; then
            WPA_KEY_TYPE=passphrase
        else
            WPA_KEY_TYPE=psk
        fi
        cat <<- EOF >> $CONFDIR/hostapd.conf
			wpa=${WPA_VERSION}
			wpa_${WPA_KEY_TYPE}=${PASSPHRASE}
			wpa_key_mgmt=WPA-PSK
			wpa_pairwise=CCMP
			rsn_pairwise=CCMP
		EOF
    else
        echo "WARN: Wifi is not protected by password" >&2
    fi
	chmod 600 $CONFDIR/hostapd.conf
fi

#===================================================
#===================================================

if [[ $NM_RUNNING -eq 1 ]] && nm_knows $TARGET_IFACE ; then
    nm_set_unmanaged ${SUBNET_IFACE}
fi

if [[ $NO_DNSMASQ -eq 0 ]]; then
    cat <<- EOF > $CONFDIR/dnsmasq.conf
		user=nobody
		group=nobody
		bind-dynamic
		listen-address=${GATEWAY}
		interface=$SUBNET_IFACE
		except-interface=lo
		no-dhcp-interface=lo
		dhcp-range=${GATEWAY%.*}.10,${GATEWAY%.*}.250,255.255.255.0
		dhcp-option-force=option:router,${GATEWAY}
		#log-dhcp
		log-facility=/dev/null
		bogus-priv
		domain-needed
	EOF
    # 'log-dhcp' show too much logs. Using '-d' in dnsmasq command shows a proper dhcp log
    # if use '-d', 'log-facility' should = /dev/null
    if [[ $SHARE_METHOD == "none" ]]; then    
        echo "no-resolv"  >> $CONFDIR/dnsmasq.conf
        echo "no-poll" >> $CONFDIR/dnsmasq.conf
    fi
    if [[ "$DHCP_DNS" != "no" ]]; then
        if [[ "$DHCP_DNS" == "gateway" ]]; then
            dns_offer="$GATEWAY"
        else
            dns_offer="$DHCP_DNS"
        fi
        echo "dhcp-option-force=option:dns-server,${dns_offer}" >> $CONFDIR/dnsmasq.conf
    fi
    
    if [[ ! "$dnsmasq_NO_DNS" -eq 0 ]]; then
        echo "port=0"  >> $CONFDIR/dnsmasq.conf
    fi

    [[ -n "$MTU" ]] && echo "dhcp-option-force=option:mtu,${MTU}" >> $CONFDIR/dnsmasq.conf
    [[ $ETC_HOSTS -eq 0 ]] && echo no-hosts >> $CONFDIR/dnsmasq.conf
    [[ -n "$ADDN_HOSTS" ]] && echo "addn-hosts=${ADDN_HOSTS}" >> $CONFDIR/dnsmasq.conf
    if [[ "$THISHOSTNAME" ]]; then
        [[ "$THISHOSTNAME" == "-" ]] && THISHOSTNAME="$(cat /etc/hostname)"
        echo "interface-name=$THISHOSTNAME,$SUBNET_IFACE" >> $CONFDIR/dnsmasq.conf
    fi
    if [[ ! "$SHOW_DNS_QUERY" -eq 0 ]]; then
        echo log-queries=extra >> $CONFDIR/dnsmasq.conf
    fi
    
    if [[ $DNS ]]; then
        DNS_count=$(echo $DNS | awk -F, '{print NF}')
        for (( i=1;i<=DNS_count;i++ )); do
            sep_ip_port "$(echo $DNS | cut -d, -f$i)" DNS_IP DNS_PORT
            [[ "$DNS_PORT" ]] && DNS_PORT_D="#$DNS_PORT"
            echo "server=${DNS_IP}${DNS_PORT_D}" >> $CONFDIR/dnsmasq.conf
        done
        
        cat <<- EOF >> $CONFDIR/dnsmasq.conf
			no-resolv
			no-poll
		EOF
    fi
    if [[ $IPV6 -eq 1 ]];then
        cat <<- EOF  >> $CONFDIR/dnsmasq.conf
			listen-address=${GATEWAY6}
			enable-ra
			#quiet-ra
			dhcp-range=interface:${SUBNET_IFACE},::,::ffff:ffff:ffff:ffff,constructor:${SUBNET_IFACE},ra-stateless,64
		EOF
        if [[ "$DHCP_DNS6" != "no" ]]; then
            if [[ "$DHCP_DNS6" == "gateway" ]]; then
                dns_offer6="[$GATEWAY6]"
            else
                dns_offer6="$DHCP_DNS6"
            fi
            echo "dhcp-option=option6:dns-server,${dns_offer6}" >> $CONFDIR/dnsmasq.conf
        fi
    fi
fi

#===========================

# initialize subnet interface
if [[  -n "$NEW_MACADDR" ]]; then
    ip link set dev ${SUBNET_IFACE} address ${NEW_MACADDR} || die "Failed setting new MAC address"
fi

ip link set down dev ${SUBNET_IFACE} || die "Failed setting ${SUBNET_IFACE} down"
ip addr flush ${SUBNET_IFACE} || die "Failed flush ${SUBNET_IFACE} IP"


ip link set up dev ${SUBNET_IFACE} || die "Failed bringing ${SUBNET_IFACE} up"

if [[ $WIFI_IFACE ]]; then

    if [[ $NO_HAVEGED -eq 0 ]]; then
        haveged_watchdog &
        HAVEGED_WATCHDOG_PID=$!
        echo $HAVEGED_WATCHDOG_PID > $CONFDIR/haveged_watchdog.pid
        echo "haveged_watchdog PID: $HAVEGED_WATCHDOG_PID" 
    fi

    # start access point
    #echo "hostapd command-line interface: hostapd_cli -p $CONFDIR/hostapd_ctrl"
    # start hostapd (use stdbuf when available for no delayed output in programs that redirect stdout)
    STDBUF_PATH=`which stdbuf`
    if [ $? -eq 0 ]; then
        STDBUF_PATH=$STDBUF_PATH" -oL"
    fi
    echo 
    echo "Starting hostapd"
    # hostapd '-P' works only when use '-B' (run in background)
    $STDBUF_PATH hostapd $HOSTAPD_DEBUG_ARGS -P $CONFDIR/hostapd.pid $CONFDIR/hostapd.conf  &
    HOSTAPD_PID=$!
    echo $HOSTAPD_PID > $CONFDIR/hostapd.pid
    echo "hostapd PID: $HOSTAPD_PID"
    #while [[ ! -f $CONFDIR/hostapd.pid ]]; do
    #    sleep 1
    #done
    #echo -n "hostapd PID: " ; cat $CONFDIR/hostapd.pid
    ( while [ -e /proc/$HOSTAPD_PID ]; do sleep 10; done ; die "hostapd exited" ) &

    sleep 3
fi

ip addr add ${GATEWAY}/24 broadcast ${GATEWAY%.*}.255 dev ${SUBNET_IFACE} || die "Failed setting ${SUBNET_IFACE} IP"

mkdir $CONFDIR/sys_6_conf_iface
if [[ $IPV6 -eq 1 ]]; then
    cp /proc/sys/net/ipv6/conf/$SUBNET_IFACE/accept_ra     \
        /proc/sys/net/ipv6/conf/$SUBNET_IFACE/use_tempaddr  \
        /proc/sys/net/ipv6/conf/$SUBNET_IFACE/addr_gen_mode \
            $CONFDIR/sys_6_conf_iface/
    
    echo 0 > /proc/sys/net/ipv6/conf/$SUBNET_IFACE/accept_ra
    echo 0 > /proc/sys/net/ipv6/conf/$SUBNET_IFACE/use_tempaddr
    echo 0 > /proc/sys/net/ipv6/conf/$SUBNET_IFACE/addr_gen_mode
    
    ip -6 addr add ${GATEWAY6}/64  dev ${SUBNET_IFACE} || die "Failed setting ${SUBNET_IFACE} IPv6"
else
    cp /proc/sys/net/ipv6/conf/$SUBNET_IFACE/disable_ipv6  $CONFDIR/sys_6_conf_iface/
    echo 1 > /proc/sys/net/ipv6/conf/$SUBNET_IFACE/disable_ipv6
fi

# enable Internet sharing
if [[ "$SHARE_METHOD" == "none" ]]; then
    echo "No Internet sharing"
elif [[ "$SHARE_METHOD" == "nat" ]]; then
    [[ "$INTERNET_IFACE" && "$dnsmasq_NO_DNS" -eq 0 ]] && echo -e "\nWARN: You specified Internet interface but this host is providing local DNS, queries may leak to other interfaces!!!\n" >&2
    start_nat
    echo 1 > /proc/sys/net/ipv4/ip_forward || die "Failed enabling system ipv4 forwarding"
    if [[ $IPV6 -eq 1 ]]; then
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding || die "Failed enabling system ipv6 forwarding"
    fi
    # to enable clients to establish PPTP connections we must
    # load nf_nat_pptp module
    modprobe nf_nat_pptp > /dev/null 2>&1
elif [[ "$SHARE_METHOD" == "redsocks" ]]; then
    if [[ $IPV6 -eq 1 ]]; then
        echo 1 > /proc/sys/net/ipv6/conf/$SUBNET_IFACE/forwarding || die "Failed enabling $SUBNET_IFACE ipv6 forwarding"
    fi
    [[ "$dnsmasq_NO_DNS" -eq 0 && ! $DNS ]] &&  echo -e "\nWARN: You are using transparent proxy but this host is providing local DNS, this may cause privacy leak !!!\n" >&2

    start_redsocks
fi

# start dhcp + dns (optional)

if [[ "$DHCP_DNS" == "gateway" || "$DHCP_DNS6" == "gateway" ]]; then
    allow_dns_port
fi


if [[ $NO_DNSMASQ -eq 0 ]]; then
    start_dhcp

    if which complain > /dev/null 2>&1; then
        # openSUSE's apparmor does not allow dnsmasq to read files.
        # remove restriction.
        complain dnsmasq
    fi

    echo 
    echo "Starting dnsmasq"
    # dnsmasq '-x' works only when no '-d' (run in foreground)
    # Using '-d' dnsmasq will not turn into 'nobody'
    dnsmasq -d -C $CONFDIR/dnsmasq.conf -x $CONFDIR/dnsmasq.pid -l $CONFDIR/dnsmasq.leases & 
    DNSMASQ_PID=$!
    echo "dnsmasq PID: $DNSMASQ_PID"
    #while [[ ! -f $CONFDIR/dnsmasq.pid ]]; do
    #    sleep 1
    #done
    echo -n "dnsmasq PID: " ; cat $CONFDIR/dnsmasq.pid
    #(wait $DNSMASQ_PID ; die "dnsmasq failed") &
    ( while [ -e /proc/$DNSMASQ_PID ]; do sleep 10; done ; die "dnsmasq exited" ) &
    sleep 2

fi

echo 
echo "== Setting up completed, now linux-router is working =="
# need loop to keep this script running
bash -c "while :; do sleep 8000 ; done " &
KEEP_RUNNING_PID=$!
echo $KEEP_RUNNING_PID > $CONFDIR/keep_running.pid
wait $KEEP_RUNNING_PID

clean_exit
