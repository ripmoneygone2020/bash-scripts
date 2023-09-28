#!/bin/bash

HOSTNAME="GATEWAY01"
SYSTEM_TYPE="GENERIC"
SUDO_USER="sysadmin01"

OVPN_PORT=9931
OVPN_PROTO="tcp"

OVPN_PKI_ROOT="/etc/openvpn/server/pki"
OVPN_NETWORK_ADDR="172.9.0.0"
OVPN_SUBNET="255.255.255.0"

SSH_KEY=""
SSHD_PORT=22

ALLOW_ROOT_LOGIN="yes"

DNS01="1.1.1.1"
DNS02="1.0.0.1"
DOT_DOMAIN="cloudflare-dns.com"

openvpn --genkey tls-auth "tls-auth/ta.key"
openssl dhparam -out "dhparam/dh2048.pem" 2048


if [ $UID -ne 0 ]; then
    echo "[ERROR]: attempting to run build script without root priviledges"
    echo "[ERROR RESPONSE]: Exiting"

    exit
fi

OS_RELEASE_STRING="$(grep -Pe '^ID=[a-z]+$' /etc/os-release)"

if [ ! -z "$OS_RELEASE_STRING" ]; then
    echo "[INFO]: reading /etc/os-release..."

    IFS="="
    ## ARR specifies the words separates by IFS
    ## are assigned to the indices of an array
    read -a OS_RELEASE_ARR <<< "$OS_RELEASE_STRING"

    if [ "${#OS_RELEASE_ARR[@]}" -gt 1 ]; then
        OS_RELEASE_ID="${OS_RELEASE_ARR[1]}"

        echo "[INFO]: parsed /etc/os-release..."
        echo "[INFO]: os release id is $OS_RELEASE_ID"
    fi

    IFS=" "
else
    echo "[ERROR]: failed to parse /etc/os-release..."
    echo "[ERROR RESPONSE]: Exiting"

    exit
fi

case "$OS_RELEASE_ID" in
    "fedora")
        # set package manager command
        MGR="dnf"
        SUDO_GNAME="wheel"

        # configure other distro specific software related 
        # config settings
        IPT_NAME="services";
        IPT_PATH="/etc/sysconfig/iptables"
        IPT_SERVICE="iptables"
        IPT6_PATH="/etc/iptables/ip6tables"

        # disable unused services
        if [ "$(systemctl is-active cockpit)" = "active"]; then
            systemctl stop cockpit cockpit.socket
            systemctl disable cockpit cockpit.socket
            systemctl mask cockpit cockpit.socket
        fi

        if [ "$(systemctl is-active firewalld)" = "active" ]; then
            systemctl stop firewalld
            systemctl disable firewalld
            systemctl mask firewalld
        fi

        ;;

    "debian")
        # set package manager command
        MGR="apt"
        SUDO_GNAME="sudo"

        # configure other distro specific software related 
        # config settings
        IPT_NAME="persistent";
        IPT_PATH="/etc/iptables/rules.v4"
        IPT_SERVICE="netfilter-persistent"
        IPT6_PATH="/etc/iptables/rules.v6"

        # disable unused services
        if [ "$(systemctl is-active ufw)" = "active" ]; then
            systemctl stop ufw
            systemctl disable ufw 
            systemctl mask ufw
        fi

        ;;

    *)
        echo "[ERROR]: unsupported os release found... unable to continue."
        echo "[ERROR RESPONSE]: Exiting"

        exit

        ;;
esac

if [ ! -z "$(systemctl list-units --type service | grep systemd-resolved)" ]; then
    systemctl stop systemd-resolved 2> /dev/null
    systemctl disable systemd-resolved 2> /dev/null
    systemctl mask systemd-resolved 2> /dev/null
fi

if [ ! -z "$(systemctl list-units --type service | grep systemd-timesyncd)" ]; then
    systemctl stop systemd-timesyncd 2> /dev/null
    systemctl disable systemd-timesyncd 2> /dev/null
    systemctl mask systemd-timesyncd 2> /dev/null
fi

# set system hostname to the user defined hostname
echo "[INFO]: setting system hostname to $HOSTNAME"
hostnamectl set-hostname "$HOSTNAME"

echo "[INFO]: running $MGR system updates"
$MGR update -y

if [ "$MGR" = "apt" ]; then
    echo "[INFO]: running apt system upgrades."
    $MGR upgrade -y
fi

SOFTWARE="iptables iptables-$IPT_NAME unbound"

if [ "$SYSTEM_TYPE" = "VPN" ]; then
    echo "[INFO]: openvpn requested... installing openvpn."
    SOFTWARE="$SOFTWARE openvpn"
fi

$MGR install $SOFTWARE

if [ ! -z "$SUDO_USER" ]; then
    echo "[INFO]: sudo user requested... adding sudo user: $SUDO_USER"
    useradd -G $SUDO_GNAME -s /bin/bash $SUDO_USER
fi

echo "[INFO]: configuring iptables"

systemctl enable $IPT_SERVICE
systemctl start iptables

# flush iptables and delete custom chains

echo "[INFO]: flushing firewall rules..."
iptables -F

echo "[INFO]: deleting custom firewall chains..."
iptables -X ACCEPTED_TCP_CONNECTIONS
iptables -X ACCEPTED_UDP_CONNECTIONS

# create custom chains for incoming tcp and udp connections
echo "[INFO]: creating custom firewall chains..."
iptables -N ACCEPTED_TCP_CONNECTIONS
iptables -N ACCEPTED_UDP_CONNECTIONS

# INPUT CHAIN
echo "[INFO]: configuring ingress rules..."
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# MISC HARDENING RULES
iptables -A INPUT --fragment -j DROP
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A INPUT -m state ! --state NEW -j DROP

## ICMP
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# DROP ANY NEW INCOMING CONNS WITHOUT THE SYN FLAG SET
iptables -A INPUT -p tcp ! --syn -j DROP

# DROP ANY NEW INCOMING CONNS WITH ALL TCP FLAGS SET
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# LOOPBACK RULES
iptables -A INPUT -i lo -s 127.0.0.0/8 -j ACCEPT

# RATE LIMITING
iptables -A INPUT -p tcp -m limit --limit 1/s --limit-burst 60 -j ACCEPTED_TCP_CONNECTIONS
iptables -A INPUT -p udp -m limit --limit 1/s --limit-burst 60 -j ACCEPTED_UDP_CONNECTIONS

# OUTPUT CHAIN
echo "[INFO]: configuring egress rules..."
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state ! --state NEW -j DROP

# ICMP
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT

# LOOPBACK RULES
iptables -A OUTPUT -o lo -d 127.0.0.0/8 -j ACCEPT

# HTTP/HTTPS
iptables -A OUTPUT -o eth0 -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --dport 80 -j ACCEPT

# NTP/DNS
iptables -A OUTPUT -o eth0 -p udp --dport 123 -j ACCEPT
iptables -A OUTPUT -o eth0 -p udp -d $DNS01,$DNS02 --dport 53 -j ACCEPT

# FORWARDING CHAIN
echo "[INFO]: configuring forwarding rules..."
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables-save > $IPT_PATH

if [ -f "$IPT_PATH" ]; then
    echo "[INFO]: configuring default ipv4 ingress, egress, and forwarding policy..."

    sed -E -i 's/^:INPUT\s[A-Z]+/:INPUT DROP/g' $IPT_PATH
    sed -E -i 's/^:OUTPUT\s[A-Z]+/:OUTPUT DROP/g' $IPT_PATH
    sed -E -i 's/^:FORWARD\s[A-Z]+/:FORWARD DROP/g' $IPT_PATH
else
    echo "[ERROR]: failed to configure default ipv4 ingress, egress, and forwarding policy... exiting."
    exit
fi

if [ -f "$IPT6_PATH" ]; then
    echo "[INFO]: configuring default ipv6 ingress, egress, and forwarding policy..."

    sed -E -i 's/^:INPUT\s[A-Z]+/:INPUT DROP/g' $IPT6_PATH
    sed -E -i 's/^:OUTPUT\s[A-Z]+/:OUTPUT DROP/g' $IPT6_PATH
    sed -E -i 's/^:FORWARD\s[A-Z]+/:FORWARD DROP/g' $IPT6_PATH
else
    echo "[ERROR]: failed to configure default ipv6 ingress, egress, and forwarding policy... exiting."
    exit
fi

systemctl restart iptables

if [ "$(systemctl is-failed iptables)" = "failed" ]; then
    echo "Script ERROR... Exiting..."
    echo "ERROR: failed to start iptables"

    exit
fi

UNBOUND_CONFIG="\
server:\n\
    num-threads: 2\n\

    interface: 127.0.0.53@53\n\

    do-ip4: yes\n\
    do-ip6: no\n\

    do-udp: yes\n\
    do-tcp: yes\n\

    qname-minimisation: yes\n\

    tls-upstream: yes\n\
    tls-cert-bundle: \"/etc/ssl/certs/ca-certificates.crt\"\n\
    tls-use-sni: yes\n\

    hide-identity: yes\n\
    hide-version: yes\n\

    username: \"unbound\"\n\
    access-control: 127.0.0.0/8 allow\n\

forward-zone:\n\
    name: \".\"\n\

    forward-first: no\n\
    forward-tls-upstream: yes\n\

    forward-addr: $DNS01@853#$DOT_DOMAIN\n\
    forward-addr: $DNS02@853#$DOT_DOMAIN\n\

remote-control:\n\
    control-enable: no\n"

echo -e "$UNBOUND_CONFIG" > /etc/unbound/unbound.conf

systemctl enable unbound
systemctl start unbound

if [ "$(systemctl is-active unbound)" = "active" ]; then

    chattr -i /etc/resolv.conf
    rm -f /etc/resolv.conf
    touch /etc/resolv.conf

    echo "nameserver 127.0.0.53" > /etc/resolv.conf
    chattr +i /etc/resolv.conf

    iptables -D OUTPUT -o eth0 -p udp -d $DNS01,$DNS02 --dport 53 -j ACCEPT
    iptables -A OUTPUT -o eth0 -p tcp -d $DNS01,$DNS02 --dport 853 -j ACCEPT

    iptables-save > $IPT_PATH
    systemctl restart iptables

    if [ "$(systemctl is-failed iptables)" = "failed" ]; then
        echo "script failure while configuring unbound... exiting..."
        echo "error: failed to configure iptables"

        exit
    fi

    systemctl restart unbound
else
    echo "Script ERROR... Exiting..."
    echo "ERROR: failed to start unbound"

    exit
fi

# CONFIGURE SSHD
SSHD_CONPATH="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONPATH" ]; then
    if [ ! -z "$SSHD_PORT" ]; then
        sed -E -i 's/^#Port\s[0-9]+$/Port '"$SSHD_PORT"'/g' /etc/ssh/sshd_config
    else
        # default SSH listening port
        SSHD_PORT=22
    fi

    PASS_AUTH=$([ -z "$SSH_KEY" ] && echo "yes" || echo "no")

    if [ "$PASS_AUTH" = "yes" ]; then
        PUBKEY_AUTH="no"
    else

        if [ "$ALLOW_ROOT_LOGIN" = "yes" ]; then
            echo "$SSH_KEY" > /root/.ssh/authorized_keys
        fi

        if [ ! -z "$SUDO_USER" ]; then

            SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)

            if [ -z "$SUDO_USER_HOME" ]; then
                echo "ERROR! Exitting..."
                exit
            fi

            echo "$SSH_KEY" > "$SUDO_USER_HOME/.ssh/authorized_keys"
        fi

        PUBKEY_AUTH="yes"
    fi

    declare -A SETTINGS

    SETTINGS["PermitRootLogin"]="$ALLOW_ROOT_LOGIN"
    SETTINGS["PasswordAuthentication"]="$PASS_AUTH"
    SETTINGS["PubkeyAuthentication"]="$PUBKEY_AUTH"

    SETTINGS["PermitEmptyPasswords"]="no"
    SETTINGS["HostbasedAuthentication"]="no"
    SETTINGS["IgnoreUserKnownHosts"]="yes"
    SETTINGS["IgnoreRhosts"]="yes"

    SETTINGS["X11Forwarding"]="no"
    SETTINGS["UsePAM"]="no"

    INSERT_AFTER=$(grep -Pn "^#\sAuthentication:$" "$SSHD_CONPATH" | cut -d: -f1)

    for SETTING in "${!SETTINGS[@]}"; do

        LINE=$(grep -Pn "^#?$SETTING" "$SSHD_CONPATH" | cut -d: -f1)

        if [ -z "$LINE" ]; then
            sed -E -i "$INSERT_AFTER"'a '"$SETTING"' '"${SETTINGS["$SETTING"]}" $SSHD_CONPATH
        else
            sed -E -i 's/^#?'"$SETTING"'\s[a-z\-]+$/'"$SETTING"' '"${SETTINGS[$SETTING]}"'/g' $SSHD_CONPATH 
        fi

    done

    systemctl enable ssh
    systemctl restart ssh

    if [ "$(systemctl is-failed ssh)" = "failed" ]; then
        echo "Script ERROR... Exiting..."
        echo "ERROR: failed to start SSHD"

        exit
    fi

    # add necessary firewall rules
    iptables -A ACCEPTED_TCP_CONNECTIONS -p tcp --dport $SSHD_PORT -j ACCEPT

    iptables-save > $IPT_PATH
    systemctl restart iptables

    if [ "$(systemctl is-failed iptables)" = "failed" ]; then
        echo "[ERROR]: failed to start configure SSH"
        echo "[DETAIL]: failed to restart iptables"

        exit
    fi
fi

if [ "$SYSTEM_TYPE" = "VPN" ]; then

    if [ -z "$OPENVPN_PKI_ROOT" ]; then
        echo "Script ERROR... Exiting..."
        echo "ERROR: OPENVPN_PKI_ROOT not set"

        exit
    fi

    OPENVPN_PORT=[ -z "$OPENVPN_PORT" ] && echo "443" || echo "$OPENVPN_PORT"
    OPENVPN_PROTO=[ -z "$OPENVPN_PROTO" ] && echo "tcp" || echo "$OPENVPN_PROTO"

    if [[ -z "$OPENVPN_NET_ADDRESS" || -z "$OPENVPN_NET_SUBNET" ]]; then
        echo "Script ERROR... Exiting..."
        echo "ERROR: empty network address or subnet"

        exit
    fi

    adduser --system --no-create-home --shell /usr/sbin/nologin openvpn

    ## Make PKI FS Hierarchy
    umask 027
    mkdir -p "$OPENVPN_PKI_ROOT/{cacerts,certs}"

    umask 077
    mkdir "$OPENVPN_PKI_ROOT/{tls-auth,dhparam,private}"

    umask 027
    mkdir /etc/openvpn/server/log

    umask 077
    openvpn --genkey tls-auth "$OPENVPN_PKI_ROOT/tls-auth/ta.key"
    openssl dhparam -out "$OPENVPN_PKI_ROOT/dhparam/dh2048.pem" 2048

    umask 027
    mkdir -p "/etc/openvpn/server/jail/tmp"
    chown -R openvpn:openvpn "/etc/openvpn/server/jail"

    OPENVPN_CONFIG="\

        port $OPENVPN_PORT\n\
        proto $OPENVPN_PROTO\n\

        dev tun\n\
        topology subnet\n\

        chroot /etc/openvpn/server/jail\n\
        tmp-dir tmp\n\

        server $OPENVPN_NET_ADDRESS $OPENVPN_NET_SUBNET\n\

        ping 10\n\
        ping-restart 60\n\

        ifconfig-pool-persist /etc/openvpn/server/log/ipp.txt\n\

        ## Set PKI paths\n\
        ca "$OPENVPN_PKI_ROOT/cacerts/CA.crt"\n\
        cert "$OPENVPN_PKI_ROOT/certs/server.crt"\n\
        key "$OPENVPN_PKI_ROOT/private/server.key"\n\
        tls-auth "$OPENVPN_PKI_ROOT/tls-auth/ta.key" 1\n\
        dh "$OPENVPN_PKI_ROOT/dhparam/dh2048.pem"\n\

        ## Set Cipher And Auth Options\n\
        cipher AES-256-GCM\n\
        auth SHA512\n\

        user openvpn\n\
        group openvpn\n\
        persist-key\n\
        persist-tun\n\

        status /etc/openvpn/server/log/server-status.log\n\
        log /etc/openvpn/server/log/server.log\n\
        log-append /etc/openvpn/server/log/server.log\n\

        verb 6\n"

    echo "$OPENVPN_CONFIG" > /etc/openvpn/server/server0.conf
    systemctl enable openvpn-server@server0

    if [ "$OPENVPN_PROTO" = "tcp" ]; then
        iptables -A ACCEPTED_TCP_CONNECTIONS -i eth0 --dport $OPENVPN_PORT -j ACCEPT
    elif [ "$OPENVPN_PROTO" = "udp" ]; then
        iptables -A ACCEPTED_UDP_CONNECTIONS -i eth0 --dport $OPENVPN_PORT -j ACCEPT
    fi

    iptables-save > $IPT_PATH
    systemctl restart iptables

    if [ "$(systemctl is-failed iptables)" = "failed" ]; then
        echo "[ERROR]: failed to start configure SSH"
        echo "[DETAIL]: failed to restart iptables"

        exit
    fi
fi