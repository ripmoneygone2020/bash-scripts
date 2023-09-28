#!/bin/bash

# USAGE:
# -c [COMMAND], -c init-ca, -c new-cert
# -d [PKI_ROOT], -d /etc/pki/CA

# -n [NAME]
# -r [REQ_EXTS?] 
# -f [EXT_FILE?]
# -e [ENCRYPTED?]

while getopts c:d:n:r:f:e OPT; do

    case "$OPT" in

        c) COMMAND="$OPTARG" ;;
        d) PKI_ROOT="$OPTARG" ;;

        n) NAME="$OPTARG" ;;
        r) REQEXTS="$OPTARG" ;;
        f) EXTFILE="$OPTARG" ;;

        e) ENCRYPTED="yes" ;;

    esac

done

if [ $UID -ne 0 ]; then
    echo "[Error]: root priviledges are required."
    exit
fi

if [ -z "$PKI_ROOT" ]; then
    echo "[Error] Root PKI directory not provided... Exiting."
    exit
fi

if [ ! -f "$PKI_ROOT/openssl.cnf" ]; then
    echo "[Error] openssl.cnf not found in root pki directory... Exiting."
    exit
fi

if [ "$COMMAND" = "init-ca" ]; then

    CONFIG_DIR="$(grep -Pe '^dir' $PKI_ROOT/openssl.cnf | cut -d= -f 2 | xargs)"

    if [ "$CONFIG_DIR" != $PKI_ROOT ]; then

        echo "[Error] openssl.cnf directory assignment does not match the provided PKI_ROOT..."
        echo "[INFO] PKI_ROOT=$PKI_ROOT"
        echo "[INFO] CONFIG_DIR=$CONFIG_DIR"

        exit
    fi

    umask 027
    mkdir "$PKI_ROOT"/{cacerts,certs,newcerts,reqs,extfiles}

    echo "1234" > "$PKI_ROOT/serial"
    echo "1234" > "$PKI_ROOT/CRLnumber"
    touch "$PKI_ROOT/index.txt"

    umask 077
    mkdir "$PKI_ROOT/private"

    openssl genrsa -aes256 -out "$PKI_ROOT/private/CA.key" 4096

    umask 027
    openssl req -x509 -days 3650 -key "$PKI_ROOT/private/CA.key" -out "$PKI_ROOT/cacerts/CA.crt" -config "$PKI_ROOT/openssl.cnf"

elif [ "$COMMAND" = "new-cert" ]; then

    NAME=[ -z "$OPT" ] && echo "$(grep -Pe '^default_keyfile' openssl.cnf | cut -d= -f2)" || echo "$OPT"
            
    if [ -z "$NAME" ]; then
        echo '[Error] No certificate name provided or present in the config file... Exiting.'
        exit
    fi

    REQPARAMS="-new -newkey rsa -keyout $PKI_ROOT/private/$NAME.key -out $PKI_ROOT/reqs/$NAME.req"
    CAPARAMS="-in $PKI_ROOT/reqs/$NAME.req -out $PKI_ROOT/certs/$NAME.crt"

    if [ ! -z "$REQEXTS" ]; then
        if [ -z "$(grep -Pe '\[\s*'"$REQEXTS"'\s*\]' openssl.cnf)" ]; then
            echo '[Error] Provided section not present in the config file... Exiting.'
            exit
        fi

        REQPARAMS="$REQPARAMS -reqexts $REQEXTS"
    fi

    if [ -z "$ENCRYPTED" ]; then 
        REQPARAMS="$REQPARAMS -nodes"
    fi

    if [ ! -z "$EXTFILE" ]; then
        if [ ! -f "$PKI_ROOT/extfiles/$EXTFILE" ]; then
            echo "[Error] ext file doesn't exist... Exiting."
            exit
        fi

        CAPARAMS="$CAPARAMS -extfile $PKI_ROOT/extfiles/$EXTFILE"
    fi

    openssl req $REQPARAMS -config "$PKI_ROOT/openssl.cnf"
    openssl ca $CAPARAMS -config "$PKI_ROOT/openssl.cnf"

elif [ "$COMMAND" = "revoke" ]; then

    if [ -z "$NAME" ]; then
        echo '[Error] No certificate name provided... Exiting.'
        exit
    fi

    if [ ! -f "$PKI_ROOT/certs/$NAME.crt" ]; then
        echo '[Error] Certificate not found... Exiting.'
        exit
    fi

    openssl ca -revoke "$PKI_ROOT/certs/$NAME.crt" -config "$PKI_ROOT/openssl.cnf"
    openssl ca -gencrl -out "$PKI_ROOT/CA.crl" -config "$PKI_ROOT/openssl.cnf"
fi