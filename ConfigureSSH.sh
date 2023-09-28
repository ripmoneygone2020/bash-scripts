#!/bin/bash

PUBKEY=""
PORT=22
ROOT_LOGIN_ENABLED="yes"

SSHD_CONPATH="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONPATH" ]; then
    if [ ! -z "$PORT" ]; then
        sed -E -i 's/^#Port\s[0-9]+$/Port '"$PORT"'/g' /etc/ssh/sshd_config
    else
        # default SSH listening port
        PORT=22
    fi

    PASS_AUTH=$([ -z "$PUBKEY" ] && echo "yes" || echo "no")

    if [ "$PASS_AUTH" = "yes" ]; then
        PUBKEY_AUTH="no"
    else

        if [ "$ALLOW_ROOT_LOGIN" = "yes" ]; then
            echo "$PUBKEY" > /root/.ssh/authorized_keys
        fi

        if [ ! -z "$SUDO_USER" ]; then

            SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)

            if [ -z "$SUDO_USER_HOME" ]; then
                echo "ERROR! Exitting..."
                exit
            fi

            echo "$PUBKEY" > "$SUDO_USER_HOME/.ssh/authorized_keys"
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
    iptables -A ACCEPTED_TCP_CONNECTIONS -p tcp --dport $PORT -j ACCEPT

    iptables-save > $IPT_PATH
    systemctl restart iptables

    if [ "$(systemctl is-failed iptables)" = "failed" ]; then
        echo "[ERROR]: failed to start configure SSH"
        echo "[DETAIL]: failed to restart iptables"

        exit
    fi
fi