#!/usr/bin/env bash

check_network_security() {
echo
echo "[NETWORK & LISTENING PORTS]"

if command -v ss >/dev/null 2>&1
then
        HOST_IPS="$(
                hostname -I 2>/dev/null |
                sed 's/[[:space:]]*$//'
        )"
        if [[ -n "$HOST_IPS" ]]
        then
                echo
                echo "Host IP addresses : $HOST_IPS"
        else
                echo
                echo "Host IP addresses : Unable to determine"
        fi

        TCP_LISTENERS="$(ss -H -lnt 2>/dev/null)"
        UDP_SOCKETS="$(ss -H -lnu 2>/dev/null)"
       if [[ -z "$TCP_LISTENERS" ]]
        then
                TCP_LISTEN_COUNT=0
        else
                TCP_LISTEN_COUNT="$(
                        printf '%s\n' "$TCP_LISTENERS" |
                        sed '/^[[:space:]]*$/d' |
                        wc -l
                )"
        fi

        if [[ -z "$UDP_SOCKETS" ]]
        then
                UDP_SOCKET_COUNT=0
        else
                UDP_SOCKET_COUNT="$(
                        printf '%s\n' "$UDP_SOCKETS" |
                        sed '/^[[:space:]]*$/d' |
                        wc -l
                )"
        fi

        echo
        echo "Listening TCP sockets : $TCP_LISTEN_COUNT"
        echo "Bound UDP sockets     : $UDP_SOCKET_COUNT"

        if [[ "$TCP_LISTEN_COUNT" -gt 0 ]]
        then
                echo
                printf "%-8s %-26s %-8s %s\n" \
                       "Protocol" "Local Address" "Port" "Exposure"
                printf "%-8s %-26s %-8s %s\n" \
                       "--------" "-------------" "----" "--------"
                NON_LOOPBACK_TCP_COUNT=0

                while read -r state recv_q send_q local_endpoint peer_endpoint
                do
                        [[ -z "$local_endpoint" ]] && continue

                        PORT="${local_endpoint##*:}"
                        ADDRESS="${local_endpoint%:*}"
                        case "$ADDRESS" in

                                127.*|"[::1]"|"::1")
                                        EXPOSURE="LOCAL ONLY"
                                        ;;

                                "0.0.0.0"|"*"|"[::]"|"::")
                                        EXPOSURE="ALL INTERFACES"
                                        NON_LOOPBACK_TCP_COUNT=$((NON_LOOPBACK_TCP_COUNT+1))
                                        ;;

                                *)
                                        EXPOSURE="NETWORK INTERFACE"
                                        NON_LOOPBACK_TCP_COUNT=$((NON_LOOPBACK_TCP_COUNT+1))
                                        ;;

                        esac
                        printf "%-8s %-26s %-8s %s\n" \
                                "TCP" "$ADDRESS" "$PORT" "$EXPOSURE"
                done <<< "$TCP_LISTENERS"

                echo

                if [[ "$NON_LOOPBACK_TCP_COUNT" -eq 0 ]]
                then
                        pass "All TCP listeners are restricted to loopback addresses"
                else
                        info "$NON_LOOPBACK_TCP_COUNT TCP listener(s) are bound beyond loopback"
                fi

        else
                echo
                info "No listening TCP sockets detected"
        fi

        if printf '%s\n' "$TCP_LISTENERS" |
                awk '{print $4}' |
                grep -Eq '(^|:)22$'
        then
                info "TCP port 22 is listening; commonly associated with SSH"
        else
                info "TCP port 22 is not listening"
        fi

        LEGACY_PORT_FOUND=0

        if printf '%s\n' "$TCP_LISTENERS" |
                awk '{print $4}' |
                grep -Eq '(^|:)21$'
        then
                warning "TCP port 21 is listening; commonly associated with FTP"
                LEGACY_PORT_FOUND=1
        fi

         if printf '%s\n' "$TCP_LISTENERS" |
                awk '{print $4}' |
                grep -Eq '(^|:)23$'
        then
                warning "TCP port 23 is listening; commonly associated with Telnet"
                LEGACY_PORT_FOUND=1
        fi

        if [[ "$LEGACY_PORT_FOUND" -eq 0 ]]
        then
                pass "No common insecure legacy TCP ports detected"
        fi
        DATABASE_WARNING_COUNT=0

        while read -r state recv_q send_q local_endpoint peer_endpoint
        do
                [[ -z "$local_endpoint" ]] && continue

                PORT="${local_endpoint##*:}"
                ADDRESS="${local_endpoint%:*}"

                case "$PORT" in

                        3306|5432|6379|27017)
                                case "$ADDRESS" in

                                        "0.0.0.0"|"*"|"[::]"|"::")
                                                warning "Data-service port $PORT is listening on all interfaces"
                                                DATABASE_WARNING_COUNT=$((DATABASE_WARNING_COUNT + 1))
                                                ;;
                                esac
                                ;;

                esac

        done <<< "$TCP_LISTENERS"

        if [[ "$DATABASE_WARNING_COUNT" -eq 0 ]]
        then
                pass "No monitored database/data-service ports are bound to all interfaces"
        fi

else

    echo
    warning "The 'ss' command is not available"
    info "Network socket checks could not be performed"

fi

}


check_firewall_security() {
echo
echo "[FIREWALL SECURITY]"

if command -v ufw >/dev/null 2>&1
then
        echo
        echo "Firewall tool : UFW"

        if [[ "$EUID" -eq 0 ]]
        then
                UFW_VERBOSE="$(
                        ufw status verbose 2>/dev/null
                )"
                UFW_NUMBERED="$(
                        ufw status numbered 2>/dev/null
                )"

                if printf '%s\n' "$UFW_VERBOSE" | grep -q '^Status: active'
                then
                        echo "Status        : ACTIVE"
                       echo 
                        pass "UFW firewall is active"

                        DEFAULT_LINE="$(
                                printf '%s\n' "$UFW_VERBOSE" |
                                grep '^Default:' |
                                head -n 1
                        )"

                        if printf '%s\n' "$DEFAULT_LINE" |
                          grep -q 'deny (incoming)'
                        then
                                INCOMING_POLICY="deny"
                        elif printf '%s\n' "DEFAULT_LINE" |
                          grep -q 'reject (incoming)'
                        then
                                INCOMING_POLICY="reject"
                        elif printf '%s\n' "DEFAULT_LINE" |
                          grep -q 'allow (incoming)'
                        then
                                INCOMING_POLICY="allow"
                        else
                                INCOMING_POLICY="unknown"
                        fi

                        if printf '%s\n' "$DEFAULT_LINE" |
                          grep -q 'allow (outgoing)'
                        then
                                OUTGOING_POLICY="allow"
                        elif printf '%s\n' "$DEFAULT_LINE" |
                          grep -q 'deny (outgoing)'
                        then
                                OUTGOING_POLICY="deny"
                        elif printf '%s\n' "$DEFAULT_LINE" |
                          grep -q 'reject (outgoing)'
                        then
                                OUTGOING_POLICY="reject"
                        else
                                OUTGOING_POLICY="unknown"
                        fi
                       echo
                        echo "Default incoming policy : $INCOMING_POLICY"
                        echo "Default outgoing policy : $OUTGOING_POLICY"

                        case "$INCOMING_POLICY" in

                                deny|reject)
                                        warning "Default incoming traffic is blocked by default"
                                        ;;

                                allow)
                                        warning  "Default incoming traffic is allowed by default"
                                        ;;

                                *)
                                        warning "Unable to determine default incoming firewall policy to deny or reject unless there is a specific requirement"
                                        ;;

                        esac
                        if printf '%s\n' "$UFW_VERBOSE" |
                          grep -Eq '^Logging: on'
                        then
                                info "UFW logging is enabled"
                        else
                                info "UFW logging is disabled"
                        fi

                        echo
                        echo "Configured rules:"

                        UFW_RULES="$(
                                printf '%s\n' "$UFW_NUMBERED" |
                                sed -n '/^\[[[:space:]]*[0-9]/p'
                        )"

                        if [[ -z "$UFW_RULES" ]]
                        then
                                echo "  No explicit UFW rules configured"
                        else
                                printf '%s\n' "$UFW_RULES" |
                                while IFS= read -r rule
                                do
                                        echo "  $rule"
                                done
                        fi
                        echo

                        if printf '%s\n' "$UFW_RULES" |
                          grep -Eq '22(/tcp)?[[:space:]]+.*ALLOW'
                        then
                                info "SSH port 22 is explicitly allowed by UFW"
                        else
                                info "SSH port 22 is not explicitly allowed by UFW"
                        fi

                        if printf '%s\n' "$UFW_RULES" |
                          grep -Eq '23(/tcp)?[[:space:]]+.*ALLOW'
                        then
                                warning "Telnet-associated TCP port 23 is explicitily allowed"
                        else
                                pass "Telnet-associated port 23 is not explicitly allowed"
                        fi

                        DATABASE_FIREWALL_WARNING=0

                        for database_port in 3306 5432 6379 27017
                        do
                                if printf '%s\n' "$UFW_RULES" |
                                  grep -E "$database_port(/tcp)?[[:space:]]+.*ALLOW" |
                                  grep -Eq 'Anywhere'
                                then

                                        warning "Data-service port $database_port is allowed from anywhere"
                                        DATABASE_FIREWALL_WARNING=$((DATABASE_FIREWALL_WARNING + 1))

                                fi

                        done
                        if [[ "$DATABASE_FIREWALL_WARNING" -eq 0 ]]
                        then
                                pass "No monitored database/data-service ports are broadly allowed by UFW"
                        fi

                else

                        echo "Status        : INACTIVE"
                        echo
                        critical "UFW firewall is disabled"

                fi

        else

                echo "Status        : Requires elevated privileges"
                echo
                info "Full firewall inspection skipped because the auditor is not running as root"
                info "Run with sudo for the complete firewall audit"
       fi

else

    echo
    warning "UFW is not installed"
    add_recommendation "Enable and verify the host firewall, and allow only the network services that are actually required."
    info "UFW firewall checks could not be performed"

fi


}
