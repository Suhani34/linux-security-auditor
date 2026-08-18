#!/usr/bin/env bash

check_service_security() {
echo
echo "[SERVICES & PROCESSES]"

if command -v ps >/dev/null 2>&1
then

        RUNNING_SERVICES="$(
                systemctl list-units \
                --type=service \
                --state=running \
                --no-legend \
                --no-pager \
                2>/dev/null
        )"

        if [[ -z "$RUNNING_SERVICES" ]]
        then
                RUNNING_SERVICE_COUNT=0
        else
                RUNNING_SERVICE_COUNT="$(
                        printf '%s\n' "$RUNNING_SERVICES" |
                        sed '/^[[:space:]]*$/d' |
                        wc -l
                )"
        fi

        ENABLED_SERVICES="$(
                systemctl list-unit-files \
                --type=service \
                --state=enabled \
                --no-legend \
                --no-pager \
                2>/dev/null
        )"

        if [[ -z "$ENABLED_SERVICES" ]]
        then
                ENABLED_SERVICE_COUNT=0
        else
                ENABLED_SERVICE_COUNT="$(
                        printf '%s\n' "$ENABLED_SERVICES" |
                        sed '/^[[:space:]]*$/d' |
                        wc -l
                )"
        fi


        FAILED_SERVICES="$(
                systemctl list-units \
                --type=service \
                --state=failed \
                --no-legend \
                --no-pager \
                2>/dev/null
        )"


        if [[ -z "$FAILED_SERVICES" ]]
        then
                FAILED_SERVICE_COUNT=0
        else
                FAILED_SERVICE_COUNT="$(
                        printf '%s\n' "$FAILED_SERVICES" |
                        sed '/^[[:space:]]*$/d' |
                        wc -l
                )"
        fi

        echo
        echo "Running systemd services : $RUNNING_SERVICE_COUNT"
        echo "Enabled service units    : $ENABLED_SERVICE_COUNT"
        echo "Failed services          : $FAILED_SERVICE_COUNT"

        if [[ "$FAILED_SERVICE_COUNT" -eq 0 ]]
        then
                pass "No failed systemd services detected"
        else
                warning "$FAILED_SERVICE_COUNT failed systemd service(s) detected"

                printf '%s\n' "$FAILED_SERVICES" |
                awk '{print "  - " $1}'
        fi

        if [[ "$RUNNING_SERVICE_COUNT" -gt 0 ]]
        then
                echo
                echo "Running services:"

                printf '%s\n' "$RUNNING_SERVICES" |
                awk '{print "  - " $1}'
        fi

        echo

        if systemctl is-active --quiet ssh.service 2>/dev/null
        then
                info "SSH service is active"

                if systemctl is-enabled --quiet ssh.service 2>/dev/null
                then
                       info "SSH service is enabled at boot"
                else
                        info "SSH service is not enabled at boot"
                fi
        else
                info "SSH service is not active"
        fi

        LEGACY_SERVICE_FOUND=0

        for service_name in \
                telnet.service \
                rsh.service \
                rlogin.service \
                rexec.service \
                vsftpd.service \
                proftpd.service
        do

                if systemctl is-active --quiet "$service_name" 2>/dev/null
                then

                        case "$service_name" in

                                telnet.service)
                                        warning "Telnet service is active"
                                        ;;

                                rsh.service|rlogin.service|rexec.service)
                                        warning "Legacy remote-access service '$service_name' is active"
                                        ;;

                                vsftpd.service|proftpd.service)
                                        warning "FTP server service '$service_name' is active: review whether plaintext FTP is required"
                                        ;;

                        esac

                        LEGACY_SERVICE_FOUND=1
                fi
        done

        if [[ "$LEGACY_SERVICE_FOUND" -eq 0 ]]
        then
                pass "No monitored insecure legacy services detected"
        fi

else

    echo
    warning "systemctl is not available"
    info "systemd service checks could not be performed"

fi

if command -v ps >/dev/null 2>&1
then

    TOTAL_PROCESS_COUNT="$(
        ps -e --no-headers |
        wc -l
    )"

    ROOT_PROCESS_COUNT="$(
        ps -eo user= |
        awk '$1 == "root" {count++} END {print count + 0}'
    )"

    echo
    echo "Running processes      : $TOTAL_PROCESS_COUNT"
    echo "Root-owned processes   : $ROOT_PROCESS_COUNT"

    info "Root-owned processes require context; their presence alone is not a security issue"

else

    echo
    warning "The ps command is not available"

fi


}
