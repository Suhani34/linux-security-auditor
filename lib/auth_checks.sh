#!/usr/bin/env bash

check_authentication_security() {
echo
echo "[AUTHENTICATION SECURITY]"

AUTH_ANALYSIS_WINDOW="24 hours ago"

echo
echo "Analysis window        : Last 24 hours"

if command -v journalctl >/dev/null 2>&1
then

    if [[ "$EUID" -eq 0 ]]
    then

        SSH_LOG_UNIT=""

        if systemctl list-unit-files ssh.service \
            --no-legend \
            --no-pager \
            2>/dev/null | grep -q '^ssh\.service'
        then
            SSH_LOG_UNIT="ssh.service"

        elif systemctl list-unit-files sshd.service \
            --no-legend \
            --no-pager \
            2>/dev/null | grep -q '^sshd\.service'
        then
            SSH_LOG_UNIT="sshd.service"
        fi

        if [[ -n "$SSH_LOG_UNIT" ]]
        then

            SSH_AUTH_LOGS="$(
                journalctl \
                    -u "$SSH_LOG_UNIT" \
                    --since "$AUTH_ANALYSIS_WINDOW" \
                    --no-pager \
                    -o cat \
                    2>/dev/null
            )"

            FAILED_SSH_COUNT="$(
                printf '%s\n' "$SSH_AUTH_LOGS" |
                grep -c 'Failed password' || true
            )"

            INVALID_USER_COUNT="$(
                printf '%s\n' "$SSH_AUTH_LOGS" |
                grep -c 'Invalid user' || true
            )"

            SUCCESSFUL_SSH_COUNT="$(
                printf '%s\n' "$SSH_AUTH_LOGS" |
                grep -Ec 'Accepted (password|publickey|keyboard-interactive)' || true
            )"

            FAILED_SOURCE_IPS="$(
                printf '%s\n' "$SSH_AUTH_LOGS" |
                grep 'Failed password' |
                awk '
                    {
                        for (i=1; i<=NF; i++) {
                            if ($i == "from" && (i+1) <= NF) {
                                print $(i+1)
                                break
                            }
                        }
                    }
                '
            )"

            if [[ -z "$FAILED_SOURCE_IPS" ]]
            then
                UNIQUE_FAILED_IP_COUNT=0
            else
                UNIQUE_FAILED_IP_COUNT="$(
                    printf '%s\n' "$FAILED_SOURCE_IPS" |
                    sed '/^[[:space:]]*$/d' |
                    sort -u |
                    wc -l
                )"
            fi

            echo "Failed SSH attempts    : $FAILED_SSH_COUNT"
            echo "Invalid-user events    : $INVALID_USER_COUNT"
            echo "Unique failure sources : $UNIQUE_FAILED_IP_COUNT"
            echo "Successful SSH logins  : $SUCCESSFUL_SSH_COUNT"

            echo

            if [[ "$FAILED_SSH_COUNT" -eq 0 ]]
            then
                 "No failed SSH password-authentication attempts detected"

            elif [[ "$FAILED_SSH_COUNT" -le 5 ]]
            then
                info "A small number of failed SSH authentication attempts were detected"
            elif [[ "$FAILED_SSH_COUNT" -le 20 ]]
            then
                warning "Repeated SSH authentication failures detected"

            else
                warning "High volume of SSH authentication failures detected"
            fi

            if [[ "$INVALID_USER_COUNT" -gt 0 ]]
            then
                warning "SSH login attempts against invalid usernames were detected"
            else
                pass "No SSH invalid-user events detected"
            fi

            if [[ "$FAILED_SSH_COUNT" -gt 0 && -n "$FAILED_SOURCE_IPS" ]]
            then

                echo
                echo "Top failed-login sources:"
                printf '%s\n' "$FAILED_SOURCE_IPS" |
                sed '/^[[:space:]]*$/d' |
                sort |
                uniq -c |
                sort -nr |
                head -n 5 |
                while read -r count source_ip
                do
                    printf "  %-22s %s attempt(s)\n" \
                        "$source_ip" "$count"
                done

            fi

            if [[ "$SUCCESSFUL_SSH_COUNT" -gt 0 ]]
            then
                info "Successful SSH authentication events were recorded during the analysis window"
            fi

        else
            info "No SSH systemd service unit was detected"
            info "SSH authentication log analysis was skipped"

        fi

    else

        info "Authentication log analysis skipped because the auditor is not running as root"
        info "Run with sudo for the complete authentication audit"

    fi

else

    warning "journalctl is not available"
    info "Authentication log analysis could not be performed"

fi

}
