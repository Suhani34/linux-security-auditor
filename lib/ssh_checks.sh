#!/usr/bin/env bash

check_ssh_security() {
echo
echo "[SSH SECURITY]"

SSHD_BIN="$(command -v sshd 2>/dev/null || true)"

if [[ -z "$SSHD_BIN" && -x /usr/sbin/sshd ]]
then
        SSHD_BIN="/usr/sbin/sshd"
fi

if [[ -n "$SSHD_BIN" ]]
then
        echo
        echo "SSH server                : Installed"
        if command -v systemctl >/dev/null 2>&1
        then
                if systemctl is-active --quiet ssh.service 2>/dev/null
                then
                        echo "SSH service               : Active"
                elif systemctl is-active --quiet sshd.service 2>/dev/null
                then
                        echo "SSH service               : Active"
                else
                        echo "SSH service               : Inactive"
                fi
        else
                echo "SSH service               : Unable to determine"
        fi

        if [[ "$EUID"  -eq 0 ]]
        then
                if "$SSHD_BIN" -t >/dev/null 2>&1
                then
                        pass "SSH configuration syntax is valid"
                else
                        critical "SSH configuration validation failed"
                fi

                SSHD_EFFECTIVE="$(
                        "$SSHD_BIN" -T 2>/dev/null
                )"

                if [[ -n "$SSHD_EFFECTIVE" ]]
                then
                        get_sshd_setting(){
                                local setting_name="$1"
                                printf '%s\n' "$SSHD_EFFECTIVE" |
                                awk -v key="$setting_name" '
                                        $1 == key {
                                                print $2
                                                exit
                                        }
                                '
                        }

                        SSH_PORT="$(get_sshd_setting 'port')"
                        SSH_ROOT_LOGIN="$(get_sshd_setting 'permitrootlogin')"
                        SSH_PASSWORD_AUTH="$(get_sshd_setting 'passwordauthentication')"

                        SSH_PUBKEY_AUTH="$(get_sshd_setting 'pubkeyauthentication')"
                        SSH_EMPTY_PASSWORDS="$(get_sshd_setting 'permitemptypasswords')"
                        SSH_MAX_AUTH_TRIES="$(get_sshd_setting 'maxauthtries')"
                        SSH_KBD_INTERACTIVE="$(get_sshd_setting 'kbdinteractiveauthentication')"

                        echo
                        echo "SSH port         : ${SSH_PORT:-unknown}"

                        case "$SSH_ROOT_LOGIN" in

                                no)
                                        pass "Direct root SSH login is disabled"
                                        ;;

                                prohibit-password|without-password)
                                        info "Root password authentication is prohibited, but key-based root access may still be permitted"
                                        ;;

                                forced-commands-only)
                                        info "Root SSH access is restricted to forced commands"

                                        ;;

                                yes)
                                        critical "Direct root SSH login is permitted"
                                        add_recommendation "Disable direct SSH root login and use a normal administrative account with sudo for privileged tasks."
                                        ;;

                                *)
                                        warning "Unable to determine SSH root-login policy"
                                        ;;

                        esac

                        case "$SSH_PASSWORD_AUTH" in

                                no)
                                        pass "SSH password authentication is disabled"
                                        ;;
                                yes)
                                        warning "SSH password authentication is enabled"
                                        add_recommendation "Consider using SSH key-based authentication and disabling password authentication after verifying key access works correctly."
                                        ;;

                                *)
                                        warning "Unable to determine SSH password-authentication policy"
                                        ;;

                        esac

                        case "$SSH_PUBKEY_AUTH" in

                                yes)
                                        pass "SSH public-key authentication is enabled"
                                        ;;

                                no)
                                        warning "SSH public-key authentication is disabled"
                                        ;;
                                *)
                                        warning "Unable to determine SSH public-key authentication policy"
                                        ;;

                        esac

                        case "$SSH_EMPTY_PASSWORDS" in

                                no)
                                        pass "SSH empty passwords are prohibited"
                                        ;;

                                yes)
                                        critical "SSH permits accounts with empty passwords"
                                        ;;

                                *)
                                        warning "Unable to determine SSH empty-password policy"
                                        ;;
                        esac

                        info "Maximum SSH authentication attempts per connection: ${SSH_MAX_AUTH_TRIES:-unknown}"
                        info "Keyboard-interactive authentication: ${SSH_KBD_INTERACTIVE:-unknown}"

                        SSH_ALLOW_USERS="$(
                                printf '%s\n' "$SSHD_EFFECTIVE" |
                                awk '
                                        $1 == "allowusers" {
                                                $1=""
                                                sub(/^[[:space:]]+/, "")
                                                print
                                                exit
                                        }
                                '
                        )"

                        SSH_ALLOW_GROUPS="$(
                                printf '%s\n' "$SSHD_EFFECTIVE" |
                                awk '
                                        $1 == "allowgroups" {
                                                $1=""
                                                sub(/^[[:space:]]+/, "")
                                                print
                                                exit
                                        }
                                '
                        )"

                        if [[ -n "$SSH_ALLOW_USERS" ]]
                        then
                                info "SSH AllowUsers restriction: $SSH_ALLOW_USERS"
                        else
                                info "No global SSH AllowUsers restriction detected"
                        fi

                        if [[ -n "$SSH_ALLOW_GROUPS" ]]
                        then
                                info "SSH AllowGroups restriction: $SSH_ALLOW_GROUPS"
                        else
                                info "No global SSH AllowGroups restriction detected"
                        fi

                else

                        warning "Unable to obtain effective SSH server configuration"

                fi

        else

                echo
                info "Full SSH configuration audit skipped because the auditor is not running as root"
                info "Run with sudo for the complete SSH audit"

        fi

else

    echo
    echo "SSH server       : Not installed"
    info "OpenSSH server was not detected"

fi

}
