#!/usr/bin/env bash

echo "======================================================================"
echo "                        LINUX SECURITY AUDITOR                        "
echo "======================================================================"

HOST="$(hostname)"
CURRENT_USER="$(whoami)"
INVOKING_USER="${SUDO_USER:-$CURRENT_USER}"
KERNEL="$(uname -r)"
ARCHITECTURE="$(uname -m)"
UPTIME="$(uptime -p)"
AUDIT_TIME="$(date '+%Y-%m-%d %H:%M:%S')"


source /etc/os-release
OS_NAME="$PRETTY_NAME"

echo
echo "[SYSTEM INFORMATION]"
echo "Host             : $HOST"
echo "OS               : $OS_NAME"
echo "Kernel           : $KERNEL"
echo "Architecture     : $ARCHITECTURE"
echo "Uptime           : $UPTIME"
echo "Audit Time       : $AUDIT_TIME"
echo "Run By           : $INVOKING_USER"
echo "Effective As     : $CURRENT_USER"
echo
echo "[USER & ACCOUNT SECURITY]"
UID_MIN="$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/ {print $2; exit}' /etc/login.defs)"
UID_MAX="$(awk '/^[[:space:]]*UID_MAX[[:space:]]+/ {print $2; exit}' /etc/login.defs)"
if [[ -z "$UID_MIN" ]]
then 
     UID_MIN=1000
fi

if [[ -z "$UID_MAX" ]]
then
    UID_MAX=60000
fi

HUMAN_USER_COUNT="$(
    awk -F: -v min="$UID_MIN" -v max="$UID_MAX" '
     $3 >= min && $3 <= max {
       count++
     }
     END {
        print count + 0
     }
   ' /etc/passwd
)"

echo
echo "Human user accounts : $HUMAN_USER_COUNT"

awk -F: -v min="$UID_MIN" -v max="$UID_MAX" '
    $3 >= min && $3 <= max {
        printf "  - %s (UID %s, shell %s)\n", $1, $3, $7
    }
' /etc/passwd


LOGIN_SHELL_COUNT=0
LOGIN_SHELL_USERS=""

while IFS=: read -r username password uid gid info home shell
do
    if grep -Fxq "$shell" /etc/shells
    then
        LOGIN_SHELL_COUNT=$((LOGIN_SHELL_COUNT + 1))
        LOGIN_SHELL_USERS+="$username ($shell)"$'\n'
    fi
done < /etc/passwd

echo
echo "Users with login shells : $LOGIN_SHELL_COUNT"
printf '%s' "$LOGIN_SHELL_USERS"

UID_ZERO_USERS="$(awk -F: '$3 == 0 {print $1}' /etc/passwd)"

UID_ZERO_COUNT="$(
    awk -F: '
        $3 == 0 {
            count++
        }
        END {
            print count + 0
        }
    ' /etc/passwd
)"

echo

if [[ "$UID_ZERO_COUNT" -eq 1 && "$UID_ZERO_USERS" == "root" ]]
then
    echo "[PASS] Only root has UID 0"
else
    echo "[CRITICAL] Unexpected UID 0 account detected"

    awk -F: '
        $3 == 0 {
            printf "  - %s (UID %s)\n", $1, $3
        }
    ' /etc/passwd
fi


DUPLICATE_UIDS="$(
    cut -d: -f3 /etc/passwd |
    sort -n |
    uniq -d
)"

if [[ -z "$DUPLICATE_UIDS" ]]
then
    echo "[PASS] No duplicate UIDs detected"
else
    echo "[WARNING] Duplicate UIDs detected"

    printf '%s\n' "$DUPLICATE_UIDS" |
    while IFS= read -r duplicate_uid
    do
        awk -F: -v target_uid="$duplicate_uid" '
            $3 == target_uid {
                printf "  - UID %s -> %s\n", $3, $1
            }
        ' /etc/passwd
    done
fi


MISSING_HOME_COUNT=0
MISSING_HOME_USERS=""

while IFS=: read -r username password uid gid info home shell
do
    if [[ "$uid" -ge "$UID_MIN" && "$uid" -le "$UID_MAX" ]]
    then
        if [[ ! -d "$home" ]]
        then
            MISSING_HOME_COUNT=$((MISSING_HOME_COUNT + 1))
            MISSING_HOME_USERS+="$username -> $home"$'\n'
        fi
    fi
done < /etc/passwd

if [[ "$MISSING_HOME_COUNT" -eq 0 ]]
then
    echo "[PASS] All human users have valid home directories"
else
    echo "[WARNING] $MISSING_HOME_COUNT human user(s) have missing home directories"
    printf '%s' "$MISSING_HOME_USERS"
fi

echo
echo "[SUDO & PRIVILEGE SECURITY]"

if command -v sudo >/dev/null 2>&1
then
	SUDO_GROUP_MEMBERS="$(
		getent group sudo |
		awk -F: '{print $4}'
	)"

	if [[ -z "$SUDO_GROUP_MEMBERS" ]]
	then
		SUDO_USER_COUNT=0

		echo
		echo "Sudo group members : 0"
		echo "[INFO] No explicit users are listed in the sudo group"
	else
		SUDO_USER_COUNT="$(
			printf '%s\n' "$SUDO_GROUP_MEMBERS" |
			tr ',' '\n' |
			sed '/^$/d' |
			wc -l
		)"

		echo
		echo "Sudo group members : $SUDO_USER_COUNT"

		printf '%s\n' "$SUDO_GROUP_MEMBERS" |
		tr ',' '\n' |
		sed '/^$/d' |
		while IFS= read -r sudo_user
		do
			echo " - $sudo_user"
		done
fi

if id -nG "$INVOKING_USER" | grep -qw sudo
then
	echo "[INFO] Current user '$INVOKING_USER' is a member of the sudo group"
else
	echo "[INFO] Current user '$INVOKING_USER' is not a member of the sudo group"
fi

if [[ "$EUID" -eq 0 ]]
then
	if visudo -c >/dev/null 2>&1
	then
		echo "[PASS] sudoers configuration syntax is valid"
	else
		echo "[CRITICAL] sudoers configuration contains syntax errors"
	fi

	NOPASSWD_RULES="$(
		grep  -RhsE \
		'^[[:space:]]*[^#].*NOPASSWD:' \
		/etc/sudoers /etc/sudoers.d \
		2>/dev/null
	)"
	
	if [[ -z "$NOPASSWD_RULES" ]]
	then
		echo "[PASS] No passwordless sudo rules detected"
	else
		echo "[WARNING] Passwordless sudo rule(s) detected"

		printf '%s\n' "$NOPASSWD_RULES" |
		while IFS= read -r rule
		do
			echo "  - $rule"
		done
	
		if printf '$s\n' "$NOPASSWD_RULES" |
			grep -Eq 'NOPASSWD:[[:spcae:]]*ALL([[:apce:]]*($|#)|[[:spcae:]]*,)'
		then
			echo "[CRITICAL] Unrestricted NOPASSWD: All rule detected"
		fi
	fi
else
	echo "[INFO] Full sudoers inspection skipped because the auditor is not running as root"
	echo "[INFO] Run with sudo for the complete privilege audit"
fi
else

	echo 
	echo "[INFO] sudo is not installed on this system"
fi


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
					NON_LOOPBACK_TCP_COUNT=$((NON_LOOPBACK_TCP_COUNT + 1))
					;;

				*)
					EXPOSURE="NETWORK INTERFACE"
					NON_LOOPBACK_TCP_COUNT=$((NON_LOOPBACK_TCP_COUNT + 1))
					;;

			esac
			printf "%-8s %-26s %-8s %s\n" \
				"TCP" "$ADDRESS" "$PORT" "$EXPOSURE"
		done <<< "$TCP_LISTENERS"

		echo

		if [[ "$NON_LOOPBACK_TCP_COUNT" -eq 0 ]]
		then
			echo "[PASS] All TCP listeners are restricted to loopback addresses"
		else
			echo "[INFO] $NON_LOOPBACK_TCP_COUNT TCP listener(s) are bound to non-loopback interfaces"
		fi

	else
        	echo
        	echo "[INFO] No listening TCP sockets detected"
	fi

	if printf '%s\n' "$TCP_LISTENERS" |
       		awk '{print $4}' |
       		grep -Eq '(^|:)22$'
    	then
        	echo "[INFO] TCP port 22 is listening; commonly associated with SSH"
	else
        	echo "[INFO] TCP port 22 is not listening"
    	fi

	LEGACY_PORT_FOUND=0

    	if printf '%s\n' "$TCP_LISTENERS" |
       		awk '{print $4}' |
       		grep -Eq '(^|:)21$'
    	then
        	echo "[WARNING] TCP port 21 is listening; commonly associated with FTP"
        	LEGACY_PORT_FOUND=1
    	fi

	 if printf '%s\n' "$TCP_LISTENERS" |
       		awk '{print $4}' |
       		grep -Eq '(^|:)23$'
    	then
        	echo "[WARNING] TCP port 23 is listening; commonly associated with Telnet"
        	LEGACY_PORT_FOUND=1
    	fi

	if [[ "$LEGACY_PORT_FOUND" -eq 0 ]]
    	then
        	echo "[PASS] No common insecure legacy TCP ports detected"
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
                        			echo "[WARNING] Data-service port $PORT is bound to all interfaces"
                        			DATABASE_WARNING_COUNT=$((DATABASE_WARNING_COUNT + 1))
                        			;;
                		esac
                		;;

        	esac

    	done <<< "$TCP_LISTENERS"

	if [[ "$DATABASE_WARNING_COUNT" -eq 0 ]]
    	then
        	echo "[PASS] No monitored database/data-service ports are bound to all interfaces"
    	fi

else

    echo
    echo "[WARNING] The 'ss' command is not available"
    echo "[INFO] Network socket checks could not be performed"

fi


echo
echo "[SERVICES & PROCESSES]"

if command -v systemctl >/dev/null 2>&1
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
        	echo "[PASS] No failed systemd services detected"
    	else
        	echo "[WARNING] $FAILED_SERVICE_COUNT failed systemd service(s) detected"

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
        	echo "[INFO] SSH service is active"

        	if systemctl is-enabled --quiet ssh.service 2>/dev/null
        	then
            		echo "[INFO] SSH service is enabled at boot"
        	else
            		echo "[INFO] SSH service is not enabled at boot"
        	fi
    	else
        	echo "[INFO] SSH service is not active"
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
                    			echo "[WARNING] Telnet service is active"
                    			;;

                		rsh.service|rlogin.service|rexec.service)
                    			echo "[WARNING] Legacy remote-access service '$service_name' is active"
                    			;;

                		vsftpd.service|proftpd.service)
                   			echo "[WARNING] FTP server service '$service_name' is active; review whether plaintext FTP is required"
                    			;;

            		esac

            		LEGACY_SERVICE_FOUND=1
        	fi

    	done

	if [[ "$LEGACY_SERVICE_FOUND" -eq 0 ]]
    	then
        	echo "[PASS] No monitored insecure legacy services detected"
    	fi

else

    echo
    echo "[WARNING] systemctl is not available"
    echo "[INFO] systemd service checks could not be performed"

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

    echo "[INFO] Root-owned processes require context; their presence alone is not a security issue"

else

    echo
    echo "[WARNING] The ps command is not available"

fi


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
			echo "[PASS] UFW firewall is active"

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
                    			echo "[PASS] Default incoming traffic is blocked"
                    			;;

                		allow)
                    			echo "[WARNING] Default incoming traffic is allowed"
                    			;;

                		*)
                    			echo "[WARNING] Unable to determine default incoming policy"
                    			;;

            		esac

			if printf '%s\n' "$UFW_VERBOSE" |
               		  grep -Eq '^Logging: on'
            		then
                		echo "[INFO] UFW logging is enabled"
            		else
                		echo "[INFO] UFW logging is disabled"
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
                		echo "[INFO] SSH port 22 is explicitly allowed by UFW"
            		else
                		echo "[INFO] SSH port 22 is not explicitly allowed by UFW"
            		fi

			if printf '%s\n' "$UFW_RULES" |
               		  grep -Eq '23(/tcp)?[[:space:]]+.*ALLOW'
            		then
                		echo "[WARNING] Telnet-associated TCP port 23 is explicitly allowed"
            		else
                		echo "[PASS] Telnet-associated port 23 is not explicitly allowed"
            		fi

			DATABASE_FIREWALL_WARNING=0

            		for database_port in 3306 5432 6379 27017
            		do

                		if printf '%s\n' "$UFW_RULES" |
                   		  grep -E "$database_port(/tcp)?[[:space:]]+.*ALLOW" |
                   		  grep -Eq 'Anywhere'
                		then

                    			echo "[WARNING] Data-service port $database_port is allowed from Anywhere"
                    			DATABASE_FIREWALL_WARNING=$((DATABASE_FIREWALL_WARNING + 1))

                		fi

            		done

            		if [[ "$DATABASE_FIREWALL_WARNING" -eq 0 ]]
            		then
                		echo "[PASS] No monitored database/data-service ports are broadly allowed by UFW"
            		fi

		else

            		echo "Status        : INACTIVE"
            		echo
            		echo "[CRITICAL] UFW firewall is disabled"

        	fi

	else

        	echo "Status        : Requires elevated privileges"
        	echo
        	echo "[INFO] Full firewall inspection skipped because the auditor is not running as root"
        	echo "[INFO] Run with sudo for the complete firewall audit"

    	fi

else

    echo
    echo "[WARNING] UFW is not installed"
    echo "[INFO] UFW firewall checks could not be performed"

fi


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
	echo "SSH server           	: Installed"
	if command -v systemctl >/dev/null 2>&1
	then
		if systemctl is-active --quiet ssh.service 2>/dev/null
		then
			echo "SSH service              	: Active"
		elif systemctl is-active --quiet sshd.service 2>/dev/null
		then
			echo "SSH service              	: Active"
		else
			echo "SSH service		: Inactive"
		fi
	else
		echo "SSH service		: Unable to determine"
	fi

	if [[ "$EUID"  -eq 0 ]]
	then
		if "$SSHD_BIN" -t >/dev/null 2>&1
		then
			echo "[PASS] SSH configuration syntax is valid"
		else
			echo "[CRITICAL] SSH configuration validation failed"
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

			SSH_PORT="$(get_sshd_setting "port")"
            		SSH_ROOT_LOGIN="$(get_sshd_setting "permitrootlogin")"
            		SSH_PASSWORD_AUTH="$(get_sshd_setting "passwordauthentication")"
            		SSH_PUBKEY_AUTH="$(get_sshd_setting "pubkeyauthentication")"
            		SSH_EMPTY_PASSWORDS="$(get_sshd_setting "permitemptypasswords")"
            		SSH_MAX_AUTH_TRIES="$(get_sshd_setting "maxauthtries")"
            		SSH_KBD_INTERACTIVE="$(get_sshd_setting "kbdinteractiveauthentication")"

            		echo
            		echo "SSH port         : ${SSH_PORT:-unknown}"

			case "$SSH_ROOT_LOGIN" in

                		no)
                    			echo "[PASS] Direct root SSH login is disabled"
                    			;;

                		prohibit-password|without-password)
                    			echo "[INFO] Root password authentication is prohibited, but key-based root access may still be permitted"
                    			;;

                		forced-commands-only)
                    			echo "[INFO] Root SSH access is restricted to forced commands"
                    			;;

                		yes)
                    			echo "[CRITICAL] Direct root SSH login is permitted"
                    			;;

                		*)
                    			echo "[WARNING] Unable to determine SSH root-login policy"
                    			;;

            		esac

			case "$SSH_PASSWORD_AUTH" in

                		no)
                    			echo "[PASS] SSH password authentication is disabled"
                    			;;

                		yes)
                    			echo "[WARNING] SSH password authentication is enabled"
                    			;;

                		*)
                    			echo "[WARNING] Unable to determine SSH password-authentication policy"
                    			;;

            		esac

			case "$SSH_PUBKEY_AUTH" in

                		yes)
                    			echo "[PASS] SSH public-key authentication is enabled"
                    			;;

                		no)
                    			echo "[WARNING] SSH public-key authentication is disabled"
                    			;;

                		*)
                    			echo "[WARNING] Unable to determine SSH public-key authentication policy"
                    			;;

            		esac

			case "$SSH_EMPTY_PASSWORDS" in

                		no)
                    			echo "[PASS] SSH empty passwords are prohibited"
                    			;;

                		yes)
                    			echo "[CRITICAL] SSH permits accounts with empty passwords"
                    			;;

                		*)
                    			echo "[WARNING] Unable to determine SSH empty-password policy"
                    			;;

            		esac

            		echo "[INFO] Maximum SSH authentication attempts per connection: ${SSH_MAX_AUTH_TRIES:-unknown}"
            		echo "[INFO] Keyboard-interactive authentication: ${SSH_KBD_INTERACTIVE:-unknown}"

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
                		echo "[INFO] SSH AllowUsers restriction: $SSH_ALLOW_USERS"
            		else
                		echo "[INFO] No global SSH AllowUsers restriction detected"
            		fi

            		if [[ -n "$SSH_ALLOW_GROUPS" ]]
            		then
                		echo "[INFO] SSH AllowGroups restriction: $SSH_ALLOW_GROUPS"
            		else
                		echo "[INFO] No global SSH AllowGroups restriction detected"
            		fi

		else

            		echo "[WARNING] Unable to obtain effective SSH server configuration"

        	fi

	else

        	echo
        	echo "[INFO] Full SSH configuration audit skipped because the auditor is not running as root"
        	echo "[INFO] Run with sudo for the complete SSH audit"

    	fi

else

    echo
    echo "SSH server       : Not installed"
    echo "[INFO] OpenSSH server was not detected"

fi
