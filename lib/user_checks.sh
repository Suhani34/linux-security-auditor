#!/usr/bin/env bash

check_user_accounts() {
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
    pass "Only root has UID 0"
else
    critical "Unexpected UID 0 account detected"

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
    pass "No duplicate UIDs detected"
else
    warning "Duplicate UIDs detected"

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
    pass "All human users have valid home directories"
else
    warning "$MISSING_HOME_COUNT human user(s) have missing home directories"
    printf '%s' "$MISSING_HOME_USERS"
fi

}

check_sudo_security() {
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
                info  "No explicit users are listed in the sudo group"
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
        info "Current user '$INVOKING_USER' is a member of the sudo group"
else
        info "Current user '$INVOKING_USER' is not a member of the sudo group"
fi

if [[ "$EUID" -eq 0 ]]
then
        if visudo -c >/dev/null 2>&1
        then
                pass "sudoers configuration syntax is valid"
        else
                critical "sudoers configuration contains syntax errors"
        fi

        NOPASSWD_RULES="$(
                grep  -RhsE \
                '^[[:space:]]*[^#].*NOPASSWD:' \
                /etc/sudoers /etc/sudoers.d \
                2>/dev/null
        )"
       if [[ -z "$NOPASSWD_RULES" ]]
        then
                pass "No passwordless sudo rules detected"
        else
                warning "Passwordless sudo rule(s) detected"
                add_recommendation "Review sudo privileges and apply least privileges and apply least privilege: remove unnecessary passwordless sudo access>"

                printf '%s\n' "$NOPASSWD_RULES" |
                while IFS= read -r rule
                do
                        echo "  - $rule"
                done

                if printf '$s\n' "$NOPASSWD_RULES" |
                        grep -Eq 'NOPASSWD:[[:space:]]*ALL([[:space:]]*($|#)|[[:space:]]*,)'
                then
                        critical "Unrestricted NOPASSWD: All rule detected"
                fi
        fi
else
        info "Full sudoers inspection skipped because the auditor is not runninng as root"
        info "Run with sudo for the complete privilege audit"
fi
else

        echo
        info "sudo is not installed on this system"
fi
}

