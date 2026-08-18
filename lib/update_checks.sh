#!/usr/bin/env bash

check_Security_update() {
echo
echo "[SECURITY UPDATES & PATCH STATUS]"

echo

if command -v apt >/dev/null 2>&1
then

    UPGRADABLE_PACKAGES="$(
        apt list --upgradable 2>/dev/null |
        sed '1d' |
        sed '/^[[:space:]]*$/d'
    )"

    if [[ -z "$UPGRADABLE_PACKAGES" ]]
    then
        UPGRADABLE_COUNT=0
    else
        UPGRADABLE_COUNT="$(
            printf '%s\n' "$UPGRADABLE_PACKAGES" |
            wc -l
        )"
    fi

    SECURITY_UPDATES="$(
        printf '%s\n' "$UPGRADABLE_PACKAGES" |
        grep -i 'security' || true
    )"

    if [[ -z "$SECURITY_UPDATES" ]]
    then
        SECURITY_UPDATE_COUNT=0
    else
        SECURITY_UPDATE_COUNT="$(
            printf '%s\n' "$SECURITY_UPDATES" |
            sed '/^[[:space:]]*$/d' |
            wc -l
        )"
    fi
    echo "Pending package updates  : $UPGRADABLE_COUNT"
    echo "Security-related updates : $SECURITY_UPDATE_COUNT"

    echo

    if [[ "$UPGRADABLE_COUNT" -eq 0 ]]
    then
        pass "No pending package updates detected"
    else
        warning "$UPGRADABLE_COUNT package update(s) are pending"
    fi

    if [[ "$SECURITY_UPDATE_COUNT" -eq 0 ]]
    then
        pass "No security-related updates were identified in cached APT metadata."
    else
        warning "$SECURITY_UPDATE_COUNT security-related package update(s) are pending."
        add_recommendation "Review and install pending security updates after confirming they are appropriate for the system."
        echo
        echo "Security-related updates:"
        printf '%s\n' "$SECURITY_UPDATES" |
        head -n 10 |
        while IFS= read -r security_update
        do
            echo "  - $security_update"
        done

        if [[ "$SECURITY_UPDATE_COUNT" -gt 10 ]]
        then
            echo "  ... additional security updates omitted from console output"
        fi
    fi

    echo
    info "Update results depend on locally cached APT repository metadata"
    info "Run 'sudo apt update' before the audit when current repository data is required."

else

    warning "APT is not available"
    info "Package update checks could not be performed"
fi


echo

if [[ -f /var/run/reboot-required ]]
then

    echo "Reboot required          : Yes"
    warning "A system reboot is required to complete installed updates"

    if [[ -f /var/run/reboot-required.pkgs ]]
    then

        REBOOT_PACKAGES="$(
            sed '/^[[:space:]]*$/d' \
                /var/run/reboot-required.pkgs \
                2>/dev/null
        )"
        if [[ -n "$REBOOT_PACKAGES" ]]
        then

            echo
            echo "Packages associated with reboot requirement:"

            printf '%s\n' "$REBOOT_PACKAGES" |
            head -n 10 |
            while IFS= read -r reboot_package
            do
                echo "  - $reboot_package"
            done

        fi

    fi

else
   echo "Reboot required          : No"
    pass "No reboot is currently required"

fi


echo

if dpkg -s unattended-upgrades >/dev/null 2>&1
then

    info "unattended-upgrades package is installed"

    if command -v systemctl >/dev/null 2>&1
    then

        if systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null
        then
            info "apt-daily-upgrade.timer is enabled"
        else
            info "apt-daily-upgrade.timer is not enabled"
        fi

    fi

else

    info "unattended-upgrades package is not installed"
    info "Automatic updates may instead be managed through another patching process."

fi

}
