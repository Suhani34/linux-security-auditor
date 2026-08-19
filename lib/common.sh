#!/usr/bin/env bash

command_exists() {
	local command_name="$1"
	command -v "$command_name" >/dev/null 2>&1
}

check_required_dependencies() {

    local required_commands=(
        awk
        grep
        sed
        cut
        sort
        uniq
        tr
        wc
        head
        find
        stat
        df
        date
        hostname
        uname
        uptime
        whoami
        id
        getent
        tee
        mkdir
        touch
        chmod
        mv
        rm
    )

    local command_name
    local missing_count=0

    echo "[DEPENDENCY CHECK] Checking required commands..."

    for command_name in "${required_commands[@]}"
    do

        if ! command_exists "$command_name"
        then

            echo "[ERROR] Required command is missing: $command_name" >&2

            missing_count=$((missing_count + 1))

        fi

    done

    if [[ "$missing_count" -gt 0 ]]
    then

        echo "[ERROR] $missing_count required dependency/dependencies are missing." >&2

        return 1

    fi

    echo "[DEPENDENCY CHECK] Required dependencies are available."

    return 0
}

report_optional_dependencies() {

    local optional_commands=(
        sudo
        systemctl
        journalctl
        ufw
        ss
        ps
        apt
        apt-get
    )

    local command_name
    local missing_count=0

    echo
    echo "[OPTIONAL DEPENDENCIES]"

    for command_name in "${optional_commands[@]}"
    do

        if ! command_exists "$command_name"
        then

            echo "[INFO] Optional command not found: $command_name"
            echo "       Related checks may be skipped."

            missing_count=$((missing_count + 1))

        fi

    done

    if [[ "$missing_count" -eq 0 ]]
    then

        echo "[INFO] All monitored optional dependencies are available."

    fi

}

record_finding() {
    local severity="$1"
    shift

    local message="$*"

    case "$severity" in

        PASS)
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;

        INFO)
            INFO_COUNT=$((INFO_COUNT + 1))
            ;;

        WARNING)
            WARNING_COUNT=$((WARNING_COUNT + 1))
            ;;
        CRITICAL)
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
            ;;

        *)
            echo "[ERROR] Unknown finding severity: $severity"
            return 1
            ;;

    esac

    FINDING_SEVERITIES+=("$severity")
    FINDING_MESSAGES+=("$message")
    echo "[$severity] $message"
}


pass() {
    record_finding "PASS" "$@"
}
info() {
    record_finding "INFO" "$@"
}


warning() {
    record_finding "WARNING" "$@"
}


critical() {
    record_finding "CRITICAL" "$@"
}

add_recommendation() {
        local recommendation="$*"
        local existing_recommendation

        for existing_recommendation in "${RECOMMENDATIONS[@]}"; do
                if [[ "$existing_recommendation" == "$recommendation" ]]; then
                        return 0
                fi
        done
        RECOMMENDATIONS+=("$recommendation")
}

