#!/usr/bin/env bash

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

