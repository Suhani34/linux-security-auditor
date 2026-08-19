#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
source "$LIB_DIR/common.sh"
source "$LIB_DIR/system_checks.sh"
source "$LIB_DIR/user_checks.sh"
source "$LIB_DIR/ssh_checks.sh"
source "$LIB_DIR/network_checks.sh"
source "$LIB_DIR/service_checks.sh"
source "$LIB_DIR/filesystem_checks.sh"
source "$LIB_DIR/auth_checks.sh"
source "$LIB_DIR/update_checks.sh"
source "$LIB_DIR/reporting.sh"

EXIT_SUCCESS=0
EXIT_RUNTIME_ERROR=1
EXIT_DEPENDENCY_ERROR=2

PASS_COUNT=0
INFO_COUNT=0
WARNING_COUNT=0
CRITICAL_COUNT=0

FINDING_SEVERITIES=()
FINDING_MESSAGES=()

MAX_SECURITY_SCORE=100
WARNING_PENALTY=4
CRITICAL_PENALTY=12

SECURITY_SCORE=100
SECURITY_RATING=""

RECOMMENDATIONS=()
REPORT_DIR="$SCRIPT_DIR/reports"
REPORT_TIMESTAMP="$(date '+%Y-%m-%d_%H%M%S')"
REPORT_HOSTNAME="$(hostname 2>/dev/null || echo unknown-host)"
REPORT_FILE=""
JSON_REPORT_FILE=""
PREVIOUS_REPORT=""

if [[ $EUID -eq 0 ]]; then
    AUDIT_MODE="FULL"
else
    AUDIT_MODE="PARTIAL"
fi

if ! check_required_dependencies
then

    echo "[ERROR] Linux Security Auditor cannot start because required dependencies are missing." >&2

    exit "$EXIT_DEPENDENCY_ERROR"

fi

if initialize_report; then
    enable_report_logging
    report_optional_dependencies
else
    echo "[ERROR] Auditor report initialization failed." >&2

    exit "$EXIT_RUNTIME_ERROR"
fi

echo "======================================================================"
echo "                        LINUX SECURITY AUDITOR                        "
echo "======================================================================"

check_system_information

check_user_accounts

check_sudo_security

check_service_security

check_firewall_security

check_ssh_security

check_authentication_security

check_disk_storage_security

check_Security_update

print_summary
print_recommendations
print_audit_comparison

generate_json_report

echo
echo "[INFO] Audit report saved to: $REPORT_FILE"
echo "[INFO] JSON report saved to: $JSON_REPORT_FILE"
