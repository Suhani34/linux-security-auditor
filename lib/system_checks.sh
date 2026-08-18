#!/usr/bin/env bash

check_system_information() {
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
echo "Report file      : $REPORT_FILE"
echo "Audit mode       : $AUDIT_MODE"

}
