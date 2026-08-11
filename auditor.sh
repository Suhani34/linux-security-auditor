#!/usr/bin/env bash

echo "======================================================================"
echo "                        LINUX SECURITY AUDITOR                        "
echo "======================================================================"

HOST="$(hostname)"
CURRENT_USER="$(whoami)"
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
echo "Run By           : $CURRENT_USER"
